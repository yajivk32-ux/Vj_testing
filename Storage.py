"""
secure_web_app.py
Web app with PIN-protected registration
Run: python secure_web_app.py
Open: http://localhost:5000
"""

from flask import Flask, render_template_string, request, redirect, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import sqlite3
import secrets
import re

# ==================== RAILWAY FIXES ====================
# For Railway deployment - use /tmp/ directory which is writable
import os

# Determine if we're running on Railway
if 'RAILWAY_ENVIRONMENT' in os.environ:
    # Railway environment
    DB_PATH = '/tmp/secure_database.db'
    UPLOAD_FOLDER = '/tmp/secure_uploads'
    print("🚂 Running on Railway - Using /tmp/ directory")
else:
    # Local development
    DB_PATH = 'secure_database.db'
    UPLOAD_FOLDER = 'secure_uploads'
    print("💻 Running locally")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random secret key
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1000MB max
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# PIN Configuration (Change these for production!)
VALID_PINS = {
    '12345678': {'uses_left': 100, 'created_by': 'admin'},  # Master PIN
    '87654321': {'uses_left': 5, 'created_by': 'admin'},    # Limited use PIN
    '11112222': {'uses_left': 1, 'created_by': 'admin'},    # One-time PIN
}
ADMIN_PIN = '99998888'  # Admin PIN for generating new PINs

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)  # Changed to use DB_PATH
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  pin_used TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP,
                  is_active INTEGER DEFAULT 1)''')
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT NOT NULL,
                  original_name TEXT NOT NULL,
                  file_size INTEGER,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  user_id INTEGER NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # PIN usage tracking
    c.execute('''CREATE TABLE IF NOT EXISTS pin_usage
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  pin TEXT NOT NULL,
                  username TEXT NOT NULL,
                  used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  ip_address TEXT)''')
    
    # Login attempts tracking
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  ip_address TEXT,
                  attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  success INTEGER)''')
    
    conn.commit()
    conn.close()

init_db()

# Database helper
def get_db():
    conn = sqlite3.connect(DB_PATH)  # Changed to use DB_PATH
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# Security functions
def is_valid_pin(pin):
    """Check if PIN is valid 8-digit number"""
    return bool(re.match(r'^\d{8}$', pin))

def validate_password(password):
    """Password validation rules"""
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return "Password must contain at least one number"
    return None

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def check_login_attempts(username, ip_address):
    """Check if too many failed login attempts"""
    recent_attempts = query_db('''
        SELECT COUNT(*) as count FROM login_attempts 
        WHERE ip_address = ? AND success = 0 
        AND attempted_at > datetime('now', '-15 minutes')
    ''', [ip_address], one=True)
    
    if recent_attempts and recent_attempts['count'] >= 5:
        return False, "Too many failed attempts. Please wait 15 minutes."
    
    return True, ""

def record_login_attempt(username, ip_address, success):
    """Record login attempt"""
    query_db('''
        INSERT INTO login_attempts (username, ip_address, success) 
        VALUES (?, ?, ?)
    ''', [username, ip_address, 1 if success else 0])

# HTML Templates (SAME AS YOURS - NO CHANGES)
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔒 Secure Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .glass-card { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; }
        .pin-display { font-family: monospace; font-size: 1.5rem; letter-spacing: 2px; }
        .feature-icon { font-size: 3rem; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container py-5">
        <nav class="navbar navbar-expand-lg navbar-light glass-card mb-5">
            <div class="container-fluid">
                <a class="navbar-brand" href="/">🔒 SecureApp</a>
                <div class="navbar-nav ms-auto">
                    {% if user_id %}
                        <a class="nav-link" href="/dashboard">Dashboard</a>
                        <a class="nav-link" href="/logout">Logout</a>
                    {% else %}
                        <a class="nav-link" href="/login">Login</a>
                        <a class="nav-link" href="/register">Register</a>
                    {% endif %}
                </div>
            </div>
        </nav>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show glass-card">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="glass-card p-5 text-center">
                    <h1 class="mb-4">Welcome to Secure Web App</h1>
                    <p class="lead mb-4">PIN-protected registration for authorized access only</p>
                    
                    {% if user_id %}
                        <div class="mt-5">
                            <h3>Welcome back, {{ username }}!</h3>
                            <a href="/dashboard" class="btn btn-primary btn-lg mt-3">Go to Dashboard</a>
                        </div>
                    {% else %}
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <div class="p-4">
                                    <div class="feature-icon">🔐</div>
                                    <h4>Secure Login</h4>
                                    <p>Existing users can login here</p>
                                    <a href="/login" class="btn btn-primary w-100">Login</a>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="p-4">
                                    <div class="feature-icon">📝</div>
                                    <h4>PIN Registration</h4>
                                    <p>New users need 8-digit PIN</p>
                                    <a href="/register" class="btn btn-success w-100">Register with PIN</a>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-5 pt-4 border-top">
                            <h5>About PIN Protection</h5>
                            <p>Only users with a valid 8-digit PIN can register. Contact the administrator to get your PIN.</p>
                        </div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Register with PIN</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f8f9fa; }
        .card { border-radius: 15px; }
        .pin-input { letter-spacing: 8px; font-size: 24px; text-align: center; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="text-center">🔒 PIN-Protected Registration</h3>
                    </div>
                    <div class="card-body p-4">
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ category }}">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        
                        <form method="POST" action="/register">
                            <h5 class="mb-4">Step 1: Enter Your 8-Digit PIN</h5>
                            <div class="mb-4">
                                <input type="text" class="form-control form-control-lg pin-input" 
                                       name="pin" placeholder="8-digit PIN" maxlength="8" required 
                                       pattern="\d{8}" title="8 digit PIN required">
                                <small class="text-muted">Enter the 8-digit PIN provided by administrator</small>
                            </div>
                            
                            <h5 class="mb-4">Step 2: Create Your Account</h5>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" name="username" required>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" name="email" required>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-control" name="password" required>
                                <small class="text-muted">Must be 8+ chars with uppercase, lowercase, and number</small>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" name="confirm_password" required>
                            </div>
                            
                            <button type="submit" class="btn btn-primary btn-lg w-100 mb-3">
                                Register with PIN
                            </button>
                            <a href="/" class="btn btn-outline-secondary w-100">Back to Home</a>
                        </form>
                    </div>
                </div>
                
                <div class="text-center mt-4">
                    <p>Already have an account? <a href="/login">Login here</a></p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-header bg-dark text-white">
                        <h3 class="text-center">🔐 Secure Login</h3>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ category }}">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        
                        <form method="POST" action="/login">
                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input type="text" class="form-control" name="username" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            
                            <button type="submit" class="btn btn-dark btn-lg w-100 mb-3">Login</button>
                            
                            <div class="text-center">
                                <a href="/register" class="btn btn-outline-primary">Need a PIN to Register?</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f8f9fa; }
        .card { border-radius: 10px; }
        .user-info { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">🔒 SecureApp</a>
            <div class="navbar-nav ms-auto">
                <span class="nav-link">Welcome, {{ username }}!</span>
                <a class="nav-link" href="/logout">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="row">
            <!-- User Info -->
            <div class="col-md-4">
                <div class="card user-info">
                    <div class="card-body">
                        <h5>👤 Account Information</h5>
                        <p><strong>Username:</strong> {{ username }}</p>
                        <p><strong>Email:</strong> {{ email }}</p>
                        <p><strong>PIN Used:</strong> {{ pin_used }}</p>
                        <p><strong>Member since:</strong> {{ created_at[:10] }}</p>
                    </div>
                </div>

                <!-- File Upload -->
                <div class="card mt-3">
                    <div class="card-header bg-success text-white">
                        <h5>📤 Upload File</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST" action="/upload" enctype="multipart/form-data">
                            <div class="mb-3">
                                <input class="form-control" type="file" name="file" required>
                                <small class="text-muted">Max 10MB per file</small>
                            </div>
                            <button type="submit" class="btn btn-success w-100">Upload</button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Files List -->
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5>📁 Your Files</h5>
                    </div>
                    <div class="card-body">
                        {% if files %}
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Filename</th>
                                            <th>Size</th>
                                            <th>Uploaded</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for file in files %}
                                            <tr>
                                                <td>{{ file[2] }}</td>
                                                <td>{{ file[3]|filesizeformat if file[3] else 'N/A' }}</td>
                                                <td>{{ file[4][:19] }}</td>
                                                <td>
                                                    <a href="/download/{{ file[0] }}" class="btn btn-sm btn-success">Download</a>
                                                    <a href="/delete/{{ file[0] }}" class="btn btn-sm btn-danger" 
                                                       onclick="return confirm('Delete this file?')">Delete</a>
                                                </td>
                                            </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        {% else %}
                            <p class="text-center text-muted">No files uploaded yet.</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin - Generate PIN</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card bg-secondary">
                    <div class="card-header bg-warning text-dark">
                        <h3 class="text-center">🔑 Admin Panel - Generate New PINs</h3>
                    </div>
                    <div class="card-body">
                        <form method="POST" action="/admin/generate_pin">
                            <div class="mb-3">
                                <label class="form-label">Admin PIN</label>
                                <input type="password" class="form-control" name="admin_pin" 
                                       placeholder="Enter admin PIN" required>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Number of Uses</label>
                                <input type="number" class="form-control" name="uses" 
                                       value="5" min="1" max="100" required>
                                <small class="text-muted">How many times can this PIN be used?</small>
                            </div>
                            
                            <button type="submit" class="btn btn-warning btn-lg w-100">
                                Generate New 8-Digit PIN
                            </button>
                        </form>
                        
                        {% if new_pin %}
                            <div class="alert alert-success mt-4">
                                <h4>✅ New PIN Generated!</h4>
                                <p class="pin-display" style="font-size: 2rem;">{{ new_pin }}</p>
                                <p><strong>Uses remaining:</strong> {{ uses }}</p>
                                <p><strong>Share this PIN securely!</strong></p>
                            </div>
                        {% endif %}
                        
                        <div class="mt-4">
                            <h5>Current Valid PINs:</h5>
                            <table class="table table-dark">
                                <thead>
                                    <tr>
                                        <th>PIN</th>
                                        <th>Uses Left</th>
                                        <th>Created By</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for pin, info in valid_pins.items() %}
                                        <tr>
                                            <td class="pin-display">{{ pin }}</td>
                                            <td>{{ info.uses_left }}</td>
                                            <td>{{ info.created_by }}</td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        
                        <div class="text-center mt-4">
                            <a href="/" class="btn btn-outline-light">Back to Home</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
</body>
</html>
'''

# Routes (SAME AS YOURS - NO CHANGES)
@app.route('/')
def index():
    user_id = session.get('user_id')
    username = session.get('username', 'Guest')
    return render_template_string(HOME_TEMPLATE, user_id=user_id, username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        pin = request.form['pin'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if not is_valid_pin(pin):
            flash('Invalid PIN format. Must be 8 digits.', 'danger')
            return redirect('/register')
        
        if pin not in VALID_PINS:
            flash('Invalid PIN. Please enter a valid 8-digit PIN.', 'danger')
            return redirect('/register')
        
        if VALID_PINS[pin]['uses_left'] <= 0:
            flash('This PIN has been used up. Please contact administrator.', 'danger')
            return redirect('/register')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect('/register')
        
        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'danger')
            return redirect('/register')
        
        # Check if username/email exists
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if user:
            flash('Username already exists.', 'danger')
            return redirect('/register')
        
        user = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        if user:
            flash('Email already registered.', 'danger')
            return redirect('/register')
        
        # Create user
        hashed_password = generate_password_hash(password)
        query_db('''
            INSERT INTO users (username, email, password, pin_used) 
            VALUES (?, ?, ?, ?)
        ''', [username, email, hashed_password, pin])
        
        # Record PIN usage
        client_ip = get_client_ip()
        query_db('''
            INSERT INTO pin_usage (pin, username, ip_address) 
            VALUES (?, ?, ?)
        ''', [pin, username, client_ip])
        
        # Decrement PIN uses
        VALID_PINS[pin]['uses_left'] -= 1
        
        flash('Registration successful! You can now login.', 'success')
        return redirect('/login')
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        client_ip = get_client_ip()
        
        # Check login attempts
        allowed, message = check_login_attempts(username, client_ip)
        if not allowed:
            flash(message, 'danger')
            return redirect('/login')
        
        # Check user
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        
        if user and check_password_hash(user['password'], password):
            if user['is_active'] == 0:
                flash('Account is deactivated.', 'danger')
                record_login_attempt(username, client_ip, False)
                return redirect('/login')
            
            # Successful login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            
            # Update last login
            query_db('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user['id']])
            
            # Record successful attempt
            record_login_attempt(username, client_ip, True)
            
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            # Failed login
            record_login_attempt(username, client_ip, False)
            flash('Invalid username or password.', 'danger')
            return redirect('/login')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user = query_db('SELECT * FROM users WHERE id = ?', [session['user_id']], one=True)
    files = query_db('SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC', 
                     [session['user_id']])
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=user['username'],
        email=user['email'],
        pin_used=user['pin_used'],
        created_at=user['created_at'],
        files=files
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect('/login')
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect('/dashboard')
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect('/dashboard')
    
    if file:
        # Secure filename
        filename = secure_filename(file.filename)
        unique_filename = f"{session['user_id']}_{int(datetime.now().timestamp())}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save file
        file.save(filepath)
        
        # Get file size
        file_size = os.path.getsize(filepath)
        
        # Store in database
        query_db('''
            INSERT INTO files (filename, original_name, file_size, user_id) 
            VALUES (?, ?, ?, ?)
        ''', [unique_filename, filename, file_size, session['user_id']])
        
        flash(f'File "{filename}" uploaded successfully!', 'success')
    
    return redirect('/dashboard')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file or file['user_id'] != session['user_id']:
        flash('Access denied', 'danger')
        return redirect('/dashboard')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if not os.path.exists(filepath):
        flash('File not found', 'danger')
        return redirect('/dashboard')
    
    return send_file(filepath, as_attachment=True, download_name=file['original_name'])

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file or file['user_id'] != session['user_id']:
        flash('Access denied', 'danger')
        return redirect('/dashboard')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if os.path.exists(filepath):
        os.remove(filepath)
    
    query_db('DELETE FROM files WHERE id = ?', [file_id])
    flash('File deleted successfully!', 'success')
    return redirect('/dashboard')

@app.route('/admin/generate_pin', methods=['GET', 'POST'])
def admin_generate_pin():
    new_pin = None
    uses = None
    
    if request.method == 'POST':
        admin_pin = request.form['admin_pin'].strip()
        uses = int(request.form['uses'])
        
        if admin_pin != ADMIN_PIN:
            flash('Invalid admin PIN', 'danger')
        else:
            # Generate new 8-digit PIN
            new_pin = ''.join(secrets.choice('0123456789') for _ in range(8))
            VALID_PINS[new_pin] = {
                'uses_left': uses,
                'created_by': 'admin'
            }
    
    return render_template_string(
        ADMIN_TEMPLATE,
        valid_pins=VALID_PINS,
        new_pin=new_pin,
        uses=uses
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect('/')

# API endpoints
@app.route('/api/status')
def api_status():
    return {'status': 'online', 'timestamp': datetime.now().isoformat()}

@app.route('/api/pin_info/<pin>')
def api_pin_info(pin):
    if pin in VALID_PINS:
        return {
            'valid': True,
            'uses_left': VALID_PINS[pin]['uses_left'],
            'created_by': VALID_PINS[pin]['created_by']
        }
    return {'valid': False, 'message': 'Invalid PIN'}

# ==================== RAILWAY FIX - FINAL PART ====================
if __name__ == '__main__':
    import os
    
    print("=" * 60)
    print("🔒 SECURE WEB APPLICATION")
    print("=" * 60)
    
    # Railway uses PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    
    print(f"🌐 Running on port: {port}")
    print("🔑 Test PINs for registration:")
    print(f"   • 12345678 (Master PIN, {VALID_PINS['12345678']['uses_left']} uses left)")
    print(f"   • 87654321 ({VALID_PINS['87654321']['uses_left']} uses left)")
    print(f"   • 11112222 ({VALID_PINS['11112222']['uses_left']} uses left)")
    print(f"🔧 Admin PIN: {ADMIN_PIN}")
    print("=" * 60)
    
    # Create default admin user if not exists
    user = query_db('SELECT * FROM users WHERE username = ?', ['admin'], one=True)
    if not user:
        hashed_pw = generate_password_hash('Admin@123')
        query_db('''
            INSERT INTO users (username, email, password, pin_used) 
            VALUES (?, ?, ?, ?)
        ''', ['admin', 'admin@example.com', hashed_pw, '12345678'])
        print("✓ Created default admin: username='admin', password='Admin@123'")
    
    # Create uploads directory (just in case)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(debug=False, host='0.0.0.0', port=port)