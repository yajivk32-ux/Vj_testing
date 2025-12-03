"""
secure_web_app.py
Web app with PIN-protected registration
Run: python secure_web_app.py
Open: http://localhost:8080
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
# ==================== CHANGED TO 1GB ====================
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max (changed from 1000MB)
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

# HTML Templates (UPDATED ADMIN TEMPLATE)
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
                        {% if session.get('username') == 'admin' %}
                            <a class="nav-link" href="/admin/dashboard">Admin Panel</a>
                        {% endif %}
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
                            {% if session.get('username') == 'admin' %}
                                <a href="/admin/dashboard" class="btn btn-warning btn-lg mt-3">Admin Panel</a>
                            {% endif %}
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
                            <p><strong>Test PINs:</strong> 12345678 (100 uses), 87654321 (5 uses), 11112222 (1 use)</p>
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
                {% if session.get('username') == 'admin' %}
                    <a class="nav-link" href="/admin/dashboard">Admin Panel</a>
                {% endif %}
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
                        <p><strong>Storage Used:</strong> {{ storage_used|filesizeformat }}</p>
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
                                <small class="text-muted">Max 1GB per file</small>
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
                        <h5>📁 Your Files ({{ files|length }})</h5>
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

# ==================== UPDATED ADMIN TEMPLATES ====================
ADMIN_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        body { background: #f8f9fa; }
        .admin-card { border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .danger-hover:hover { background-color: #dc3545 !important; color: white !important; }
        .user-row:hover { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">🔒 SecureApp - Admin Panel</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/dashboard"><i class="bi bi-speedometer2"></i> User Dashboard</a>
                <a class="nav-link" href="/"><i class="bi bi-house"></i> Home</a>
                <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body text-center">
                        <h3><i class="bi bi-people"></i></h3>
                        <h5>{{ total_users }}</h5>
                        <p>Total Users</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                    <div class="card-body text-center">
                        <h3><i class="bi bi-file-earmark"></i></h3>
                        <h5>{{ total_files }}</h5>
                        <p>Total Files</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                    <div class="card-body text-center">
                        <h3><i class="bi bi-hdd"></i></h3>
                        <h5>{{ total_storage|filesizeformat }}</h5>
                        <p>Storage Used</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                    <div class="card-body text-center">
                        <h3><i class="bi bi-key"></i></h3>
                        <h5>{{ active_pins }}</h5>
                        <p>Active PINs</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabs Navigation -->
        <ul class="nav nav-tabs mb-4" id="adminTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button">
                    <i class="bi bi-people"></i> Manage Users
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="pins-tab" data-bs-toggle="tab" data-bs-target="#pins" type="button">
                    <i class="bi bi-key"></i> Manage PINs
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="files-tab" data-bs-toggle="tab" data-bs-target="#files" type="button">
                    <i class="bi bi-files"></i> All Files
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button">
                    <i class="bi bi-clock-history"></i> Activity Logs
                </button>
            </li>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="adminTabsContent">
            <!-- Users Tab -->
            <div class="tab-pane fade show active" id="users" role="tabpanel">
                <div class="card admin-card">
                    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="bi bi-people"></i> User Management</h5>
                        <span class="badge bg-light text-dark">{{ users|length }} users</span>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>PIN Used</th>
                                        <th>Joined</th>
                                        <th>Status</th>
                                        <th>Files</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for user in users %}
                                    <tr class="user-row">
                                        <td>{{ user[0] }}</td>
                                        <td><strong>{{ user[1] }}</strong></td>
                                        <td>{{ user[2] }}</td>
                                        <td><code>{{ user[4] }}</code></td>
                                        <td>{{ user[5][:10] }}</td>
                                        <td>
                                            {% if user[7] == 1 %}
                                                <span class="badge bg-success">Active</span>
                                            {% else %}
                                                <span class="badge bg-danger">Inactive</span>
                                            {% endif %}
                                        </td>
                                        <td>
                                            {% set user_files = user_files_counts.get(user[0], 0) %}
                                            <span class="badge bg-info">{{ user_files }}</span>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                {% if user[7] == 1 %}
                                                    <a href="/admin/deactivate_user/{{ user[0] }}" class="btn btn-warning" 
                                                       onclick="return confirm('Deactivate {{ user[1] }}?')">
                                                        <i class="bi bi-pause"></i>
                                                    </a>
                                                {% else %}
                                                    <a href="/admin/activate_user/{{ user[0] }}" class="btn btn-success" 
                                                       onclick="return confirm('Activate {{ user[1] }}?')">
                                                        <i class="bi bi-play"></i>
                                                    </a>
                                                {% endif %}
                                                <a href="/admin/delete_user/{{ user[0] }}" class="btn btn-danger danger-hover" 
                                                   onclick="return confirm('Permanently delete user {{ user[1] }} and ALL their files?')">
                                                    <i class="bi bi-trash"></i>
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PINs Tab -->
            <div class="tab-pane fade" id="pins" role="tabpanel">
                <div class="card admin-card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0"><i class="bi bi-key"></i> PIN Management</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card mb-4">
                                    <div class="card-header bg-success text-white">
                                        <h6>Generate New PIN</h6>
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
                                                       value="5" min="1" max="1000" required>
                                                <small class="text-muted">How many times can this PIN be used?</small>
                                            </div>
                                            
                                            <button type="submit" class="btn btn-success w-100">
                                                <i class="bi bi-plus-circle"></i> Generate New 8-Digit PIN
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                {% if new_pin %}
                                <div class="alert alert-success">
                                    <h5><i class="bi bi-check-circle"></i> New PIN Generated!</h5>
                                    <p class="pin-display" style="font-size: 2rem; font-family: monospace;">{{ new_pin }}</p>
                                    <p><strong>Uses remaining:</strong> {{ uses }}</p>
                                    <p><strong>Share this PIN securely!</strong></p>
                                </div>
                                {% endif %}
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <h6>Current Valid PINs</h6>
                            </div>
                            <div class="card-body">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>PIN</th>
                                            <th>Uses Left</th>
                                            <th>Created By</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for pin, info in valid_pins.items() %}
                                        <tr>
                                            <td><code class="pin-display">{{ pin }}</code></td>
                                            <td>
                                                <span class="badge {% if info.uses_left > 0 %}bg-success{% else %}bg-danger{% endif %}">
                                                    {{ info.uses_left }}
                                                </span>
                                            </td>
                                            <td>{{ info.created_by }}</td>
                                            <td>
                                                {% if pin not in ['12345678', '87654321', '11112222'] %}
                                                <a href="/admin/delete_pin/{{ pin }}" class="btn btn-sm btn-outline-danger" 
                                                   onclick="return confirm('Delete PIN {{ pin }}?')">
                                                    <i class="bi bi-trash"></i>
                                                </a>
                                                {% endif %}
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Files Tab -->
            <div class="tab-pane fade" id="files" role="tabpanel">
                <div class="card admin-card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-files"></i> All System Files</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="table-info">
                                    <tr>
                                        <th>ID</th>
                                        <th>Filename</th>
                                        <th>Original Name</th>
                                        <th>Size</th>
                                        <th>Uploaded</th>
                                        <th>User</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for file in all_files %}
                                    <tr>
                                        <td>{{ file[0] }}</td>
                                        <td><small>{{ file[1] }}</small></td>
                                        <td>{{ file[2] }}</td>
                                        <td>{{ file[3]|filesizeformat if file[3] else 'N/A' }}</td>
                                        <td>{{ file[4][:19] }}</td>
                                        <td>{{ file[5] }}</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <a href="/admin/download_file/{{ file[0] }}" class="btn btn-success btn-sm">
                                                    <i class="bi bi-download"></i>
                                                </a>
                                                <a href="/admin/delete_file/{{ file[0] }}" class="btn btn-danger btn-sm" 
                                                   onclick="return confirm('Delete this file?')">
                                                    <i class="bi bi-trash"></i>
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Logs Tab -->
            <div class="tab-pane fade" id="logs" role="tabpanel">
                <div class="card admin-card">
                    <div class="card-header bg-secondary text-white">
                        <h5 class="mb-0"><i class="bi bi-clock-history"></i> System Activity Logs</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="table-secondary">
                                    <tr>
                                        <th>Time</th>
                                        <th>Username</th>
                                        <th>IP Address</th>
                                        <th>Action</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for log in activity_logs %}
                                    <tr>
                                        <td><small>{{ log[3][:19] }}</small></td>
                                        <td><strong>{{ log[1] or 'N/A' }}</strong></td>
                                        <td><code>{{ log[2] }}</code></td>
                                        <td>Login Attempt</td>
                                        <td>
                                            {% if log[4] == 1 %}
                                                <span class="badge bg-success">Success</span>
                                            {% else %}
                                                <span class="badge bg-danger">Failed</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh logs every 30 seconds
        setTimeout(function() {
            window.location.reload();
        }, 30000);
    </script>
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
                            <a href="/admin/dashboard" class="btn btn-primary">Go to Admin Dashboard</a>
                            <a href="/" class="btn btn-outline-light">Back to Home</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
</body>
</html>
'''

# Routes
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
    
    # Calculate storage used
    storage_used = 0
    for file in files:
        storage_used += file[3] or 0
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=user['username'],
        email=user['email'],
        pin_used=user['pin_used'],
        created_at=user['created_at'],
        files=files,
        storage_used=storage_used
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
        
        try:
            # Save file
            file.save(filepath)
            
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # Check if file size exceeds limit (1GB = 1073741824 bytes)
            if file_size > 1073741824:
                os.remove(filepath)
                flash('File size exceeds 1GB limit!', 'danger')
                return redirect('/dashboard')
            
            # Store in database
            query_db('''
                INSERT INTO files (filename, original_name, file_size, user_id) 
                VALUES (?, ?, ?, ?)
            ''', [unique_filename, filename, file_size, session['user_id']])
            
            flash(f'File "{filename}" uploaded successfully! Size: {file_size // (1024*1024)} MB', 'success')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
    
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

# ==================== UPDATED ADMIN ROUTES ====================

@app.route('/admin/dashboard')
def admin_dashboard():
    # Only admin can access
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    # Get statistics
    total_users = query_db('SELECT COUNT(*) FROM users', one=True)[0]
    total_files = query_db('SELECT COUNT(*) FROM files', one=True)[0]
    
    # Calculate total storage
    total_storage_result = query_db('SELECT SUM(file_size) FROM files', one=True)
    total_storage = total_storage_result[0] if total_storage_result[0] else 0
    
    # Count active PINs
    active_pins = sum(1 for pin_info in VALID_PINS.values() if pin_info['uses_left'] > 0)
    
    # Get all users
    users = query_db('SELECT * FROM users ORDER BY created_at DESC')
    
    # Get user file counts
    user_files_counts = {}
    for user in users:
        count = query_db('SELECT COUNT(*) FROM files WHERE user_id = ?', [user[0]], one=True)[0]
        user_files_counts[user[0]] = count
    
    # Get all files with usernames
    all_files = query_db('''
        SELECT f.*, u.username 
        FROM files f 
        JOIN users u ON f.user_id = u.id 
        ORDER BY f.uploaded_at DESC
    ''')
    
    # Get activity logs
    activity_logs = query_db('SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 50')
    
    return render_template_string(
        ADMIN_DASHBOARD_TEMPLATE,
        total_users=total_users,
        total_files=total_files,
        total_storage=total_storage,
        active_pins=active_pins,
        users=users,
        user_files_counts=user_files_counts,
        all_files=all_files,
        activity_logs=activity_logs,
        valid_pins=VALID_PINS,
        new_pin=None,
        uses=None
    )

@app.route('/admin/generate_pin', methods=['GET', 'POST'])
def admin_generate_pin():
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
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
            flash(f'New PIN {new_pin} generated with {uses} uses!', 'success')
    
    # Return to admin dashboard
    return redirect('/admin/dashboard')

@app.route('/admin/delete_pin/<pin>')
def admin_delete_pin(pin):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    # Don't delete default PINs
    if pin in ['12345678', '87654321', '11112222']:
        flash('Cannot delete default PINs!', 'warning')
    elif pin in VALID_PINS:
        del VALID_PINS[pin]
        flash(f'PIN {pin} deleted successfully!', 'success')
    else:
        flash('PIN not found!', 'danger')
    
    return redirect('/admin/dashboard')

@app.route('/admin/deactivate_user/<int:user_id>')
def admin_deactivate_user(user_id):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    query_db('UPDATE users SET is_active = 0 WHERE id = ?', [user_id])
    user = query_db('SELECT username FROM users WHERE id = ?', [user_id], one=True)
    if user:
        flash(f'User {user[0]} deactivated!', 'success')
    
    return redirect('/admin/dashboard')

@app.route('/admin/activate_user/<int:user_id>')
def admin_activate_user(user_id):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    query_db('UPDATE users SET is_active = 1 WHERE id = ?', [user_id])
    user = query_db('SELECT username FROM users WHERE id = ?', [user_id], one=True)
    if user:
        flash(f'User {user[0]} activated!', 'success')
    
    return redirect('/admin/dashboard')

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    # Don't allow deleting admin user
    if user_id == 1:
        flash('Cannot delete admin user!', 'danger')
        return redirect('/admin/dashboard')
    
    # Get user info before deletion
    user = query_db('SELECT username FROM users WHERE id = ?', [user_id], one=True)
    
    if user:
        username = user[0]
        
        # Delete user's files from filesystem
        files = query_db('SELECT filename FROM files WHERE user_id = ?', [user_id])
        for file in files:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(filepath):
                os.remove(filepath)
        
        # Delete from database
        query_db('DELETE FROM files WHERE user_id = ?', [user_id])
        query_db('DELETE FROM pin_usage WHERE username = ?', [username])
        query_db('DELETE FROM login_attempts WHERE username = ?', [username])
        query_db('DELETE FROM users WHERE id = ?', [user_id])
        
        flash(f'User {username} and all their files deleted permanently!', 'success')
    
    return redirect('/admin/dashboard')

@app.route('/admin/download_file/<int:file_id>')
def admin_download_file(file_id):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file:
        flash('File not found', 'danger')
        return redirect('/admin/dashboard')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if not os.path.exists(filepath):
        flash('File not found on server', 'danger')
        return redirect('/admin/dashboard')
    
    return send_file(filepath, as_attachment=True, download_name=file['original_name'])

@app.route('/admin/delete_file/<int:file_id>')
def admin_delete_file(file_id):
    if session.get('username') != 'admin':
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file:
        flash('File not found', 'danger')
        return redirect('/admin/dashboard')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if os.path.exists(filepath):
        os.remove(filepath)
    
    query_db('DELETE FROM files WHERE id = ?', [file_id])
    flash('File deleted successfully!', 'success')
    return redirect('/admin/dashboard')

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

# Health check endpoint for Render
@app.route('/health')
def health_check():
    return 'OK', 200

# ==================== MAIN ====================
if __name__ == '__main__':
    import os
    
    print("=" * 60)
    print("🔒 SECURE WEB APPLICATION")
    print("=" * 60)
    
    # Railway uses PORT environment variable
    port = int(os.environ.get("PORT", 8080))
    
    print(f"🌐 Running on port: {port}")
    print("🔑 Test PINs for registration:")
    print(f"   • 12345678 (Master PIN, {VALID_PINS['12345678']['uses_left']} uses left)")
    print(f"   • 87654321 ({VALID_PINS['87654321']['uses_left']} uses left)")
    print(f"   • 11112222 ({VALID_PINS['11112222']['uses_left']} uses left)")
    print(f"🔧 Admin PIN: {ADMIN_PIN}")
    print(f"📁 Upload limit: 1GB per file")
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