"""
secure_web_app.py
Web app with PIN-protected registration
"""

from flask import Flask, render_template_string, request, redirect, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import sqlite3
import secrets
import re

# ==================== DEPLOYMENT SETUP ====================
if 'RAILWAY_ENVIRONMENT' in os.environ or 'RENDER' in os.environ:
    DB_PATH = '/tmp/secure_database.db'
    UPLOAD_FOLDER = '/tmp/secure_uploads'
    print("🚀 Running in production mode")
else:
    DB_PATH = 'secure_database.db'
    UPLOAD_FOLDER = 'secure_uploads'
    print("💻 Running locally")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== SECRET PIN CONFIGURATION ====================
# These are NOT shown to users - only for admin
VALID_PINS = {
    '77087078': {'uses_left': 100, 'created_by': 'admin'},  # Master PIN
    '75399455': {'uses_left': 5, 'created_by': 'admin'},    # Limited use PIN
    '97505232': {'uses_left': 1, 'created_by': 'admin'},    # One-time PIN
}
ADMIN_PIN = '91301511'  # Admin PIN for generating new PINs

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table with admin flag
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  pin_used TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP,
                  is_active INTEGER DEFAULT 1,
                  is_admin INTEGER DEFAULT 0)''')  # New: admin flag
    
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
    conn = sqlite3.connect(DB_PATH)
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
    return bool(re.match(r'^\d{8}$', pin))

def validate_password(password):
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
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# ==================== UPDATED HTML TEMPLATES ====================

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔒 Secure Web App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .glass-card { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; }
        .feature-icon { font-size: 3rem; margin-bottom: 20px; }
        .secret-link { color: #ff6b6b; font-weight: bold; }
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
                        {% if is_admin %}
                            <a class="nav-link secret-link" href="/admin_panel">👑 Admin</a>
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
                    <p class="lead mb-4">🔐 Exclusive access with PIN authorization</p>
                    
                    {% if user_id %}
                        <div class="mt-5">
                            <h3>Welcome back, {{ username }}!</h3>
                            {% if is_admin %}
                                <p class="text-warning">👑 Administrator Access Granted</p>
                                <a href="/admin_panel" class="btn btn-warning btn-lg mt-3">Admin Control Panel</a>
                                <br>
                            {% endif %}
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
                            <!-- TEST PINS REMOVED FROM PUBLIC VIEW -->
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
                {% if is_admin %}
                    <a class="nav-link text-warning" href="/admin_panel">👑 Admin Panel</a>
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
            <div class="col-md-4">
                <div class="card user-info">
                    <div class="card-body">
                        <h5>👤 Account Information</h5>
                        <p><strong>Username:</strong> {{ username }}</p>
                        <p><strong>Email:</strong> {{ email }}</p>
                        <p><strong>PIN Used:</strong> {{ pin_used }}</p>
                        <p><strong>Member since:</strong> {{ created_at[:10] }}</p>
                        {% if is_admin %}
                            <p><strong class="text-warning">👑 Administrator Account</strong></p>
                        {% endif %}
                    </div>
                </div>

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

# ==================== ADMIN PANEL TEMPLATE ====================
ADMIN_PANEL_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Control Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        :root {
            --admin-primary: #2c3e50;
            --admin-secondary: #34495e;
            --admin-accent: #e74c3c;
        }
        body { background: #ecf0f1; }
        .admin-header { background: var(--admin-primary); color: white; }
        .admin-card { border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 10px; }
        .stat-card { color: white; border-radius: 10px; }
        .nav-pills .nav-link.active { background: var(--admin-accent); }
        .secret-pin { font-family: monospace; background: #2c3e50; color: #f1c40f; padding: 5px; border-radius: 5px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark admin-header">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-lock"></i> Admin Control Panel
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/dashboard"><i class="bi bi-speedometer"></i> User Dashboard</a>
                <a class="nav-link" href="/"><i class="bi bi-house"></i> Home</a>
                <a class="nav-link text-warning" href="/logout"><i class="bi bi-box-arrow-right"></i> Logout</a>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3">
                <div class="admin-card p-3 mb-4">
                    <h5><i class="bi bi-person-badge"></i> Admin User</h5>
                    <p class="mb-1"><strong>{{ admin_username }}</strong></p>
                    <small class="text-muted">Administrator</small>
                    <hr>
                    <h6><i class="bi bi-key"></i> Secret PINs</h6>
                    <div class="mb-2">
                        <small>Master PIN:</small><br>
                        <span class="secret-pin">12345678</span>
                        <small class="text-muted">({{ valid_pins['12345678'].uses_left }} uses left)</small>
                    </div>
                    <div class="mb-2">
                        <small>Limited PIN:</small><br>
                        <span class="secret-pin">87654321</span>
                        <small class="text-muted">({{ valid_pins['87654321'].uses_left }} uses left)</small>
                    </div>
                    <div>
                        <small>One-time PIN:</small><br>
                        <span class="secret-pin">11112222</span>
                        <small class="text-muted">({{ valid_pins['11112222'].uses_left }} uses left)</small>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9">
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

                <!-- Statistics -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="stat-card p-3" style="background: linear-gradient(135deg, #3498db, #2980b9);">
                            <h3><i class="bi bi-people"></i> {{ total_users }}</h3>
                            <p>Total Users</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card p-3" style="background: linear-gradient(135deg, #2ecc71, #27ae60);">
                            <h3><i class="bi bi-file-earmark"></i> {{ total_files }}</h3>
                            <p>Total Files</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card p-3" style="background: linear-gradient(135deg, #e74c3c, #c0392b);">
                            <h3><i class="bi bi-hdd"></i> {{ total_storage|filesizeformat }}</h3>
                            <p>Storage Used</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card p-3" style="background: linear-gradient(135deg, #9b59b6, #8e44ad);">
                            <h3><i class="bi bi-shield-check"></i> {{ active_pins }}</h3>
                            <p>Active PINs</p>
                        </div>
                    </div>
                </div>

                <!-- Navigation -->
                <ul class="nav nav-pills mb-4">
                    <li class="nav-item">
                        <a class="nav-link active" data-bs-toggle="tab" href="#users">
                            <i class="bi bi-people"></i> Manage Users
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#pins">
                            <i class="bi bi-key"></i> Manage PINs
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-bs-toggle="tab" href="#files">
                            <i class="bi bi-files"></i> All Files
                        </a>
                    </li>
                </ul>

                <!-- Tab Content -->
                <div class="tab-content">
                    <!-- Users Tab -->
                    <div class="tab-pane fade show active" id="users">
                        <div class="admin-card p-4">
                            <h5><i class="bi bi-people"></i> Registered Users ({{ users|length }})</h5>
                            <div class="table-responsive mt-3">
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
                                        <tr>
                                            <td>{{ user.id }}</td>
                                            <td>
                                                <strong>{{ user.username }}</strong>
                                                {% if user.is_admin %}
                                                    <span class="badge bg-warning">Admin</span>
                                                {% endif %}
                                            </td>
                                            <td>{{ user.email }}</td>
                                            <td><code>{{ user.pin_used }}</code></td>
                                            <td>{{ user.created_at[:10] }}</td>
                                            <td>
                                                {% if user.is_active %}
                                                    <span class="badge bg-success">Active</span>
                                                {% else %}
                                                    <span class="badge bg-danger">Inactive</span>
                                                {% endif %}
                                            </td>
                                            <td>
                                                {% set file_count = user_files_counts.get(user.id, 0) %}
                                                <span class="badge bg-info">{{ file_count }}</span>
                                            </td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    {% if user.is_active and user.id != 1 %}
                                                        <a href="/admin/deactivate_user/{{ user.id }}" class="btn btn-warning" 
                                                           onclick="return confirm('Deactivate {{ user.username }}?')">
                                                            <i class="bi bi-pause"></i>
                                                        </a>
                                                    {% elif not user.is_active %}
                                                        <a href="/admin/activate_user/{{ user.id }}" class="btn btn-success" 
                                                           onclick="return confirm('Activate {{ user.username }}?')">
                                                            <i class="bi bi-play"></i>
                                                        </a>
                                                    {% endif %}
                                                    
                                                    {% if user.id != 1 %}
                                                        <a href="/admin/delete_user/{{ user.id }}" class="btn btn-danger" 
                                                           onclick="return confirm('Permanently delete {{ user.username }} and ALL their files?')">
                                                            <i class="bi bi-trash"></i>
                                                        </a>
                                                    {% endif %}
                                                </div>
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- PINs Tab -->
                    <div class="tab-pane fade" id="pins">
                        <div class="admin-card p-4">
                            <h5><i class="bi bi-key"></i> PIN Management</h5>
                            <div class="row mt-3">
                                <div class="col-md-6">
                                    <div class="card">
                                        <div class="card-header bg-primary text-white">
                                            <h6>Generate New PIN</h6>
                                        </div>
                                        <div class="card-body">
                                            <form method="POST" action="/admin/generate_pin">
                                                <div class="mb-3">
                                                    <label class="form-label">Admin PIN (for verification)</label>
                                                    <input type="password" class="form-control" name="admin_pin" required>
                                                </div>
                                                <div class="mb-3">
                                                    <label class="form-label">Number of Uses</label>
                                                    <input type="number" class="form-control" name="uses" value="5" min="1" max="1000" required>
                                                </div>
                                                <button type="submit" class="btn btn-success w-100">
                                                    <i class="bi bi-plus-circle"></i> Generate New PIN
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card">
                                        <div class="card-header bg-info text-white">
                                            <h6>Current PINs</h6>
                                        </div>
                                        <div class="card-body">
                                            <table class="table table-sm">
                                                <thead>
                                                    <tr>
                                                        <th>PIN</th>
                                                        <th>Uses Left</th>
                                                        <th>Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {% for pin, info in valid_pins.items() %}
                                                    <tr>
                                                        <td><code class="secret-pin">{{ pin }}</code></td>
                                                        <td>
                                                            <span class="badge {% if info.uses_left > 0 %}bg-success{% else %}bg-danger{% endif %}">
                                                                {{ info.uses_left }}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            {% if pin not in ['12345678', '87654321', '11112222'] %}
                                                            <a href="/admin/delete_pin/{{ pin }}" class="btn btn-sm btn-outline-danger" 
                                                               onclick="return confirm('Delete PIN {{ pin }}?')">
                                                                <i class="bi bi-trash"></i>
                                                            </a>
                                                            {% else %}
                                                            <small class="text-muted">System PIN</small>
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

                    <!-- Files Tab -->
                    <div class="tab-pane fade" id="files">
                        <div class="admin-card p-4">
                            <h5><i class="bi bi-files"></i> All System Files ({{ all_files|length }})</h5>
                            <div class="table-responsive mt-3">
                                <table class="table table-hover">
                                    <thead class="table-info">
                                        <tr>
                                            <th>ID</th>
                                            <th>Filename</th>
                                            <th>Size</th>
                                            <th>Uploaded</th>
                                            <th>User</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for file in all_files %}
                                        <tr>
                                            <td>{{ file.id }}</td>
                                            <td><small>{{ file.original_name }}</small></td>
                                            <td>{{ file.file_size|filesizeformat if file.file_size else 'N/A' }}</td>
                                            <td>{{ file.uploaded_at[:19] }}</td>
                                            <td>{{ file.username }}</td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <a href="/admin/download_file/{{ file.id }}" class="btn btn-success">
                                                        <i class="bi bi-download"></i>
                                                    </a>
                                                    <a href="/admin/delete_file/{{ file.id }}" class="btn btn-danger" 
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
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Activate tab from URL hash
        document.addEventListener('DOMContentLoaded', function() {
            var hash = window.location.hash;
            if (hash) {
                var tabTrigger = new bootstrap.Tab(document.querySelector('a[href="' + hash + '"]'));
                tabTrigger.show();
            }
        });
    </script>
</body>
</html>
'''

# ==================== ROUTES ====================

@app.route('/')
def index():
    user_id = session.get('user_id')
    username = session.get('username', 'Guest')
    is_admin = session.get('is_admin', False)
    return render_template_string(HOME_TEMPLATE, user_id=user_id, username=username, is_admin=is_admin)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        pin = request.form['pin'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
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
        
        # Create user (NOT admin by default)
        hashed_password = generate_password_hash(password)
        is_admin = 1 if username == 'admin' else 0  # Only 'admin' username gets admin rights
        
        query_db('''
            INSERT INTO users (username, email, password, pin_used, is_admin) 
            VALUES (?, ?, ?, ?, ?)
        ''', [username, email, hashed_password, pin, is_admin])
        
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
        
        # Check user
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        
        if user and check_password_hash(user['password'], password):
            if user['is_active'] == 0:
                flash('Account is deactivated.', 'danger')
                return redirect('/login')
            
            # Successful login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session.permanent = True
            
            # Update last login
            query_db('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user['id']])
            
            flash('Login successful!', 'success')
            
            # Redirect admin to admin panel, others to dashboard
            if user['is_admin']:
                return redirect('/admin_panel')
            else:
                return redirect('/dashboard')
        else:
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
        files=files,
        is_admin=session.get('is_admin', False)
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
        filename = secure_filename(file.filename)
        unique_filename = f"{session['user_id']}_{int(datetime.now().timestamp())}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(filepath)
            file_size = os.path.getsize(filepath)
            
            if file_size > 1073741824:
                os.remove(filepath)
                flash('File size exceeds 1GB limit!', 'danger')
                return redirect('/dashboard')
            
            query_db('''
                INSERT INTO files (filename, original_name, file_size, user_id) 
                VALUES (?, ?, ?, ?)
            ''', [unique_filename, filename, file_size, session['user_id']])
            
            flash(f'File "{filename}" uploaded successfully!', 'success')
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

# ==================== ADMIN ROUTES ====================

@app.route('/admin_panel')
def admin_panel():
    # Check if user is admin
    if not session.get('is_admin'):
        flash('🔒 Admin access required!', 'danger')
        return redirect('/')
    
    # Get statistics
    total_users = query_db('SELECT COUNT(*) FROM users', one=True)[0]
    total_files = query_db('SELECT COUNT(*) FROM files', one=True)[0]
    
    total_storage_result = query_db('SELECT SUM(file_size) FROM files', one=True)
    total_storage = total_storage_result[0] if total_storage_result[0] else 0
    
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
    
    return render_template_string(
        ADMIN_PANEL_TEMPLATE,
        admin_username=session.get('username'),
        total_users=total_users,
        total_files=total_files,
        total_storage=total_storage,
        active_pins=active_pins,
        users=users,
        user_files_counts=user_files_counts,
        all_files=all_files,
        valid_pins=VALID_PINS
    )

@app.route('/admin/generate_pin', methods=['POST'])
def admin_generate_pin():
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    admin_pin = request.form['admin_pin'].strip()
    uses = int(request.form['uses'])
    
    if admin_pin != ADMIN_PIN:
        flash('Invalid admin PIN', 'danger')
    else:
        # Generate new 8-digit PIN
        new_pin = ''.join(secrets.choice('0123456789') for _ in range(8))
        VALID_PINS[new_pin] = {
            'uses_left': uses,
            'created_by': session.get('username', 'admin')
        }
        flash(f'✅ New PIN generated: {new_pin} ({uses} uses)', 'success')
    
    return redirect('/admin_panel')

@app.route('/admin/delete_pin/<pin>')
def admin_delete_pin(pin):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    if pin in ['12345678', '87654321', '11112222']:
        flash('Cannot delete system PINs!', 'warning')
    elif pin in VALID_PINS:
        del VALID_PINS[pin]
        flash(f'PIN {pin} deleted!', 'success')
    else:
        flash('PIN not found!', 'danger')
    
    return redirect('/admin_panel')

@app.route('/admin/deactivate_user/<int:user_id>')
def admin_deactivate_user(user_id):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    query_db('UPDATE users SET is_active = 0 WHERE id = ?', [user_id])
    user = query_db('SELECT username FROM users WHERE id = ?', [user_id], one=True)
    if user:
        flash(f'User {user[0]} deactivated!', 'warning')
    
    return redirect('/admin_panel')

@app.route('/admin/activate_user/<int:user_id>')
def admin_activate_user(user_id):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    query_db('UPDATE users SET is_active = 1 WHERE id = ?', [user_id])
    user = query_db('SELECT username FROM users WHERE id = ?', [user_id], one=True)
    if user:
        flash(f'User {user[0]} activated!', 'success')
    
    return redirect('/admin_panel')

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    # Don't allow deleting admin user (ID 1)
    if user_id == 1:
        flash('Cannot delete admin user!', 'danger')
        return redirect('/admin_panel')
    
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
        
        flash(f'User {username} and all their files deleted!', 'success')
    
    return redirect('/admin_panel')

@app.route('/admin/download_file/<int:file_id>')
def admin_download_file(file_id):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file:
        flash('File not found', 'danger')
        return redirect('/admin_panel')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if not os.path.exists(filepath):
        flash('File not found on server', 'danger')
        return redirect('/admin_panel')
    
    return send_file(filepath, as_attachment=True, download_name=file['original_name'])

@app.route('/admin/delete_file/<int:file_id>')
def admin_delete_file(file_id):
    if not session.get('is_admin'):
        flash('Admin access required!', 'danger')
        return redirect('/')
    
    file = query_db('SELECT * FROM files WHERE id = ?', [file_id], one=True)
    
    if not file:
        flash('File not found', 'danger')
        return redirect('/admin_panel')
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    if os.path.exists(filepath):
        os.remove(filepath)
    
    query_db('DELETE FROM files WHERE id = ?', [file_id])
    flash('File deleted!', 'success')
    return redirect('/admin_panel')

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

# Health check endpoint
@app.route('/health')
def health_check():
    return 'OK', 200

# ==================== CREATE ADMIN USER ====================
def create_admin_user():
    """Ensure admin user exists"""
    admin_user = query_db('SELECT * FROM users WHERE username = ?', ['admin'], one=True)
    if not admin_user:
        hashed_pw = generate_password_hash('Admin@123')
        query_db('''
            INSERT INTO users (username, email, password, pin_used, is_active, is_admin) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ['admin', 'admin@example.com', hashed_pw, '12345678', 1, 1])
        print("=" * 60)
        print("✅ ADMIN USER CREATED!")
        print("   Username: admin")
        print("   Password: Admin@123")
        print("   Access: /admin_panel")
        print("=" * 60)
        return True
    return False

# ==================== MAIN ====================
if __name__ == '__main__':
    import os
    
    print("=" * 60)
    print("🔒 SECURE WEB APPLICATION")
    print("=" * 60)
    
    port = int(os.environ.get("PORT", 8080))
    
    print(f"🌐 Running on port: {port}")
    print(f"📁 Upload limit: 1GB per file")
    print("=" * 60)
    print("🔑 SECRET ADMIN ACCESS:")
    print("   • Username: admin")
    print("   • Password: Admin@123")
    print("   • Admin URL: /admin_panel")
    print("=" * 60)
    print("🔐 SECRET PINS (NOT SHOWN TO USERS):")
    print("   • 12345678 (100 uses)")
    print("   • 87654321 (5 uses)")
    print("   • 11112222 (1 use)")
    print("=" * 60)
    
    # Create admin user if doesn't exist
    created = create_admin_user()
    if not created:
        print("✅ Admin user already exists")
        print("=" * 60)
    
    # Create uploads directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(debug=False, host='0.0.0.0', port=port)