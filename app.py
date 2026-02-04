from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Helper function to verify password
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Home Route
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if not all([username, email, password, confirm_password]):
            return render_template('register.html', error='All fields are required')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already exists')

        # Create user
        hashed_password = hash_password(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login', success='Registration successful! Please log in.'))
    
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        # Check if account is locked
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            return render_template('login.html', error='Account locked. Try again later.')

        if user and verify_password(password, user.password):
            # Reset failed attempts
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            if user.mfa_enabled:
                session['pre_mfa_user_id'] = user.id
                return redirect(url_for('verify_otp'))
            else:
                session['user_id'] = user.id
                session.permanent = True
                user.last_login = datetime.utcnow()
                db.session.commit()
                return redirect(url_for('dashboard'))
        else:
            # Track failed attempts
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

# Setup MFA Route
@app.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        
        if pyotp.TOTP(user.totp_secret).verify(otp_token):
            user.mfa_enabled = True
            db.session.commit()
            return redirect(url_for('dashboard', success='MFA enabled successfully!'))
        else:
            return render_template('setup_mfa.html', qr_code=generate_qr_code(user), error='Invalid OTP')
    
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
    
    qr_code = generate_qr_code(user)
    return render_template('setup_mfa.html', qr_code=qr_code, secret=user.totp_secret)

# Verify OTP Route
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pre_mfa_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['pre_mfa_user_id'])
    
    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        
        if pyotp.TOTP(user.totp_secret).verify(otp_token):
            session.pop('pre_mfa_user_id')
            session['user_id'] = user.id
            session.permanent = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return render_template('verify_otp.html', error='Invalid OTP. Try again.')
    
    return render_template('verify_otp.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Helper function to generate QR code
def generate_qr_code(user):
    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name='Secure MFA Auth')
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
