# 🔐 Secure Authentication System with MFA

A complete, production-ready authentication system built with Flask featuring Multi-Factor Authentication (MFA) using Google Authenticator (TOTP). This project demonstrates modern security practices including password hashing, session management, rate limiting, and comprehensive user authentication flows.
## 🔗 You can try Here:

- [URL TO TRAIL MY PROJECT DEMO](https://secure-mfa-auth.onrender.com/)

## 📋 Features

### Core Authentication
- ✅ **User Registration** - Create new accounts with email validation
- ✅ **Secure Login** - Password hashing with bcrypt
- ✅ **Logout & Session Management** - Secure session handling with timeouts
- ✅ **Password Reset** - (Optional) Recovery mechanisms

### Multi-Factor Authentication (MFA)
- ✅ **TOTP Support** - Time-based One-Time Password (Google Authenticator)
- ✅ **QR Code Generation** - Easy setup with QR codes
- ✅ **Backup Codes** - (Optional) Recovery codes for account access
- ✅ **OTP Verification** - 6-digit code verification

### Security Features
- 🔒 **Password Hashing** - Industry-standard bcrypt hashing
- 🔒 **Account Lockout** - Protection against brute-force attacks (5 attempts)
- 🔒 **Session Timeout** - Automatic logout after 30 minutes
- 🔒 **Secure Cookies** - HttpOnly and Secure flags enabled
- 🔒 **CSRF Protection** - Built-in Flask protection
- 🔒 **Failed Attempt Tracking** - Monitor suspicious activities

### User Experience
- 📱 **Responsive Design** - Mobile-friendly interface
- 🎨 **Modern UI** - Gradient design with smooth animations
- 📊 **User Dashboard** - View profile and MFA status
- 🔐 **Security Tips** - Built-in security guidance

## 💻 Tech Stack

### Backend
- **Framework:** Flask 3.0.0
- **Database:** SQLite (SQLAlchemy ORM)
- **Authentication:** bcrypt, PyOTP
- **Security:** Werkzeug

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with gradients and animations
- **JavaScript** - Form validation and interactivity

### Dependencies
- **Flask** - Web framework
- **Flask-SQLAlchemy** - ORM for database
- **bcrypt** - Password hashing
- **PyOTP** - TOTP implementation
- **qrcode** - QR code generation
- **Pillow** - Image processing
- **python-dotenv** - Environment configuration

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Instructions

1. **Clone or navigate to the project directory:**
   ```bash
   cd secure-mfa-auth
   ```

2. **Create a virtual environment:**
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables (create .env file):**
   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here-change-in-production
   ```

5. **Initialize the database:**
   ```bash
   python app.py
   ```
   The database will be created automatically on first run.

6. **Run the application:**
   ```bash
   python app.py
   ```

7. **Access the application:**
   - Open your browser and navigate to `http://localhost:5000`
   - Register a new account
   - Login and enable MFA

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

# Visit http://localhost:5000 in your browser
```

## 📁 Project Structure

```
secure-mfa-auth/
│
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── database.db            # SQLite database (auto-created)
│
├── templates/             # HTML templates
│   ├── login.html         # Login page
│   ├── register.html      # Registration page
│   ├── verify_otp.html    # OTP verification page
│   ├── dashboard.html     # User dashboard
│   ├── setup_mfa.html     # MFA setup page
│   ├── 404.html          # Error page
│   └── 500.html          # Server error page
│
├── static/                # Static files
│   └── style.css          # Global styles
│
├── README.md              # Project documentation
└── .gitignore            # Git ignore rules
```

## 🔐 Security Best Practices Implemented

1. **Password Security**
   - Bcrypt hashing with salt
   - Minimum 8 character requirement
   - Password confirmation on registration

2. **Account Protection**
   - Login attempt limiting (5 attempts)
   - Account lockout for 15 minutes after failed attempts
   - Session timeout after 30 minutes of inactivity

3. **MFA Implementation**
   - TOTP (Time-Based One-Time Password) with PyOTP
   - QR code for easy authenticator setup
   - Backup secret key display

4. **Data Protection**
   - HttpOnly cookies (prevents XSS attacks)
   - Secure cookie flag (HTTPS only in production)
   - CSRF protection via Flask-WTF

5. **Database Security**
   - Password hashing before storage
   - No sensitive data in logs
   - SQL injection prevention via ORM

## 📱 How to Set Up MFA

1. **Create an account** and login
2. **Go to Dashboard** → Click "Enable MFA"
3. **Download an Authenticator App:**
   - Google Authenticator (iOS/Android)
   - Microsoft Authenticator
   - Authy
4. **Scan the QR code** in the app or enter the backup code manually
5. **Enter the 6-digit code** shown in the app to verify
6. **Done!** MFA is now enabled on your account

## 🧪 Testing

### Test Account Credentials
```
Username: testuser
Email: test@example.com
Password: Test@12345
```

### Test MFA Flow
1. Register with a test email
2. Login with credentials
3. Setup MFA using Google Authenticator
4. Use OTP codes for future logins

## 🌐 Deployment

### Deploy to Render (Recommended)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin <your-repo-url>
   git push -u origin main
   ```

2. **Create on Render:**
   - Go to https://render.com
   - Create new Web Service
   - Connect your GitHub repository
   - Set environment variables
   - Deploy

### Deploy to Heroku

1. **Install Heroku CLI**
2. **Create Procfile:**
   ```
   web: gunicorn app:app
   ```
3. **Deploy:**
   ```bash
   heroku login
   heroku create your-app-name
   git push heroku main
   ```

### Deploy to AWS

1. Use EC2 with Gunicorn and Nginx
2. Configure RDS for production database
3. Set up environment variables
4. Use Route 53 for domain management

## 📊 Database Schema

### Users Table
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email
- `password` - Hashed password
- `totp_secret` - TOTP secret key
- `mfa_enabled` - MFA status
- `created_at` - Account creation date
- `last_login` - Last login timestamp
- `failed_attempts` - Failed login counter
- `locked_until` - Account lockout timestamp

## 🔧 Configuration

### Environment Variables
```
SECRET_KEY=your-secret-key
FLASK_ENV=development  # or production
DATABASE_URL=sqlite:///database.db
```

### Flask Settings
- Debug mode: On (development only)
- Session timeout: 30 minutes
- Account lockout: 15 minutes after 5 failed attempts
- Port: 5000

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/` | Home page |
| GET/POST | `/register` | User registration |
| GET/POST | `/login` | User login |
| POST | `/logout` | User logout |
| GET | `/dashboard` | User dashboard |
| GET/POST | `/setup-mfa` | MFA setup |
| GET/POST | `/verify-otp` | OTP verification |

## 🐛 Troubleshooting

### Common Issues

**Issue: Database already exists**
- Delete `database.db` and restart the app

**Issue: Port 5000 already in use**
```bash
python app.py --port 5001
```

**Issue: QR Code not displaying**
- Ensure Pillow is installed: `pip install Pillow`

**Issue: OTP codes not working**
- Check device time is synced correctly
- Ensure correct time zone setting

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is open source and available under the MIT License.

## 👨‍💻 Author

Created as a complete, production-ready authentication system example.

## 🔗 Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PyOTP Documentation](https://pyotp.readthedocs.io/)
- [bcrypt Security](https://auth0.com/blog/hashing-passwords-one-way-road-to-security/)
- [Google Authenticator](https://support.google.com/accounts/answer/1066447)

## ⚠️ Important Security Notes

1. **Change SECRET_KEY** in production
2. **Enable HTTPS** in production (set SECURE_COOKIE_SECURE=True)
3. **Use environment variables** for sensitive data
4. **Regularly update dependencies**
5. **Implement CSRF protection** in forms
6. **Use strong database passwords**
7. **Enable SQL database backups**
8. **Monitor failed login attempts**
9. **Implement rate limiting** on APIs
10. **Keep authentication logs** for audit trails

## 📧 Support

For issues or questions:
- Create an issue on GitHub
- Check existing documentation
- Review error logs

---

**Last Updated:** February 2026
**Version:** 1.0.0
