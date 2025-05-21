import os
import io
import base64
import hmac
import hashlib
from sqlalchemy import inspect, text
from functools import wraps
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask import (
    Flask, Blueprint, render_template, request, redirect, url_for,
    flash, session, current_app, send_file, g, has_request_context, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import pyotp
import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as crypto_padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import re

# Load environment variables from .env file
load_dotenv()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    if len(email) > 255:
        return False
    disposable_domains = {'mailinator.com', 'tempmail.com', '10minutemail.com'}
    domain = email.split('@')[1].lower()
    if domain in disposable_domains:
        return False
    return True

def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-key-fallback'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///./instance/securedocs.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    UPLOAD_FOLDER = 'Uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'fallback-32-byte-encryption-key')
    HMAC_KEY = os.environ.get('HMAC_KEY', 'fallback-32-byte-hmac-key').encode('utf-8')
    if isinstance(ENCRYPTION_KEY, str):
        ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY.encode('utf-8')
    else:
        ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY
    if len(ENCRYPTION_KEY_BYTES) < 32:
        ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY_BYTES.ljust(32, b'\0')
    elif len(ENCRYPTION_KEY_BYTES) > 32:
        ENCRYPTION_KEY_BYTES = ENCRYPTION_KEY_BYTES[:32]
    if len(HMAC_KEY) < 32:
        HMAC_KEY = HMAC_KEY.ljust(32, b'\0')
    elif len(HMAC_KEY) > 32:
        HMAC_KEY = HMAC_KEY[:32]
    PROCESSED_ENCRYPTION_KEY = ENCRYPTION_KEY_BYTES

    OAUTH_CREDENTIALS = {
        'github': {
            'id': os.environ.get('GITHUB_CLIENT_ID') or 'YOUR_GITHUB_CLIENT_ID',
            'secret': os.environ.get('GITHUB_CLIENT_SECRET') or 'YOUR_GITHUB_CLIENT_SECRET'
        },
        'auth0': {
            'id': os.environ.get('AUTH0_CLIENT_ID') or 'wOAFwXM2NWavmooqwRjMhwA3DhcvUhf2',
            'secret': os.environ.get('AUTH0_CLIENT_SECRET') or 'cJdlG60MdsPp-RdkVOKfpQEhEKK38aOQWZTWDemQFB89f-RpNBvreAXvbCFYupPA'
        }
    }
    SERVER_NAME = os.environ.get('SERVER_NAME', 'localhost:5000')

# --- Flask App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

instance_path = os.path.join(app.instance_path)
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

upload_folder_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
if not os.path.exists(upload_folder_path):
    os.makedirs(upload_folder_path)

if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///./instance/'):
    db_filename = app.config['SQLALCHEMY_DATABASE_URI'].split('/')[-1]
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, db_filename)}'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
oauth = OAuth(app)
migrate = Migrate(app, db)

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default='user', nullable=False)
    twofa_secret = db.Column(db.String(32), nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)
    documents = db.relationship('Document', backref='owner', lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship('AuditLog', backref='user_account', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"

class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    signature = db.Column(db.String(512), nullable=True)  # Document signature
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    file_hmac = db.Column(db.String(64), nullable=False)  # For encrypted file integrity
    file_hash = db.Column(db.String(64), nullable=True)   # SHA-256 of original file

    def __repr__(self):
        return f"<Document {self.filename}>"

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by User ID {self.user_id} at {self.timestamp}>"

# --- Helper Functions ---
def get_roles():
    return ['user', 'admin']

def get_user_by_id(user_id):
    return User.query.get(int(user_id))

def log_action(action, user_id=None, details=None):
    effective_user_id = user_id
    if effective_user_id is None and has_request_context() and hasattr(g, 'user_id'):
        effective_user_id = g.user_id
    audit_log = AuditLog(user_id=effective_user_id, action=action, details=details)
    db.session.add(audit_log)
    db.session.commit()

def setup_2fa_secret_and_qr():
    secret = pyotp.random_base32()
    user_email_for_qr = "User"
    if has_request_context() and current_user.is_authenticated:
        user_email_for_qr = current_user.email
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_email_for_qr, issuer_name="SecureDocsApp")
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return secret, f"data:image/png;base64,{img_str}"

def verify_2fa_code(secret, code):
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=0)

def encrypt_file_data(data_bytes):
    key = app.config['PROCESSED_ENCRYPTION_KEY']
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return cipher.nonce + tag + ciphertext

def decrypt_file_data(encrypted_blob_with_nonce_and_tag):
    key = app.config['PROCESSED_ENCRYPTION_KEY']
    nonce = encrypted_blob_with_nonce_and_tag[:16]
    tag = encrypted_blob_with_nonce_and_tag[16:32]
    ciphertext = encrypted_blob_with_nonce_and_tag[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError:
        log_action(action="Decryption or MAC verification failed.")
        return None

def generate_file_hmac(data):
    return hmac.new(app.config['HMAC_KEY'], data, hashlib.sha256).hexdigest()

def generate_user_key_pair(user):
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Assign keys to user
        user.private_key = private_pem
        user.public_key = public_pem
        db.session.commit()  # Explicit commit
        log_action(action="Generated RSA key pair", user_id=user.id)
        return True
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error generating RSA key pair: {e}", user_id=user.id)
        return False

def sign_document_data(data, user):
    try:
        if not user.private_key:
            log_action(action="No private key available for signing", user_id=user.id)
            return None
        private_key = serialization.load_pem_private_key(
            user.private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign(
            data,
            crypto_padding.PSS(
                mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                salt_length=crypto_padding.PSS.MAX_LENGTH
            ),
            crypto_hashes.SHA256()
        )
        return signature.hex()
    except Exception as e:
        log_action(action=f"Error signing document data: {e}", user_id=user.id)
        return None

def verify_document_signature(data, signature_hex, user):
    try:
        if not user.public_key or not signature_hex:
            return False
        public_key = serialization.load_pem_public_key(
            user.public_key.encode('utf-8'),
            backend=default_backend()
        )
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            data,
            crypto_padding.PSS(
                mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                salt_length=crypto_padding.PSS.MAX_LENGTH
            ),
            crypto_hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        log_action(action=f"Error verifying document signature: {e}", user_id=user.id)
        return False

def verify_document_integrity(file_path, stored_hmac):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        current_hmac = generate_file_hmac(data)
        return hmac.compare_digest(current_hmac.encode('utf-8'), stored_hmac.encode('utf-8'))
    except Exception as e:
        log_action(action=f"Error verifying document integrity: {e}")
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- OAuth Configuration ---
oauth.register(
    name='github',
    client_id=Config.OAUTH_CREDENTIALS['github']['id'],
    client_secret=Config.OAUTH_CREDENTIALS['github']['secret'],
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email read:user'},
)

oauth.register(
    name='auth0',
    client_id=Config.OAUTH_CREDENTIALS['auth0']['id'],
    client_secret=Config.OAUTH_CREDENTIALS['auth0']['secret'],
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
    api_base_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/'
)

# --- Blueprints ---
auth_bp = Blueprint('auth', __name__, template_folder='templates')

def twofa_required(f):
    """
    Custom decorator that checks if user is authenticated AND has completed 2FA verification (if enabled)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        
        # Check if 2FA is enabled for the user
        if current_user.twofa_secret:
            # Check if 2FA has been verified in this session
            if 'twofa_verified' not in session or session['twofa_verified'] != current_user.id:
                # Store the original request path for redirect after 2FA
                session['next'] = request.url
                flash('Please complete Two-Factor Authentication to continue.', 'warning')
                return redirect(url_for('auth.verify_2fa_on_login'))
                
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([email, password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('signup.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')
        if not validate_password(password):
            flash('Password must be at least 12 characters, include uppercase, lowercase, numbers, and special characters.', 'error')
            return render_template('signup.html')
        if not validate_email(email):
            flash('Invalid email address.', 'error')
            return render_template('signup.html')

        if User.query.filter_by(email=email).first():
            flash('This email address is already registered.', 'warning')
            return redirect(url_for('auth.signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()  # Commit first to get the user ID
        generate_user_key_pair(new_user)  # Then generate keys
        log_action(action=f"User signed up: {email}", user_id=new_user.id)
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')

@auth_bp.route('/disable_2fa', methods=['GET', 'POST'])
@twofa_required
def disable_2fa():
    if not current_user.twofa_secret:
        flash('Two-Factor Authentication is not enabled for your account.', 'info')
        return redirect(url_for('documents.dashboard'))

    if request.method == 'POST':
        current_user.twofa_secret = None
        db.session.commit()
        log_action(action="2FA disabled", user_id=current_user.id)
        flash('Two-Factor Authentication has been disabled successfully.', 'success')
        return redirect(url_for('documents.dashboard'))

    return render_template('disable_2fa.html', current_page='disable_2fa')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with that email.', 'error')
            log_action(action=f"Failed login attempt: No user found for email {email}")
            return render_template('login.html')
        
        if not user.password:
            flash('This account does not have a password set. Please use GitHub or Auth0 login.', 'error')
            log_action(action=f"Failed login attempt: No password set for email {email}")
            return render_template('login.html')

        if not check_password_hash(user.password, password):
            flash('Incorrect password. Please try again.', 'error')
            log_action(action=f"Failed login attempt: Incorrect password for email {email}")
            return render_template('login.html')

        login_user(user)
        if user.twofa_secret:
            session['user_id_for_2fa_verify'] = user.id
            session['remember_me'] = remember
            log_action(action=f"User login attempt (2FA required): {email}", user_id=user.id)
            return redirect(url_for('auth.verify_2fa_on_login'))
        
        login_user(user, remember=remember)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        session['user_id_for_2fa_setup'] = user.id
        flash('Please set up Two-Factor Authentication to continue.', 'warning')
        return redirect(url_for('auth.setup_2fa'))
    
    return render_template('login.html')

@auth_bp.route('/logout')
@twofa_required
def logout():
    user_id_for_log = current_user.id
    user_email_for_log = current_user.email
    logout_user()
    session.clear()  # This already clears all session data
    log_action(
        action="User logged out via button",
        user_id=user_id_for_log,
        details=f"User {user_email_for_log} (ID: {user_id_for_log}) logged out by clicking the logout button."
    )
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/verify_2fa_on_login', methods=['GET', 'POST'])
def verify_2fa_on_login():
    user_id = session.get('user_id_for_2fa_verify')
    if not user_id:
        flash("Invalid verification session. Please log in again.", "error")
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user or not user.twofa_secret:
        flash("2FA not enabled or user not found.", "error")
        session.pop('user_id_for_2fa_verify', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code')
        if verify_2fa_code(user.twofa_secret, code):
            session.pop('user_id_for_2fa_verify', None)
            login_user(user)
            g.user_id = user.id
            session['session_start_time'] = datetime.utcnow().timestamp()
            session['twofa_verified'] = user.id  # Add this line to mark 2FA as verified
            log_action(action="User logged in (2FA verified)", user_id=user.id)
            flash('Successfully verified and logged in!', 'success')
            return redirect(url_for('documents.dashboard'))
        
        flash('Invalid 2FA code.', 'error')
        log_action(action="Failed 2FA verification on login", user_id=user.id)

    return render_template('verify_2fa.html', current_page='verify_2fa')

@auth_bp.route('/login/auth0/')
def auth0_login():
    try:
        redirect_uri = url_for('auth.auth0_callback', _external=True)
        log_action(action=f"Initiating Auth0 login with redirect URI: {redirect_uri}")
        return oauth.auth0.authorize_redirect(redirect_uri)
    except Exception as e:
        log_action(action=f"Auth0 OAuth initiation error: {str(e)}")
        flash(f'Failed to initiate Auth0 login: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/auth0/callback')
def auth0_callback():
    try:
        token = oauth.auth0.authorize_access_token()
        if not token:
            log_action(action="Auth0 OAuth failed: No token received")
            flash('Failed to authorize with Auth0: No token received.', 'error')
            return redirect(url_for('auth.login'))

        resp = oauth.auth0.get('userinfo', token=token)
        resp.raise_for_status()
        user_info = resp.json()
        log_action(action=f"Auth0 userinfo response: {user_info}")

        email = user_info.get('email')
        if not email:
            log_action(action="Auth0 OAuth failed: No email found")
            flash('No email found from Auth0. Please ensure your Auth0 account has a verified email.', 'error')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, role='user')
            db.session.add(user)
            db.session.commit()
            generate_user_key_pair(user)
            log_action(action=f"New user signed up via Auth0: {email}", user_id=user.id)
            flash('Your account has been successfully created via Auth0!', 'success')
        else:
            log_action(action=f"User logged in via Auth0: {email}", user_id=user.id)
            flash('Logged in successfully via Auth0!', 'success')

        login_user(user)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        return redirect(url_for('documents.dashboard'))

    except Exception as e:
        log_action(action=f"Auth0 OAuth callback error: {str(e)}")
        flash(f'An error occurred during Auth0 authentication: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/github/')
def github_login():
    try:
        redirect_uri = url_for('auth.github_callback', _external=True)
        return oauth.github.authorize_redirect(redirect_uri)
    except Exception as e:
        log_action(action=f"GitHub OAuth initiation error: {str(e)}")
        flash(f'Failed to initiate GitHub login: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/login/github/callback')
def github_callback():
    try:
        token = oauth.github.authorize_access_token()
        if not token:
            log_action(action="GitHub OAuth failed: No token received")
            flash('Failed to authorize with GitHub: No token received.', 'error')
            return redirect(url_for('auth.login'))
        
        resp = oauth.github.get('user', token=token)
        resp.raise_for_status()
        user_info = resp.json()
        
        email = user_info.get('email')
        if not email:
            email_resp = oauth.github.get('user/emails', token=token)
            email_resp.raise_for_status()
            emails_data = email_resp.json()
            primary_email_obj = next((e for e in emails_data if e.get('primary') and e.get('verified')), None)
            if primary_email_obj:
                email = primary_email_obj['email']
            else:
                verified_email_obj = next((e for e in emails_data if e.get('verified')), None)
                if verified_email_obj:
                    email = verified_email_obj['email']
                else:
                    log_action(action="GitHub OAuth failed: No verified email found")
                    flash('No verified email found from GitHub. Please ensure you have a primary, verified email on your GitHub account.', 'error')
                    return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, role='user')
            db.session.add(user)
            db.session.commit()
            generate_user_key_pair(user)
            log_action(action=f"New user signed up via GitHub: {email}", user_id=user.id)
            flash('Your account has been successfully created via GitHub!', 'success')
        else:
            log_action(action=f"User logged in via GitHub: {email}", user_id=user.id)
            flash('Logged in successfully via GitHub!', 'success')

        login_user(user)
        g.user_id = user.id
        session['session_start_time'] = datetime.utcnow().timestamp()
        return redirect(url_for('documents.dashboard'))

    except Exception as e:
        log_action(action=f"GitHub OAuth callback error: {str(e)}")
        flash(f'An error occurred during GitHub authentication: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/setup_2fa', methods=['GET', 'POST'])
@twofa_required
def setup_2fa():
    user = User.query.get(session.get('user_id_for_2fa_setup', current_user.id))
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code')
        temp_secret = session.get(f'temp_2fa_secret_{user.id}')
        if not temp_secret:
            flash("2FA setup session expired. Please try again.", "error")
            return redirect(url_for('auth.setup_2fa'))

        if verify_2fa_code(temp_secret, code):
            user.twofa_secret = temp_secret
            db.session.commit()
            session.pop(f'temp_2fa_secret_{user.id}', None)
            session.pop('user_id_for_2fa_setup', None)
            log_action(action="2FA enabled", user_id=user.id)
            flash('Two-Factor Authentication enabled successfully!', 'success')
            return redirect(url_for('documents.dashboard'))
        
        flash('Invalid 2FA code. Please try again.', 'error')
        log_action(action="2FA setup failed (invalid code)", user_id=user.id)
        uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(name=user.email, issuer_name="SecureDocsApp")
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_img = base64.b64encode(buffered.getvalue()).decode('utf-8')
        return render_template('setup_2fa.html', qr_code=f"data:image/png;base64,{qr_code_img}", for_setup=True, current_page='setup_2fa')

    secret, qr_code_img = setup_2fa_secret_and_qr()
    session[f'temp_2fa_secret_{user.id}'] = secret
    log_action(action="Initiated 2FA setup", user_id=user.id)
    return render_template('setup_2fa.html', qr_code=qr_code_img, for_setup=True, current_page='setup_2fa')

@auth_bp.route('/setup_signing_keys', methods=['POST'])
@twofa_required
def setup_signing_keys():
    if generate_user_key_pair(current_user):
        flash('RSA key pair generated successfully.', 'success')
    else:
        flash('Failed to generate RSA key pair.', 'error')
    return redirect(url_for('rbac.profile'))

# Documents Blueprint
documents_bp = Blueprint('documents', __name__, template_folder='templates')

@documents_bp.route('/dashboard')
@twofa_required
def dashboard():
    document_count = Document.query.filter_by(user_id=current_user.id).count()
    return render_template('dashboard.html', document_count=document_count, current_page='dashboard')

@documents_bp.route('/upload', methods=['GET', 'POST'])
@twofa_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part selected.', 'warning')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading.', 'warning')
            return redirect(request.url)

        if file:
            original_filename = file.filename
            allowed_extensions = {'.pdf', '.docx', '.txt'}
            if not any(original_filename.lower().endswith(ext) for ext in allowed_extensions):
                flash('Unsupported file type. Allowed files: PDF, DOCX, TXT.', 'error')
                return redirect(request.url)

            file_data = file.read()
            if len(file_data) == 0:
                flash('The selected file is empty.', 'warning')
                return redirect(request.url)
            if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
                flash(f"File size exceeds the maximum limit of {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB.", "error")
                return redirect(request.url)

            try:
                file_data = file.read()
                
                # Generate SHA-256 hash of original file (optional)
                file_hash = hashlib.sha256(file_data).hexdigest()
                
                encrypted_blob = encrypt_file_data(file_data)
                if encrypted_blob is None:
                    flash('File encryption failed.', 'error')
                    return redirect(request.url)
                
                # Generate HMAC of encrypted data (for storage integrity)
                file_hmac = generate_file_hmac(encrypted_blob)
                
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
                encrypted_filename = f"document_{current_user.id}_{timestamp}.enc"
                encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_blob)

                document = Document(
                    user_id=current_user.id,
                    filename=original_filename,
                    file_path=encrypted_file_path,
                    file_hmac=file_hmac,
                    file_hash=file_hash
                )
                db.session.add(document)
                db.session.commit()
                
                log_action(action=f"Uploaded file: {original_filename}", user_id=current_user.id, details=f"Document ID: {document.id}, Saved as: {encrypted_filename}")
                flash('File uploaded and encrypted successfully! You can sign it from the document list.', 'success')
                return redirect(url_for('documents.list_documents'))
            except Exception as e:
                db.session.rollback()  # Explicit rollback on error
                log_action(action=f"Error uploading file {original_filename}: {e}", user_id=current_user.id)
                flash(f'An error occurred while processing the file: {str(e)}', 'error')
                return redirect(request.url)
    return render_template('upload.html', current_page='upload')

@documents_bp.route('/list')
@twofa_required
def list_documents():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    if current_user.role == 'admin':
        pagination = Document.query.order_by(Document.upload_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        pagination = Document.query.filter_by(user_id=current_user.id).order_by(Document.upload_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    documents_on_page = pagination.items
    return render_template('documents.html', documents=documents_on_page, pagination=pagination, current_page='list_documents')

@documents_bp.route('/edit/<int:document_id>', methods=['GET', 'POST'])
@twofa_required
def edit_document(document_id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit document names.', 'danger')
        log_action(action=f"Unauthorized attempt to edit document name: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    
    document = Document.query.get_or_404(document_id)
    
    if request.method == 'POST':
        new_filename = request.form.get('filename')
        if not new_filename:
            flash('Filename cannot be empty.', 'error')
            return render_template('edit_document.html', document=document, current_page='edit_document')
        
        allowed_extensions = {'.pdf', '.docx', '.txt'}
        if not any(new_filename.lower().endswith(ext) for ext in allowed_extensions):
            flash('Invalid file extension. Allowed extensions: PDF, DOCX, TXT.', 'error')
            return render_template('edit_document.html', document=document, current_page='edit_document')
        
        if len(new_filename) > 255:
            flash('Filename is too long (max 255 characters).', 'error')
            return render_template('edit_document.html', document=document, current_page='edit_document')
        
        old_filename = document.filename
        document.filename = new_filename
        try:
            db.session.commit()
            log_action(
                action=f"Document name changed: DocID {document_id}",
                user_id=current_user.id,
                details=f"Changed from '{old_filename}' to '{new_filename}'"
            )
            flash(f"Document name updated to '{new_filename}' successfully.", 'success')
            return redirect(url_for('documents.list_documents'))
        except Exception as e:
            db.session.rollback()
            log_action(action=f"Error editing document name for DocID {document_id}: {e}", user_id=current_user.id)
            flash(f"An error occurred while updating the document name: {str(e)}", 'error')
            return render_template('edit_document.html', document=document, current_page='edit_document')
    
    return render_template('edit_document.html', document=document, current_page='edit_document')

@documents_bp.route('/download/<int:document_id>')
@twofa_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        log_action(action=f"Unauthorized download attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    if not os.path.exists(document.file_path):
        flash('File not found on the server.', 'error')
        log_action(action=f"File not found for DocID {document_id}: {document.file_path}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    if not verify_document_integrity(document.file_path, document.file_hmac):  # Changed document.hash to document.file_hmac
        flash('File integrity check failed (HMAC mismatch). The file might be corrupted.', 'error')
        log_action(action=f"Integrity check failed for DocID {document_id} (encrypted data)", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))
    
    with open(document.file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file_data(encrypted_data)
    if decrypted_data is None:
        flash('Failed to decrypt the file. It might be corrupted or the encryption key has changed.', 'error')
        log_action(action=f"Decryption failed for DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    log_action(action=f"Downloaded file: {document.filename}", user_id=current_user.id, details=f"Document ID: {document_id}")
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=document.filename,
        as_attachment=True,
        mimetype='application/octet-stream'
    )

@documents_bp.route('/sign/<int:document_id>', methods=['POST'])
@twofa_required
def sign_document(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to sign this file.', 'danger')
        log_action(action=f"Unauthorized sign attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    if not current_user.private_key:
        flash('You need to set up a signing key pair first.', 'error')
        return redirect(url_for('auth.setup_signing_keys'))

    try:
        with open(document.file_path, 'rb') as f:
            encrypted_data = f.read()
        
        signature = sign_document_data(encrypted_data, current_user)
        if signature is None:
            flash('Failed to sign the document.', 'error')
            return redirect(url_for('documents.list_documents'))

        document.signature = signature
        db.session.commit()
        log_action(action=f"Signed document: {document.filename}", user_id=current_user.id, details=f"Document ID: {document_id}")
        flash(f'Document "{document.filename}" signed successfully.', 'success')
    except Exception as e:
        log_action(action=f"Error signing document (DocID {document_id}): {e}", user_id=current_user.id)
        flash(f'An error occurred while signing the document: {str(e)}', 'error')

    return redirect(url_for('documents.list_documents'))

@documents_bp.route('/verify_signature/<int:document_id>')
@twofa_required
def verify_signature(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to verify this file’s signature.', 'danger')
        log_action(action=f"Unauthorized signature verify attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    if not document.signature:
        flash('This document has not been signed.', 'warning')
        return redirect(url_for('documents.list_documents'))

    try:
        with open(document.file_path, 'rb') as f:
            encrypted_data = f.read()
        
        if verify_document_signature(encrypted_data, document.signature, document.owner):
            flash(f'Signature for "{document.filename}" is valid.', 'success')
            log_action(action=f"Verified signature for document: {document.filename}", user_id=current_user.id, details=f"Document ID: {document_id}")
        else:
            flash(f'Signature for "{document.filename}" is invalid.', 'error')
            log_action(action=f"Invalid signature for document: {document.filename}", user_id=current_user.id, details=f"Document ID: {document_id}")
    except Exception as e:
        log_action(action=f"Error verifying signature for DocID {document_id}: {e}", user_id=current_user.id)
        flash(f'An error occurred while verifying the signature: {str(e)}', 'error')

    return redirect(url_for('documents.list_documents'))

@documents_bp.route('/delete/<int:document_id>', methods=['POST'])
@twofa_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)
    if document.owner.id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this file.', 'danger')
        log_action(action=f"Unauthorized delete attempt: DocID {document_id}", user_id=current_user.id)
        return redirect(url_for('documents.list_documents'))

    try:
        filename_for_log = document.filename
        file_path = document.file_path
        if os.path.exists(file_path):
            os.remove(file_path)
            log_action(action=f"Deleted file from disk: {file_path}", user_id=current_user.id)
        db.session.delete(document)
        db.session.commit()
        log_action(action=f"Deleted file: {filename_for_log}", user_id=current_user.id, details=f"Document ID: {document_id}")
        flash(f'File "{filename_for_log}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error deleting file (DocID {document_id}): {e}", user_id=current_user.id)
        flash(f'An error occurred while deleting the file: {str(e)}', 'error')
        
    return redirect(url_for('documents.list_documents'))

# RBAC Blueprint
rbac_bp = Blueprint('rbac', __name__, template_folder='templates')

@rbac_bp.route('/users')
@twofa_required
def list_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        log_action(action="Unauthorized access attempt to user list", user_id=current_user.id)
        return redirect(url_for('documents.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search', '')
    query = User.query
    if search_query:
        query = query.filter(User.email.ilike(f'%{search_query}%'))
    user_pagination = query.order_by(User.email).paginate(page=page, per_page=per_page, error_out=False)
    all_users = user_pagination.items
    return render_template('admin/users.html', users=all_users, pagination=user_pagination, current_page='list_users', search_query=search_query)

@rbac_bp.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@twofa_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('documents.dashboard'))
    
    user_to_edit = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_role = request.form.get('role')
        if new_role not in get_roles():
            flash('Invalid role selected.', 'error')
        else:
            if user_to_edit.id == current_user.id and user_to_edit.role == 'admin' and new_role != 'admin':
                flash('You cannot remove your own admin role.', 'warning')
            else:
                old_role = user_to_edit.role
                user_to_edit.role = new_role
                db.session.commit()
                log_action(action=f"User role changed for {user_to_edit.email} from {old_role} to {new_role}", user_id=current_user.id)
                flash(f'User role for {user_to_edit.email} updated successfully.', 'success')
                return redirect(url_for('rbac.list_users'))
                
    return render_template('admin/edit_user.html', user_to_edit=user_to_edit, roles=get_roles(), current_page='edit_user')

@rbac_bp.route('/user/delete/<int:user_id>', methods=['POST'])
@twofa_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('documents.dashboard'))

    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('rbac.list_users'))

    try:
        email_deleted_log = user_to_delete.email
        db.session.delete(user_to_delete)
        db.session.commit()
        log_action(action=f"User deleted: {email_deleted_log}", user_id=current_user.id)
        flash(f'User {email_deleted_log} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        log_action(action=f"Error deleting user {user_to_delete.email}: {e}", user_id=current_user.id)
        flash(f'An error occurred while deleting the user: {str(e)}', 'error')
        
    return redirect(url_for('rbac.list_users'))

@rbac_bp.route('/user/add', methods=['GET', 'POST'])
@twofa_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('documents.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')
        if not all([email, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('rbac.add_user'))
        if role not in ['user', 'admin']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('rbac.add_user'))
        if not validate_email(email):
            flash('Invalid email address', 'error')
            return redirect(url_for('rbac.add_user'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'warning')
            return redirect(url_for('rbac.add_user'))
        temp_password = os.urandom(8).hex()
        new_user = User(
            email=email,
            password=generate_password_hash(temp_password, method='pbkdf2:sha256'),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        generate_user_key_pair(new_user)
        log_action(
            action=f"Admin created user: {email}",
            user_id=current_user.id,
            details=f"Role: {role}, Temp password: {temp_password}"
        )
        flash(f'User {email} created successfully! Temporary password: {temp_password}', 'success')
        return redirect(url_for('rbac.list_users'))

    return render_template('admin/add_user.html', current_page='add_user')

@rbac_bp.route('/profile', methods=['GET', 'POST'])
@twofa_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if new_password:
            if not current_user.password:
                flash("You cannot change your password as your account was created via OAuth and does not have a local password. You can set one if you wish.", "info")
            elif not current_password or not check_password_hash(current_user.password, current_password):
                flash('Your current password is incorrect.', 'error')
            elif new_password != confirm_new_password:
                flash('The new passwords do not match.', 'error')
            elif not validate_password(new_password):
                flash('New password must be at least 12 characters, include uppercase, lowercase, numbers, and special characters.', 'error')
            else:
                current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                log_action(action="User changed password", user_id=current_user.id)
                flash('Your password has been updated successfully.', 'success')
                return redirect(url_for('rbac.profile'))
        else:
            if not any(request.form.values()):
                flash('No changes were submitted.', 'info')
    return render_template('profile.html', current_page='profile')

# Security Blueprint
security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/audit_logs')
@twofa_required
def audit_logs_list():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('documents.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 15
    search_query = request.args.get('search', '')
    query = AuditLog.query
    if search_query:
        query = query.join(User, AuditLog.user_id == User.id, isouter=True).filter(
            db.or_(
                AuditLog.action.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%'),
                AuditLog.details.ilike(f'%{search_query}%')
            )
        )
    log_pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    logs = log_pagination.items
    return render_template('admin/audit_logs.html', logs=logs, pagination=log_pagination, current_page='audit_logs', search_query=search_query)

# --- Request Hooks ---
@app.before_request
def before_request():
    if current_user.is_authenticated:
        g.user_id = current_user.id

@app.teardown_request
def teardown_request(exception=None):
    if hasattr(g, 'user_id') and g.user_id is not None:
        if not current_user.is_authenticated:
            user = User.query.get(g.user_id)
            if user:
                log_action(
                    action="User session ended",
                    user_id=g.user_id,
                    details=f"User {user.email} (ID: {g.user_id}) left the website or session expired."
                )
        delattr(g, 'user_id')

# --- Register Blueprints ---
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(documents_bp, url_prefix='/documents')
app.register_blueprint(rbac_bp, url_prefix='/admin/rbac')
app.register_blueprint(security_bp, url_prefix='/admin/security')

# --- Root Route ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('documents.dashboard'))
    return redirect(url_for('auth.login'))

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    log_action(action=f"404 Not Found: {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    log_action(action=f"500 Internal Server Error: {request.url} - Error: {str(error)}", user_id=current_user.id if current_user.is_authenticated else None)
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    log_action(action=f"403 Forbidden: {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    return render_template('errors/403.html'), 403

@app.errorhandler(401)
def unauthorized_access(error):
    log_action(action=f"401 Unauthorized (handler): {request.url}", user_id=current_user.id if current_user.is_authenticated else None)
    flash("You need to be logged in to access this page.", "warning")
    return redirect(url_for('auth.login', next=request.url))

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    is_admin_user = False
    if current_user.is_authenticated and hasattr(current_user, 'role') and current_user.role == 'admin':
        is_admin_user = True
    return dict(is_admin_user=is_admin_user)

# --- Main Execution ---
if __name__ == '__main__':
    # Replace the schema update code in your __main__ block with this:
    with app.app_context():
        try:
            # First ensure all existing connections are closed
            db.session.close_all()
            
            # Get a fresh connection
            with db.engine.connect() as conn:
                # Start a transaction
                trans = conn.begin()
                
                try:
                    # Check the schema
                    inspector = inspect(db.engine)
                    existing_columns = {col['name']: col for col in inspector.get_columns('document')}

                    # If 'hash' exists and is NOT NULL, we need to handle it
                    if 'hash' in existing_columns:
                        # First check if we can drop the NOT NULL constraint if needed
                        if existing_columns['hash'].get('nullable') is False:
                            conn.execute(text('ALTER TABLE document ALTER COLUMN hash DROP NOT NULL'))
                        
                        # Then rename it to file_hash if file_hash doesn't exist
                        if 'file_hash' not in existing_columns:
                            conn.execute(text('ALTER TABLE document RENAME COLUMN hash TO file_hash'))
                            print("Renamed 'hash' column to 'file_hash' in 'document' table.")
                    
                    # Add missing columns if they don't exist
                    if 'file_hmac' not in existing_columns:
                        conn.execute(text('ALTER TABLE document ADD COLUMN file_hmac VARCHAR(64) NOT NULL DEFAULT ""'))
                        print("Added 'file_hmac' column to 'document' table.")
                    
                    # Commit the schema changes
                    trans.commit()
                    
                    # Log the schema changes
                    try:
                        log_action(action="Schema updated: Modified document table columns.")
                    except:
                        pass  # Don't fail if logging doesn't work
                    
                    # Now handle the admin user creation
                    db.session.close()  # Ensure no active session
                    
                    admin_user = User.query.filter_by(email='admin@example.com').first()
                    default_admin_pass = 'AdminSecure123!'
                    
                    if not admin_user:
                        admin_user = User(
                            email='admin@example.com',
                            password=generate_password_hash(default_admin_pass, method='pbkdf2:sha256'),
                            role='admin'
                        )
                        db.session.add(admin_user)
                        db.session.commit()
                        generate_user_key_pair(admin_user)
                        print(f"Default admin user 'admin@example.com' created with password 'AdminSecure123!'. Please change the password immediately after logging in.")
                    else:
                        if admin_user.password and not admin_user.password.startswith('pbkdf2:sha256'):
                            admin_user.password = generate_password_hash(default_admin_pass, method='pbkdf2:sha256')
                            db.session.commit()
                            print(f"Reset admin user password to use pbkdf2:sha256. New password: 'AdminSecure123!'. Please change it immediately after logging in.")
                
                except Exception as e:
                    trans.rollback()
                    print(f"Error during schema update: {e}")
                    raise

        except Exception as e:
            print(f"CRITICAL: Error during app initialization or DB setup: {e}")
            try:
                log_action(action=f"CRITICAL Error during app initialization or DB setup: {e}")
            except:
                pass  # Don't fail if logging doesn't work
            
    flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    run_host = os.environ.get('HOST', '0.0.0.0')
    run_port = int(os.environ.get('PORT', 5000))
    app.run(debug=flask_debug, host=run_host, port=run_port, ssl_context=('cert.pem', 'key.pem'))
