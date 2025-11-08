from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import markdown2
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure Gemini API
GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

# Store chat sessions
chat_sessions = {}

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def landing():
    """Landing page - public"""
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return render_template('signup.html')
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken!', 'error')
            return render_template('signup.html')
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        if not email or not password:
            flash('Please provide email and password!', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid email or password!', 'error')
            return render_template('login.html')
        
        login_user(user, remember=remember)
        flash(f'Welcome back, {user.username}!', 'success')
        
        # Redirect to next page or chat
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('chat'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('landing'))

# ==================== CHAT ROUTES (PROTECTED) ====================

@app.route('/chat')
@login_required
def chat():
    """Main chat page - requires login"""
    return render_template('index.html', user=current_user)

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    """Chat API endpoint"""
    try:
        data = request.json
        message = data.get('message')
        session_id = data.get('session_id', f'user_{current_user.id}_default')
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Get or create chat session
        if session_id not in chat_sessions:
            chat_sessions[session_id] = model.start_chat(history=[])
        
        chat = chat_sessions[session_id]
        
        # Send message and get response
        response = chat.send_message(message)
        
        # Convert markdown to HTML
        html_response = markdown2.markdown(
            response.text,
            extras=['fenced-code-blocks', 'tables', 'break-on-newline']
        )
        
        return jsonify({
            'response': html_response,
            'session_id': session_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear', methods=['POST'])
@login_required
def clear_chat():
    """Clear chat history"""
    try:
        data = request.json
        session_id = data.get('session_id', f'user_{current_user.id}_default')
        
        if session_id in chat_sessions:
            del chat_sessions[session_id]
        
        return jsonify({'message': 'Chat cleared successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

# ==================== SEO ROUTES ====================

from flask import send_from_directory

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

# ==================== ERROR HANDLERS ====================

# @app.errorhandler(404)
# def not_found(e):
#     return render_template('404.html'), 404

# @app.errorhandler(500)
# def server_error(e):
#     return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
