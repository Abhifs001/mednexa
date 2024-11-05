# app/views/auth.py

from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response, session, current_app
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
import logging 
import hashlib
import os
import base64 # sql table cannot accept some encoding so we are using base64 encoding
auth = Blueprint('auth', __name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# -----------------------------HASH FUNCTIONS 

def generate_password_hash(password, salt=None):
    if not salt:
        salt = os.urandom(16)  # Generate a new salt for each user
    hash_object = hashlib.sha256(salt + password.encode()).digest()
    # Store the salt + hash together, then encode in Base64 for safe storage
    return base64.b64encode(salt + hash_object).decode('utf-8')

def check_password_hash(stored_hash, password):
    stored_hash_bytes = base64.b64decode(stored_hash)  # Decode Base64
    salt = stored_hash_bytes[:16]  # Extract the salt from the stored hash
    stored_hash_value = stored_hash_bytes[16:]  # Extract the hash
    hash_object = hashlib.sha256(salt + password.encode()).digest()
    return hash_object == stored_hash_value

# -------------------LOGIN ROUTE---------------------------------------
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic validation
        if not email or not password:
            logger.warning("Email or password missing in login form.")
            flash('Email and password are required.', 'danger')
            return render_template('login.html')

        logger.debug(f"Login attempt with email: {email}")

        try:
            # Retrieve user using SQLAlchemy
            user = User.query.filter_by(email=email).first()
            logger.debug(f"User retrieved: {user}")

            # Check if user exists and password is correct
            if user:
                if check_password_hash(user.password, password):
                    # Manually set session variables
                    session['user_id'] = user.id
                    session['user_name'] = user.name
                    session['email'] = user.email 
                    session['logged_in'] = True
                    logger.info(f"User {user.email} logged in successfully.")
                    
                    flash('Login successful!', 'success')
                    return redirect('/dashboard')  # Redirect to dashboard
                else:
                    logger.warning("Incorrect password entered.")
                    flash('Incorrect password. Please try again.', 'danger')
            else:
                logger.warning(f"No user found with email: {email}")
                flash('Login unsuccessful. Please check email and password.', 'danger')

        except Exception as e:
            logger.error(f"An error occurred while logging in: {str(e)}")
            flash(f'An error occurred while logging in: {str(e)}', 'danger')

    return render_template('login.html')


# --------------------------SIGNUP ROUTE-----------------------------------
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic validation
        if not name or not email or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return render_template('signup.html')
        if password != confirm_password:
            flash('Passwords must match.', 'danger')
            return render_template('signup.html')

        try:
            # Check if the email already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email is already in use. Please choose a different one.', 'danger')
                return render_template('signup.html')

            # Hash password and create a new user instance
            h_password = generate_password_hash(password  )
            new_user = User(name=name, email=email, password=h_password)

            # Add the new user to the session and commit
            db.session.add(new_user)
            db.session.commit()
            
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('auth.login'))  # Redirect to login page

        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash(f'An error occurred while creating your account: {str(e)}', 'danger')
            print("Error:", str(e))

    return render_template('signup.html')

# -------------DASHBOARD ROUTE-------------
@auth.route('/dashboard')
def dashboard():
    # Check if the user is logged in by verifying session data
    if not session.get('logged_in'):
        flash('Please log in to access the dashboard.', 'danger')
        return redirect('/login')  # Redirect to login if not logged in

    # Retrieve user information from session to display on dashboard
    user_name = session.get('user_name')
    user_email = session.get('email')
    

    # Create a response to prevent caching (for added security)
    response = make_response(render_template('dashboard.html', username=user_name, email = user_email))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response
    




# ------------LOGOUT ROUTE 
@auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('email', None)
    flash('You have been logged out.', 'success')
    return redirect('/')
