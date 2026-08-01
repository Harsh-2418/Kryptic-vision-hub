from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database.db import get_db_connection, log_system_event
from utils.helpers import sanitize_input
import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password.', 'warning')
            return render_template('login.html', email=email)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['is_admin'] = user['is_admin']

            # Update last_login
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user['id']))
            conn.commit()
            conn.close()

            # Audit log
            log_system_event(user['id'], 'LOGIN', f"User '{user['email']}' logged in successfully.", request.remote_addr)

            flash(f'Welcome back, {user["name"]}!', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard.dashboard'))

        conn.close()
        log_system_event(None, 'LOGIN_FAILED', f"Failed login attempt for email '{email}'.", request.remote_addr)
        flash('Invalid email or password. Please check your credentials.', 'danger')
        return render_template('login.html', email=email)

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'POST':
        name = sanitize_input(request.form.get('name'))
        email = sanitize_input(request.form.get('email'))
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not name or not email or not password:
            flash('All fields are required.', 'warning')
            return render_template('register.html', name=name, email=email)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', name=name, email=email)

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
            return render_template('register.html', name=name, email=email)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check existing user
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            flash('An account with this email already exists.', 'warning')
            return render_template('register.html', name=name, email=email)

        hashed_pw = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, hashed_pw)
        )
        conn.commit()
        new_user_id = cursor.lastrowid
        conn.close()

        log_system_event(new_user_id, 'REGISTER', f"New user account registered for '{email}'.", request.remote_addr)

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    email = session.get('user_email')
    if user_id:
        log_system_event(user_id, 'LOGOUT', f"User '{email}' logged out.", request.remote_addr)
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
