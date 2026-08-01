from functools import wraps
from flask import session, redirect, url_for, flash, request
import datetime
import html

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(text):
    if not text:
        return ""
    return html.escape(text.strip())

def format_timestamp(dt_str=None):
    if not dt_str:
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return dt_str
