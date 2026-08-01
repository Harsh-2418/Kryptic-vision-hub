from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from database.db import get_db_connection, log_system_event
from utils.helpers import login_required
from functools import wraps

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in as Administrator to access the Admin Panel.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        
        email = session.get('user_email')
        is_admin = session.get('is_admin')
        if email != 'admin@kryptic.com' and not is_admin:
            flash('Access Denied. Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard.dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # System counts
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_phishing_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM sql_analysis")
    total_sql = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM xss_analysis")
    total_xss = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM wifi_analysis")
    total_wifi = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM contact_messages")
    total_messages = cursor.fetchone()[0]

    # Fetch all users
    cursor.execute("SELECT id, name, email, is_admin, last_login, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()

    # Fetch recent contact messages
    cursor.execute("SELECT * FROM contact_messages ORDER BY created_at DESC LIMIT 10")
    contact_messages = cursor.fetchall()

    # Fetch recent audit logs
    cursor.execute("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 10")
    recent_logs = cursor.fetchall()

    conn.close()

    admin_stats = {
        'total_users': total_users,
        'total_scans': total_phishing_scans + total_sql + total_xss + total_wifi,
        'total_messages': total_messages,
        'total_sql': total_sql,
        'total_xss': total_xss,
        'total_wifi': total_wifi
    }

    return render_template('admin.html', stats=admin_stats, users=users, contact_messages=contact_messages, recent_logs=recent_logs)

@admin_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user and user['email'] == 'admin@kryptic.com':
        conn.close()
        flash('Default System Admin account cannot be deleted.', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    log_system_event(session.get('user_id'), 'ADMIN_DELETE_USER', f"Admin deleted user ID #{user_id}.", request.remote_addr)

    flash('User account deleted successfully.', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/admin/delete_message/<int:msg_id>', methods=['POST'])
@admin_required
def delete_message(msg_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM contact_messages WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    flash('Contact message deleted.', 'success')
    return redirect(url_for('admin.admin_dashboard'))
