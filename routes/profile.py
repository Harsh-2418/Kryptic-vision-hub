from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database.db import get_db_connection, log_system_event
from utils.helpers import login_required, sanitize_input

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    # Calculate total scans for this user
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
    total_scans = cursor.fetchone()[0]

    conn.close()
    return render_template('profile.html', user=user, total_scans=total_scans)

@profile_bp.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user_id = session.get('user_id')
    new_name = sanitize_input(request.form.get('name'))
    avatar = sanitize_input(request.form.get('avatar'))

    if not new_name:
        flash('Full name cannot be empty.', 'warning')
        return redirect(url_for('profile.profile'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name = ?, profile_pic = ? WHERE id = ?", (new_name, avatar, user_id))
    conn.commit()
    conn.close()

    session['user_name'] = new_name
    log_system_event(user_id, 'PROFILE_UPDATE', f"Updated profile name to '{new_name}'.", request.remote_addr)

    flash('Profile details updated successfully!', 'success')
    return redirect(url_for('profile.profile'))

@profile_bp.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = session.get('user_id')
    current_pw = request.form.get('current_password')
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')

    if not current_pw or not new_pw or not confirm_pw:
        flash('Please fill in all password fields.', 'warning')
        return redirect(url_for('profile.profile'))

    if new_pw != confirm_pw:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile.profile'))

    if len(new_pw) < 6:
        flash('Password must be at least 6 characters long.', 'warning')
        return redirect(url_for('profile.profile'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user['password_hash'], current_pw):
        conn.close()
        flash('Current password entered is incorrect.', 'danger')
        return redirect(url_for('profile.profile'))

    new_hashed_pw = generate_password_hash(new_pw)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hashed_pw, user_id))
    conn.commit()
    conn.close()

    log_system_event(user_id, 'PASSWORD_CHANGE', "Updated account password successfully.", request.remote_addr)

    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile.profile'))
