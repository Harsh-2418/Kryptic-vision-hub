from flask import Blueprint, render_template, request, redirect, url_for, flash, session, make_response
from utils.helpers import login_required, sanitize_input
from database.db import log_system_event

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        theme_mode = sanitize_input(request.form.get('theme_mode', 'light'))
        email_notifications = request.form.get('email_notifications') == 'on'
        default_landing = sanitize_input(request.form.get('default_landing', 'dashboard'))

        session['theme_mode'] = theme_mode
        session['email_notifications'] = email_notifications
        session['default_landing'] = default_landing

        user_id = session.get('user_id')
        log_system_event(user_id, 'SETTINGS_UPDATE', f"Updated preferences: Theme '{theme_mode}', Landing '{default_landing}'.", request.remote_addr)

        flash('Settings updated successfully!', 'success')
        resp = make_response(redirect(url_for('settings.settings')))
        resp.set_cookie('theme_mode', theme_mode, max_age=30*24*60*60)
        return resp

    return render_template('settings.html')
