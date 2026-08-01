from flask import Blueprint, render_template, request, session
from database.db import get_db_connection
from utils.helpers import login_required, sanitize_input

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/logs')
@login_required
def view_logs():
    event_filter = sanitize_input(request.args.get('type', ''))
    conn = get_db_connection()
    cursor = conn.cursor()

    if event_filter:
        cursor.execute("SELECT * FROM system_logs WHERE event_type = ? ORDER BY created_at DESC LIMIT 100", (event_filter,))
    else:
        cursor.execute("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100")

    logs = cursor.fetchall()

    cursor.execute("SELECT DISTINCT event_type FROM system_logs")
    event_types = [r[0] for r in cursor.fetchall()]

    conn.close()
    return render_template('logs.html', logs=logs, event_types=event_types, current_filter=event_filter)
