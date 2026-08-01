from flask import Blueprint, render_template, session, jsonify
from database.db import get_db_connection
from utils.helpers import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total Users count
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Total Phishing URL Scans for user
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
    total_phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Safe'", (user_id,))
    safe_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Suspicious'", (user_id,))
    suspicious_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Dangerous'", (user_id,))
    dangerous_scans = cursor.fetchone()[0]

    # Module specific counts
    cursor.execute("SELECT COUNT(*) FROM sql_analysis WHERE user_id = ?", (user_id,))
    sql_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM xss_analysis WHERE user_id = ?", (user_id,))
    xss_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM wifi_analysis WHERE user_id = ?", (user_id,))
    wifi_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM evil_twin_analysis WHERE user_id = ?", (user_id,))
    evil_twin_count = cursor.fetchone()[0]

    # High Risk & Safe counts aggregate across all modules
    cursor.execute("SELECT COUNT(*) FROM sql_analysis WHERE user_id = ? AND severity IN ('High', 'Critical')", (user_id,))
    sql_high_risk = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM xss_analysis WHERE user_id = ? AND severity IN ('High', 'Critical')", (user_id,))
    xss_high_risk = cursor.fetchone()[0]

    total_high_risk = dangerous_scans + sql_high_risk + xss_high_risk
    total_scans_all = total_phishing + sql_count + xss_count + wifi_count + evil_twin_count

    # Recent activity
    cursor.execute(
        "SELECT id, url, risk_score, status, recommendation, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
        (user_id,)
    )
    recent_scans = cursor.fetchall()

    conn.close()

    stats = {
        'total_users': total_users,
        'total_scans_all': total_scans_all,
        'total_phishing': total_phishing,
        'safe': safe_scans,
        'suspicious': suspicious_scans,
        'dangerous': dangerous_scans,
        'sql': sql_count,
        'xss': xss_count,
        'wifi': wifi_count,
        'evil_twin': evil_twin_count,
        'high_risk': total_high_risk
    }

    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

@dashboard_bp.route('/api/dashboard_charts')
@login_required
def dashboard_charts_api():
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()

    # Threat Distribution (Pie Chart)
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Safe'", (user_id,))
    safe = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Suspicious'", (user_id,))
    suspicious = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'Dangerous'", (user_id,))
    dangerous = cursor.fetchone()[0]

    # Module Usage (Bar Chart)
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
    phishing_cnt = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM sql_analysis WHERE user_id = ?", (user_id,))
    sql_cnt = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM xss_analysis WHERE user_id = ?", (user_id,))
    xss_cnt = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM wifi_analysis WHERE user_id = ?", (user_id,))
    wifi_cnt = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM evil_twin_analysis WHERE user_id = ?", (user_id,))
    evil_cnt = cursor.fetchone()[0]

    # Daily Scans Line Chart (Last 7 Days)
    cursor.execute("""
        SELECT DATE(created_at) as scan_date, COUNT(*) as cnt 
        FROM scans 
        WHERE user_id = ? 
        GROUP BY DATE(created_at) 
        ORDER BY scan_date DESC LIMIT 7
    """, (user_id,))
    daily_rows = cursor.fetchall()
    daily_labels = [r['scan_date'] for r in reversed(daily_rows)] or ['Today']
    daily_data = [r['cnt'] for r in reversed(daily_rows)] or [phishing_cnt]

    conn.close()

    return jsonify({
        'threat_distribution': {
            'labels': ['Safe', 'Suspicious', 'Dangerous / High Risk'],
            'data': [safe, suspicious, dangerous]
        },
        'module_usage': {
            'labels': ['Phishing URLs', 'SQL Code', 'XSS Code', 'WiFi Security', 'Evil Twin'],
            'data': [phishing_cnt, sql_cnt, xss_cnt, wifi_cnt, evil_cnt]
        },
        'daily_scans': {
            'labels': daily_labels,
            'data': daily_data
        },
        'safe_vs_dangerous': {
            'labels': ['Safe Results', 'Dangerous Results'],
            'data': [safe, dangerous]
        }
    })
