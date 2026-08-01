from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from database.db import get_db_connection
from scanner.evil_twin_detector import EvilTwinDetector
from utils.helpers import sanitize_input
from config import Config
import json
import os

evil_twin_bp = Blueprint('evil_twin', __name__)

@evil_twin_bp.route('/evil_twin')
def evil_twin_page():
    return render_template('evil_twin.html')

@evil_twin_bp.route('/analyze_evil_twin', methods=['POST'])
def analyze_evil_twin():
    c_ssid = sanitize_input(request.form.get('current_ssid'))
    c_bssid = sanitize_input(request.form.get('current_bssid'))
    c_channel = sanitize_input(request.form.get('current_channel'))
    c_encryption = sanitize_input(request.form.get('current_encryption'))
    c_frequency = sanitize_input(request.form.get('current_frequency'))

    t_ssid = sanitize_input(request.form.get('trusted_ssid'))
    t_bssid = sanitize_input(request.form.get('trusted_bssid'))
    t_channel = sanitize_input(request.form.get('trusted_channel'))
    t_encryption = sanitize_input(request.form.get('trusted_encryption'))
    t_frequency = sanitize_input(request.form.get('trusted_frequency'))

    analysis = EvilTwinDetector.analyze_access_point(
        current_ssid=c_ssid,
        current_bssid=c_bssid,
        current_channel=c_channel,
        current_encryption=c_encryption,
        current_frequency=c_frequency,
        trusted_ssid=t_ssid,
        trusted_bssid=t_bssid,
        trusted_channel=t_channel,
        trusted_encryption=t_encryption,
        trusted_frequency=t_frequency
    )

    if not analysis.get('success'):
        flash(analysis.get('error'), 'warning')
        return redirect(url_for('evil_twin.evil_twin_page'))

    user_id = session.get('user_id')
    rules_json = json.dumps(analysis['triggered_rules'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO evil_twin_analysis (user_id, ssid, bssid, risk_score, status, rules_json, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, analysis['ssid'], analysis['bssid'], analysis['risk_score'], analysis['status'], rules_json, analysis['recommendation'])
    )
    conn.commit()
    analysis_id = cursor.lastrowid
    conn.close()

    return render_template('analysis_result.html', module_title="Evil Twin Detection Simulation", analysis=analysis, analysis_id=analysis_id, export_endpoint="evil_twin.export_evil_twin_report")

@evil_twin_bp.route('/export_evil_twin_report/<int:analysis_id>')
def export_evil_twin_report(analysis_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evil_twin_analysis WHERE id = ?", (analysis_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        flash('Report not found.', 'danger')
        return redirect(url_for('evil_twin.evil_twin_page'))

    reports_dir = Config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"evil_twin_report_{analysis_id}.json"
    report_path = os.path.join(reports_dir, report_filename)

    report_data = {
        'report_type': 'Evil Twin Detection Simulation',
        'analysis_id': record['id'],
        'ssid': record['ssid'],
        'bssid': record['bssid'],
        'status': record['status'],
        'risk_score': f"{record['risk_score']}%",
        'triggered_rules': json.loads(record['rules_json']),
        'recommendation': record['recommendation'],
        'timestamp': record['created_at']
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)

    return send_file(report_path, as_attachment=True, download_name=report_filename)
