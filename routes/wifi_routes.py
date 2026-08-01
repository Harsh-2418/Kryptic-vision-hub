from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from database.db import get_db_connection
from scanner.wifi_detector import WiFiDetector
from utils.helpers import sanitize_input
from config import Config
import json
import os

wifi_bp = Blueprint('wifi', __name__)

@wifi_bp.route('/wifi_analyzer')
def wifi_page():
    return render_template('wifi_analyzer.html')

@wifi_bp.route('/analyze_wifi', methods=['POST'])
def analyze_wifi():
    ssid = sanitize_input(request.form.get('ssid'))
    encryption = sanitize_input(request.form.get('encryption'))
    signal_strength = sanitize_input(request.form.get('signal_strength'))
    channel = sanitize_input(request.form.get('channel'))
    frequency = sanitize_input(request.form.get('frequency'))
    
    trusted_ssid = sanitize_input(request.form.get('trusted_ssid'))
    trusted_encryption = sanitize_input(request.form.get('trusted_encryption'))
    trusted_channel = sanitize_input(request.form.get('trusted_channel'))

    analysis = WiFiDetector.analyze_network(
        ssid=ssid,
        encryption=encryption,
        signal_strength=signal_strength,
        channel=channel,
        frequency=frequency,
        trusted_ssid=trusted_ssid,
        trusted_encryption=trusted_encryption,
        trusted_channel=trusted_channel
    )

    if not analysis.get('success'):
        flash(analysis.get('error'), 'warning')
        return redirect(url_for('wifi.wifi_page'))

    user_id = session.get('user_id')
    rules_json = json.dumps(analysis['triggered_rules'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO wifi_analysis (user_id, ssid, risk_score, status, rules_json, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, analysis['ssid'], analysis['risk_score'], analysis['status'], rules_json, analysis['recommendation'])
    )
    conn.commit()
    analysis_id = cursor.lastrowid
    conn.close()

    return render_template('analysis_result.html', module_title="Fake WiFi Security Analysis", analysis=analysis, analysis_id=analysis_id, export_endpoint="wifi.export_wifi_report")

@wifi_bp.route('/export_wifi_report/<int:analysis_id>')
def export_wifi_report(analysis_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM wifi_analysis WHERE id = ?", (analysis_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        flash('Report not found.', 'danger')
        return redirect(url_for('wifi.wifi_page'))

    reports_dir = Config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"wifi_analysis_report_{analysis_id}.json"
    report_path = os.path.join(reports_dir, report_filename)

    report_data = {
        'report_type': 'Fake WiFi Security Analysis',
        'analysis_id': record['id'],
        'ssid': record['ssid'],
        'status': record['status'],
        'risk_score': f"{record['risk_score']}%",
        'triggered_rules': json.loads(record['rules_json']),
        'recommendation': record['recommendation'],
        'timestamp': record['created_at']
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)

    return send_file(report_path, as_attachment=True, download_name=report_filename)
