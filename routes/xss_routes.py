from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from database.db import get_db_connection
from scanner.xss_analyzer import XSSAnalyzer
from utils.helpers import sanitize_input
from config import Config
import json
import os

xss_bp = Blueprint('xss', __name__)

@xss_bp.route('/xss_analyzer')
def xss_page():
    return render_template('xss_analyzer.html')

@xss_bp.route('/analyze_xss', methods=['POST'])
def analyze_xss():
    code_snippet = request.form.get('code_snippet', '')
    analysis = XSSAnalyzer.analyze_code(code_snippet)

    if not analysis.get('success'):
        flash(analysis.get('error'), 'warning')
        return redirect(url_for('xss.xss_page'))

    user_id = session.get('user_id')
    issues_json = json.dumps(analysis['issues'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO xss_analysis (user_id, code_snippet, severity, risk_score, issues_json, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, analysis['code_snippet'], analysis['severity'], analysis['risk_score'], issues_json, analysis['recommendation'])
    )
    conn.commit()
    analysis_id = cursor.lastrowid
    conn.close()

    return render_template('analysis_result.html', module_title="Cross-Site Scripting (XSS) Analysis", analysis=analysis, analysis_id=analysis_id, export_endpoint="xss.export_xss_report")

@xss_bp.route('/export_xss_report/<int:analysis_id>')
def export_xss_report(analysis_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM xss_analysis WHERE id = ?", (analysis_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        flash('Analysis report not found.', 'danger')
        return redirect(url_for('xss.xss_page'))

    reports_dir = Config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"xss_analysis_report_{analysis_id}.json"
    report_path = os.path.join(reports_dir, report_filename)

    report_data = {
        'report_type': 'Cross-Site Scripting (XSS) Analysis',
        'analysis_id': record['id'],
        'severity': record['severity'],
        'risk_score': f"{record['risk_score']}%",
        'code_snippet': record['code_snippet'],
        'issues': json.loads(record['issues_json']),
        'recommendation': record['recommendation'],
        'timestamp': record['created_at']
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)

    return send_file(report_path, as_attachment=True, download_name=report_filename)
