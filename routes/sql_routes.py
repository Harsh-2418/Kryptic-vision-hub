from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from database.db import get_db_connection
from scanner.sql_analyzer import SQLAnalyzer
from utils.helpers import sanitize_input
from config import Config
import json
import os

sql_bp = Blueprint('sql', __name__)

@sql_bp.route('/sql_analyzer')
def sql_page():
    return render_template('sql_analyzer.html')

@sql_bp.route('/analyze_sql', methods=['POST'])
def analyze_sql():
    code_snippet = request.form.get('code_snippet', '')
    analysis = SQLAnalyzer.analyze_code(code_snippet)

    if not analysis.get('success'):
        flash(analysis.get('error'), 'warning')
        return redirect(url_for('sql.sql_page'))

    user_id = session.get('user_id')
    issues_json = json.dumps(analysis['issues'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sql_analysis (user_id, code_snippet, severity, risk_score, issues_json, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, analysis['code_snippet'], analysis['severity'], analysis['risk_score'], issues_json, analysis['recommendation'])
    )
    conn.commit()
    analysis_id = cursor.lastrowid
    conn.close()

    return render_template('analysis_result.html', module_title="SQL Injection Vulnerability Analysis", analysis=analysis, analysis_id=analysis_id, export_endpoint="sql.export_sql_report")

@sql_bp.route('/export_sql_report/<int:analysis_id>')
def export_sql_report(analysis_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sql_analysis WHERE id = ?", (analysis_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        flash('Analysis report not found.', 'danger')
        return redirect(url_for('sql.sql_page'))

    reports_dir = Config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"sql_analysis_report_{analysis_id}.json"
    report_path = os.path.join(reports_dir, report_filename)

    report_data = {
        'report_type': 'SQL Injection Vulnerability Analysis',
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
