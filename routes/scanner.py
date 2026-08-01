from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from database.db import get_db_connection, log_system_event
from scanner.phishing_detector import PhishingDetector
from utils.helpers import login_required, sanitize_input
from config import Config
import json
import os

scanner_bp = Blueprint('scanner', __name__)

@scanner_bp.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@scanner_bp.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() if request.is_json else request.form
    target_url = sanitize_input(data.get('url'))

    if not target_url:
        if request.is_json:
            return jsonify({'success': False, 'error': 'URL is required.'}), 400
        flash('Please enter a website URL.', 'warning')
        return redirect(url_for('scanner.scanner_page'))

    analysis = PhishingDetector.analyze_url(target_url)

    if not analysis.get('success'):
        if request.is_json:
            return jsonify({'success': False, 'error': analysis.get('error')}), 400
        flash(analysis.get('error'), 'danger')
        return redirect(url_for('scanner.scanner_page'))

    user_id = session.get('user_id')
    reasons_json = json.dumps(analysis['reasons'])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (user_id, url, risk_score, status, reasons_json, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, analysis['url'], analysis['risk_score'], analysis['status'], reasons_json, analysis['recommendation'])
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    log_system_event(user_id, 'PHISHING_SCAN', f"Scanned URL '{analysis['url']}' — Result: {analysis['status']} ({analysis['risk_score']}%).", request.remote_addr)

    if request.is_json:
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'redirect_url': url_for('scanner.scan_result', scan_id=scan_id)
        })

    return redirect(url_for('scanner.scan_result', scan_id=scan_id))

@scanner_bp.route('/result/<int:scan_id>')
def scan_result(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    conn.close()

    if not scan:
        flash('Scan result not found.', 'danger')
        return redirect(url_for('scanner.scanner_page'))

    reasons = json.loads(scan['reasons_json'])
    
    score = scan['risk_score']
    if score <= 25:
        badge_color = "#16A34A"
        status_class = "success"
    elif score <= 50:
        badge_color = "#F59E0B"
        status_class = "warning"
    else:
        badge_color = "#DC2626"
        status_class = "danger"

    return render_template('result.html', scan=scan, reasons=reasons, badge_color=badge_color, status_class=status_class)

@scanner_bp.route('/history')
@login_required
def history():
    user_id = session.get('user_id')
    search_query = sanitize_input(request.args.get('q', ''))
    module_filter = sanitize_input(request.args.get('module', 'all'))
    risk_filter = sanitize_input(request.args.get('risk', 'all'))
    sort_by = sanitize_input(request.args.get('sort', 'newest'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Query scans with dynamic filter conditions
    sql_stmt = "SELECT id, 'phishing' as module_type, url as title, risk_score, status, created_at FROM scans WHERE user_id = ?"
    params = [user_id]

    if search_query:
        sql_stmt += " AND url LIKE ?"
        params.append(f"%{search_query}%")

    if risk_filter != 'all':
        sql_stmt += " AND status = ?"
        params.append(risk_filter)

    if sort_by == 'oldest':
        sql_stmt += " ORDER BY created_at ASC"
    elif sort_by == 'highest_risk':
        sql_stmt += " ORDER BY risk_score DESC"
    else:
        sql_stmt += " ORDER BY created_at DESC"

    cursor.execute(sql_stmt, params)
    scans = cursor.fetchall()
    conn.close()

    return render_template('history.html', scans=scans, search_query=search_query, module_filter=module_filter, risk_filter=risk_filter, sort_by=sort_by)

@scanner_bp.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
    conn.commit()
    conn.close()

    log_system_event(user_id, 'DELETE_SCAN', f"Deleted scan record ID #{scan_id}.", request.remote_addr)

    flash('Scan record deleted successfully.', 'success')
    return redirect(url_for('scanner.history'))
