from flask import Blueprint, send_file, flash, redirect, url_for, session, request
from database.db import get_db_connection, log_system_event
from config import Config
import os
import json
import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/export_pdf/<module_type>/<int:record_id>')
def export_pdf(module_type, record_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    table_map = {
        'phishing': ('scans', 'Phishing URL Threat Analysis', 'url'),
        'sql': ('sql_analysis', 'SQL Injection Vulnerability Analysis', 'code_snippet'),
        'xss': ('xss_analysis', 'Cross-Site Scripting (XSS) Analysis', 'code_snippet'),
        'wifi': ('wifi_analysis', 'Fake WiFi Security Analysis', 'ssid'),
        'evil_twin': ('evil_twin_analysis', 'Evil Twin Detection Simulation', 'ssid')
    }

    if module_type not in table_map:
        conn.close()
        flash('Invalid report module type.', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    table_name, report_title, target_col = table_map[module_type]
    cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        flash('Requested record not found.', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    # Prepare PDF directory
    pdf_dir = os.path.join(Config.REPORTS_DIR, 'pdf')
    os.makedirs(pdf_dir, exist_ok=True)
    pdf_filename = f"{module_type}_report_{record_id}.pdf"
    pdf_path = os.path.join(pdf_dir, pdf_filename)

    # Build ReportLab Document
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1E293B')
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#2563EB')
    )

    heading_style = ParagraphStyle(
        'DocHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("Kryptic Vision Hub", title_style))
    elements.append(Paragraph(f"Security Threat Analysis Report — {report_title}", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=15))

    # Metadata Table
    risk_score = record.get('risk_score', 0)
    status_str = record.get('status') or record.get('severity') or 'Evaluated'
    
    if risk_score <= 25:
        score_color = colors.HexColor('#16A34A')
    elif risk_score <= 50:
        score_color = colors.HexColor('#F59E0B')
    else:
        score_color = colors.HexColor('#DC2626')

    target_val = record[target_col] if target_col in record.keys() else 'N/A'
    meta_data = [
        [Paragraph("<b>Report ID:</b>", body_style), Paragraph(f"#{record['id']}", body_style),
         Paragraph("<b>Date Generated:</b>", body_style), Paragraph(str(record['created_at']), body_style)],
        [Paragraph("<b>Target Input:</b>", body_style), Paragraph(str(target_val)[:40], body_style),
         Paragraph("<b>Status / Risk:</b>", body_style), Paragraph(f"<font color='{score_color.hexval()}'><b>{status_str} ({risk_score}%)</b></font>", body_style)]
    ]

    meta_table = Table(meta_data, colWidths=[90, 170, 90, 170])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 15))

    # Triggered Rules / Findings Section
    elements.append(Paragraph("Evaluated Threat Indicators", heading_style))
    
    reasons_raw = record.get('reasons_json') or record.get('issues_json') or record.get('rules_json') or '[]'
    try:
        findings = json.loads(reasons_raw)
    except Exception:
        findings = []

    findings_rows = [[Paragraph("<b>#</b>", body_style), Paragraph("<b>Indicator / Rule Description</b>", body_style)]]
    if isinstance(findings, list) and findings:
        for idx, item in enumerate(findings, 1):
            if isinstance(item, dict):
                desc = item.get('reason') or item.get('issue') or item.get('detail') or str(item)
            else:
                desc = str(item)
            findings_rows.append([Paragraph(str(idx), body_style), Paragraph(desc, body_style)])
    else:
        findings_rows.append([Paragraph("1", body_style), Paragraph("No security vulnerabilities or threat indicators identified.", body_style)])

    findings_table = Table(findings_rows, colWidths=[30, 490])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(findings_table)
    elements.append(Spacer(1, 15))

    # Recommendations Section
    elements.append(Paragraph("Security Recommendations", heading_style))
    rec_text = record.get('recommendation', 'Maintain standard security vigilance.')
    rec_p = Paragraph(f"<i>{rec_text}</i>", body_style)
    rec_table = Table([[rec_p]], colWidths=[520])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEF3C7' if risk_score > 25 else '#DCFCE7')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#F59E0B' if risk_score > 25 else '#16A34A')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    elements.append(rec_table)
    elements.append(Spacer(1, 20))

    # Footer Notice
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CBD5E1'), spaceAfter=8))
    footer_p = Paragraph("<font color='#64748B' size='8'>Generated by <b>Kryptic Vision Hub</b> — Educational Cyber Security Toolkit | University Project Demonstration</font>", body_style)
    elements.append(footer_p)

    # Build PDF
    doc.build(elements)

    user_id = session.get('user_id')
    log_system_event(user_id, 'PDF_EXPORT', f"Generated PDF report '{pdf_filename}' for {module_type} ID #{record_id}.", request.remote_addr)

    return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
