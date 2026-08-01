from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import get_db_connection
from utils.helpers import sanitize_input

contact_bp = Blueprint('contact', __name__)

@contact_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = sanitize_input(request.form.get('name'))
        email = sanitize_input(request.form.get('email'))
        message = sanitize_input(request.form.get('message'))

        if not name or not email or not message:
            flash('All fields are required.', 'warning')
            return render_template('contact.html', name=name, email=email, message=message)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)",
            (name, email, message)
        )
        conn.commit()
        conn.close()

        flash('Thank you! Your message has been sent successfully. Our security team will review it shortly.', 'success')
        return redirect(url_for('contact.contact'))

    return render_template('contact.html')
