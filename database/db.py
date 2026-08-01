import sqlite3
import os
from werkzeug.security import generate_password_hash
from config import Config

def get_db_connection():
    db_path = Config.DATABASE_PATH
    db_dir = os.path.dirname(db_path)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_pic TEXT DEFAULT NULL,
            last_login TIMESTAMP DEFAULT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure profile_pic, last_login, is_admin columns exist if created prior
    cursor.execute("PRAGMA table_info(users)")
    columns = [col['name'] for col in cursor.fetchall()]
    if 'profile_pic' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT DEFAULT NULL")
    if 'last_login' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP DEFAULT NULL")
    if 'is_admin' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")

    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            reasons_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create contact_messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create sql_analysis table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sql_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code_snippet TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            issues_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create xss_analysis table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS xss_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code_snippet TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            issues_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create wifi_analysis table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wifi_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ssid TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            rules_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create evil_twin_analysis table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evil_twin_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            rules_json TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create system_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed demo admin account with is_admin=1
    cursor.execute("SELECT id FROM users WHERE email = ?", ("admin@kryptic.com",))
    admin_user = cursor.fetchone()
    if not admin_user:
        hashed_pw = generate_password_hash("admin123")
        cursor.execute(
            "INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
            ("System Admin", "admin@kryptic.com", hashed_pw)
        )
    else:
        cursor.execute("UPDATE users SET is_admin = 1 WHERE email = ?", ("admin@kryptic.com",))

    conn.commit()
    conn.close()

def log_system_event(user_id, event_type, description, ip_address=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO system_logs (user_id, event_type, description, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, event_type, description, ip_address)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
