import sqlite3

DB_NAME = "logs.db"

def init_db():
    """������������� ���� ������."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # �������� ������� �����
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            router_ip TEXT,
            message TEXT
        )
    ''')
    # �������� ������� �������������
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
        )
    ''')
    # �������� ������� ��������
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    # ���������� �������� �� ���������
    default_settings = [
        ('log_retention_days', '30'),
        ('max_db_size_mb', '100'),
        ('allow_new_routers', 'true')
    ]
    for key, value in default_settings:
        cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    # ���������� �������������� �� ���������
    cursor.execute('SELECT * FROM users WHERE username = "admin"')
    admin_exists = cursor.fetchone()
    if not admin_exists:
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('admin', 'admin1', 'admin'))
    conn.commit()
    conn.close()

def get_settings():
    """��������� ���� �������� �� ���� ������."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    settings = {key: value for key, value in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key, value):
    """���������� ��������� � ���� ������."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE settings SET value = ? WHERE key = ?', (value, key))
    conn.commit()
    conn.close()