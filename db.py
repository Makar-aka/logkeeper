import sqlite3

LOGS_DB_NAME = "logs.db"
LOGKEEPER_DB_NAME = "logkeeper.db"

def init_db():
    """Инициализация баз данных."""
    # Инициализация базы данных для логов
    conn_logs = sqlite3.connect(LOGS_DB_NAME)
    cursor_logs = conn_logs.cursor()
    cursor_logs.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            router_ip TEXT,
            message TEXT
        )
    ''')
    conn_logs.commit()
    conn_logs.close()

    # Инициализация базы данных для настроек и пользователей
    conn_keeper = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor_keeper = conn_keeper.cursor()
    cursor_keeper.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
        )
    ''')
    cursor_keeper.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    # Добавление настроек по умолчанию
    default_settings = [
        ('log_retention_days', '30'),
        ('max_db_size_mb', '100'),
        ('allow_new_routers', 'true')
    ]
    for key, value in default_settings:
        cursor_keeper.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
    # Добавление администратора по умолчанию
    cursor_keeper.execute('SELECT * FROM users WHERE username = "admin"')
    admin_exists = cursor_keeper.fetchone()
    if not admin_exists:
        cursor_keeper.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('admin', 'admin1', 'admin'))
    conn_keeper.commit()
    conn_keeper.close()

def get_settings():
    """Получение всех настроек из базы данных logkeeper."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    settings = {key: value for key, value in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key, value):
    """Обновление настройки в базе данных logkeeper."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE settings SET value = ? WHERE key = ?', (value, key))
    conn.commit()
    conn.close()

def validate_user(username, password):
    """Проверка пользователя в базе данных logkeeper."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def insert_log(router_ip, message):
    """Добавление лога в базу данных logs."""
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO logs (router_ip, message) VALUES (?, ?)', (router_ip, message))
    conn.commit()
    conn.close()

def get_logs():
    """Получение всех логов из базы данных logs."""
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    conn.close()
    return logs