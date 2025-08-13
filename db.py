import os
import sqlite3

LOGS_DB_NAME = "logs.db"
LOGKEEPER_DB_NAME = "logkeeper.db"

def init_db():
    """Инициализация баз данных."""
    # Проверяем и создаем базу данных для логов, если она отсутствует
    if not os.path.exists(LOGS_DB_NAME):
        print(f"База данных {LOGS_DB_NAME} отсутствует. Создаем новую...")
    conn_logs = sqlite3.connect(LOGS_DB_NAME)
    cursor_logs = conn_logs.cursor()
    cursor_logs.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            log TEXT,
            device_id TEXT
        )
    ''')
    conn_logs.commit()
    conn_logs.close()

    # Проверяем и создаем базу данных для настроек и пользователей, если она отсутствует
    if not os.path.exists(LOGKEEPER_DB_NAME):
        print(f"База данных {LOGKEEPER_DB_NAME} отсутствует. Создаем новую...")
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
        ('allow_new_routers', 'true'),
        ('log_server_port', '1514')  # Добавляем настройку порта
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

def validate_user_by_id(user_id):
    """Проверка пользователя в базе данных logkeeper по ID."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def validate_user(username, password):
    """Проверка пользователя в базе данных logkeeper."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def extract_device_id(log_message):
    """Извлечение ID устройства из сообщения."""
    try:
        parts = log_message.split(' ')
        return parts[3]  # ID устройства находится в четвертой части сообщения
    except IndexError:
        return "Unknown"

def insert_log(ip, log):
    """Добавление лога в базу данных logs."""
    device_id = extract_device_id(log)  # Извлекаем ID устройства
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO logs (ip, log, device_id) VALUES (?, ?, ?)', (ip, log, device_id))
    conn.commit()
    conn.close()

def get_logs():
    """Получение всех логов из базы данных logs."""
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC')
    logs = cursor.fetchall()
    conn.close()
    return logs

def update_user_password(username, new_password):
    """Обновление пароля пользователя в базе данных logkeeper."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
    conn.commit()
    conn.close()