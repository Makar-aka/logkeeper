import os
import sqlite3
import json
import re

LOGS_DB_NAME = "logs.db"
LOGKEEPER_DB_NAME = "logkeeper.db"
ROUTER_MODELS_FILE = "router_models.json"

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
            device_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
    cursor_keeper.execute('''
        CREATE TABLE IF NOT EXISTS router_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT UNIQUE NOT NULL,
            model TEXT NOT NULL,
            description TEXT
        )
    ''')
    # Таблица для разрешенных IP
    cursor_keeper.execute('''
        CREATE TABLE IF NOT EXISTS allowed_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    ''')
    # Таблица для ожидающих IP
    cursor_keeper.execute('''
        CREATE TABLE IF NOT EXISTS pending_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    ''')
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

def load_router_models():
    """Загрузка настроек моделей роутеров из файла."""
    if not os.path.exists(ROUTER_MODELS_FILE):
        print(f"Файл {ROUTER_MODELS_FILE} не найден. Используются настройки по умолчанию.")
        return {}
    with open(ROUTER_MODELS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)

def parse_log_message(log_message, model=None):
    """Парсер логов с поддержкой моделей."""
    if model is None:
        model = get_settings().get("default_router_model")  # Получаем модель из настроек
    router_models = load_router_models()
    model_settings = router_models.get(model, {})
    log_format = model_settings.get("log_format")
    prefix_as_device_id = model_settings.get("prefix_as_device_id", False)

    try:
        match = re.match(log_format, log_message)
        if match:
            if prefix_as_device_id:
                timestamp, prefix, message = match.groups()
                device_id = prefix
            else:
                timestamp, device_id, message = match.groups()
            return timestamp, device_id, message
        else:
            return None, "Unknown", log_message
    except Exception as e:
        return None, "Unknown", log_message

def insert_log(ip, log, model=None):
    """Добавление лога в базу данных logs."""
    timestamp, device_id, message = parse_log_message(log, model)  # Парсим лог
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO logs (ip, log, device_id, timestamp) VALUES (?, ?, ?, ?)', (ip, message, device_id, timestamp))
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

def add_router_setting(identifier, model, description=None):
    """Добавление настройки для роутера."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO router_settings (identifier, model, description) VALUES (?, ?, ?)',
                   (identifier, model, description))
    conn.commit()
    conn.close()

def get_router_settings():
    """Получение всех настроек роутеров."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM router_settings')
    settings = cursor.fetchall()
    conn.close()
    return settings

def update_router_setting(identifier, model, description=None):
    """Обновление настройки для роутера."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE router_settings SET model = ?, description = ? WHERE identifier = ?',
                   (model, description, identifier))
    conn.commit()
    conn.close()

def get_router_model_by_identifier(identifier):
    """Получение модели роутера по идентификатору."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT model FROM router_settings WHERE identifier = ?', (identifier,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def is_ip_allowed(ip):
    """Проверяет, разрешен ли IP."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM allowed_ips WHERE ip = ?', (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_allowed_ip(ip):
    """Добавляет IP в список разрешенных."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO allowed_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def add_pending_ip(ip):
    """Добавляет IP в список ожидающих."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO pending_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def get_pending_ips():
    """Возвращает список ожидающих IP."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM pending_ips')
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ips

def remove_pending_ip(ip):
    """Удаляет IP из списка ожидающих."""
    conn = sqlite3.connect(LOGKEEPER_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pending_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()