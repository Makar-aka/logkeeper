import os
import sqlite3
import json
import re
import hashlib  # Для хэширования паролей

LOGS_DB_NAME = "logs.db"
USERS_DB_NAME = "users.db"
ROUTERS_DB_NAME = "routers.db"
ROUTER_MODELS_FILE = "router_models.json"

def hash_password(password):
    """Хэширование пароля с использованием SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

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

    # Создаем базу данных для пользователей
    if not os.path.exists(USERS_DB_NAME):
        print(f"База данных {USERS_DB_NAME} отсутствует. Создаем новую...")
    conn_users = sqlite3.connect(USERS_DB_NAME)
    cursor_users = conn_users.cursor()
    cursor_users.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
        )
    ''')
    # Проверяем, есть ли пользователи в таблице
    cursor_users.execute('SELECT COUNT(*) FROM users')
    if cursor_users.fetchone()[0] == 0:
        # Добавляем пользователя admin с паролем admin1
        hashed_password = hash_password("admin1")
        cursor_users.execute('''
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        ''', ("admin", hashed_password, "admin"))
        print("Пользователь admin добавлен с паролем admin1")
    conn_users.commit()
    conn_users.close()

    # Создаем базу данных для роутеров
    if not os.path.exists(ROUTERS_DB_NAME):
        print(f"База данных {ROUTERS_DB_NAME} отсутствует. Создаем новую...")
    conn_routers = sqlite3.connect(ROUTERS_DB_NAME)
    cursor_routers = conn_routers.cursor()
    cursor_routers.execute('''
        CREATE TABLE IF NOT EXISTS router_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT UNIQUE NOT NULL,
            model TEXT NOT NULL,
            description TEXT
        )
    ''')
    cursor_routers.execute('''
        CREATE TABLE IF NOT EXISTS allowed_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    ''')
    cursor_routers.execute('''
        CREATE TABLE IF NOT EXISTS pending_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    ''')
    conn_routers.commit()
    conn_routers.close()

def validate_user_by_id(user_id):
    """Проверка пользователя в базе данных users по ID."""
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def validate_user(username, password):
    """Проверка пользователя в базе данных users."""
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def update_user_password(username, new_password):
    """Обновление пароля пользователя в базе данных users."""
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
    conn.commit()
    conn.close()

def add_router_setting(identifier, model, description=None):
    """Добавление настройки для роутера."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO router_settings (identifier, model, description) VALUES (?, ?, ?)',
                   (identifier, model, description))
    conn.commit()
    conn.close()

def get_router_settings():
    """Получение всех настроек роутеров."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM router_settings')
    settings = cursor.fetchall()
    conn.close()
    return settings

def update_router_setting(identifier, model, description=None):
    """Обновление настройки для роутера."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE router_settings SET model = ?, description = ? WHERE identifier = ?',
                   (model, description, identifier))
    conn.commit()
    conn.close()

def delete_router_setting(identifier):
    """Удаление настройки роутера по идентификатору и добавление его IP в список ожидающих."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()

    # Получаем IP роутера перед удалением
    cursor.execute('SELECT identifier FROM router_settings WHERE identifier = ?', (identifier,))
    result = cursor.fetchone()
    if result:
        ip = result[0]
        # Добавляем IP в список ожидающих
        add_pending_ip(ip)

    # Удаляем роутер из настроек
    cursor.execute('DELETE FROM router_settings WHERE identifier = ?', (identifier,))
    conn.commit()
    conn.close()

def is_ip_allowed(ip):
    """Проверяет, разрешен ли IP."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM allowed_ips WHERE ip = ?', (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_allowed_ip(ip):
    """Добавляет IP в список разрешенных."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO allowed_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def add_pending_ip(ip):
    """Добавляет IP в список ожидающих."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO pending_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def get_pending_ips():
    """Возвращает список ожидающих IP."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM pending_ips')
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ips

def remove_pending_ip(ip):
    """Удаляет IP из списка ожидающих."""
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pending_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

def load_router_models():
    """Загрузка настроек моделей роутеров из файла."""
    if not os.path.exists(ROUTER_MODELS_FILE):
        print(f"Файл {ROUTER_MODELS_FILE} не найден. Используются настройки по умолчанию.")
        return {}
    with open(ROUTER_MODELS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)

def parse_log_message(log_message, model=None):
    """Парсер логов с поддержкой моделей."""
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
    except Exception:
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