import os
import sqlite3
import json
import hashlib  # Для хэширования паролей

# Имена баз данных
LOGS_DB_NAME = "logs.db"
USERS_DB_NAME = "users.db"
ROUTERS_DB_NAME = "routers.db"
ROUTER_MODELS_FILE = "router_models.json"

# Хэширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Инициализация баз данных
def init_db():
    # Логи
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

    # Пользователи
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
    cursor_users.execute('SELECT COUNT(*) FROM users')
    if cursor_users.fetchone()[0] == 0:
        hashed_password = hash_password("admin1")
        cursor_users.execute('''
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        ''', ("admin", hashed_password, "admin"))
        print("Пользователь admin добавлен с паролем admin1")
    conn_users.commit()
    conn_users.close()

    # Роутеры
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
    cursor_routers.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    cursor_routers.execute('SELECT COUNT(*) FROM settings WHERE key = "log_server_port"')
    if cursor_routers.fetchone()[0] == 0:
        cursor_routers.execute('''
            INSERT INTO settings (key, value) VALUES ('log_server_port', '1514')
        ''')
        print("Добавлена настройка log_server_port со значением 1514")
    cursor_routers.execute('SELECT COUNT(*) FROM settings WHERE key = "web_port"')
    if cursor_routers.fetchone()[0] == 0:
        cursor_routers.execute('''
            INSERT INTO settings (key, value) VALUES ('web_port', '5000')
        ''')
        print("Добавлена настройка web_port со значением 5000")
    conn_routers.commit()
    conn_routers.close()

# Работа с настройками
def get_settings():
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    settings = {key: value for key, value in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key, value):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE settings SET value = ? WHERE key = ?', (value, key))
    conn.commit()
    conn.close()

# Работа с пользователями
def validate_user_by_id(user_id):
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def validate_user(username, password):
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    return user

def update_user_password(username, new_password):
    conn = sqlite3.connect(USERS_DB_NAME)
    cursor = conn.cursor()
    hashed_password = hash_password(new_password)
    cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
    conn.commit()
    conn.close()

# Работа с роутерами
def add_router_setting(identifier, model, description=None):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO router_settings (identifier, model, description) VALUES (?, ?, ?)',
                   (identifier, model, description))
    conn.commit()
    conn.close()

def get_router_settings():
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM router_settings')
    settings = cursor.fetchall()
    conn.close()
    return settings

def update_router_setting(identifier, model, description=None):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE router_settings SET model = ?, description = ? WHERE identifier = ?',
                   (model, description, identifier))
    conn.commit()
    conn.close()

def delete_router_setting(identifier):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT identifier FROM router_settings WHERE identifier = ?', (identifier,))
    result = cursor.fetchone()
    if result:
        ip = result[0]
        add_pending_ip(ip)
    cursor.execute('DELETE FROM router_settings WHERE identifier = ?', (identifier,))
    conn.commit()
    conn.close()

# Работа с IP
def is_ip_allowed(ip):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM allowed_ips WHERE ip = ?', (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_allowed_ip(ip):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO allowed_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def add_pending_ip(ip):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO pending_ips (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()

def get_pending_ips():
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM pending_ips')
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ips

def remove_pending_ip(ip):
    conn = sqlite3.connect(ROUTERS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pending_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

# Работа с логами
def insert_log(ip, log, device_id):
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO logs (ip, log, device_id, timestamp) VALUES (?, ?, ?, datetime("now"))', (ip, log, device_id))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(LOGS_DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC')
    logs = cursor.fetchall()
    conn.close()
    return logs

# Загрузка моделей роутеров
def load_router_models():
    if not os.path.exists(ROUTER_MODELS_FILE):
        print(f"Файл {ROUTER_MODELS_FILE} не найден. Используются настройки по умолчанию.")
        return {}
    with open(ROUTER_MODELS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)