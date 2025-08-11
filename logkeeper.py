from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_simplelogin import SimpleLogin, login_required
import sqlite3

# Настройка Flask
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Настройка базы данных SQLite
DB_NAME = "logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            router_ip TEXT,
            message TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Функция проверки пользователя
def validate_login(user):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT username, password, role FROM users WHERE username = ? AND password = ?', (user['username'], user['password']))
    db_user = cursor.fetchone()
    conn.close()
    if db_user:
        return True
    return False

# Инициализация Flask-SimpleLogin
SimpleLogin(app, login_checker=validate_login)

# Маршрут для админ-панели
@app.route('/admin')
@login_required(username='admin')
def admin_panel():
    return render_template('admin.html')

# Маршрут для пользовательской панели
@app.route('/user')
@login_required(username='user')
def user_panel():
    return render_template('user.html')

# Веб-интерфейс для просмотра логов
@app.route('/logs', methods=['GET'])
@login_required
def view_logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    conn.close()

    return jsonify(logs)

# Инициализация базы данных
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)