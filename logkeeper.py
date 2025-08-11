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
    # Создание таблицы логов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            router_ip TEXT,
            message TEXT
        )
    ''')
    # Создание таблицы пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL
        )
    ''')
    # Проверка, существует ли администратор
    cursor.execute('SELECT * FROM users WHERE username = "admin"')
    admin_exists = cursor.fetchone()
    if not admin_exists:
        # Добавление администратора с паролем по умолчанию
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('admin', 'admin1', 'admin'))
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

@app.route('/')
@login_required
def home():
    # Перенаправление в зависимости от роли пользователя
    if current_user.get('role') == 'admin':
        return redirect(url_for('admin_panel'))
    return redirect(url_for('user_panel'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_login({'username': username, 'password': password}):
            return redirect(url_for('home'))
        return 'Invalid credentials', 401
    return render_template('login.html')
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


@app.route('/change_password', methods=['GET', 'POST'])
@login_required(username='admin')
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        if not new_password:
            return 'Password cannot be empty', 400

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, 'admin'))
        conn.commit()
        conn.close()

        return 'Password updated successfully', 200

    return render_template('change_password.html')


# Инициализация базы данных
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)