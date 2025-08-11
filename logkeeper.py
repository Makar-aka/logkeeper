from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3

# Настройка Flask
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

# Flask-Login User class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], role=user[2])
    return None

# Маршрут для входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            login_user(User(id=user[0], username=user[1], role=user[2]))
            return redirect(url_for('view_logs'))
        return 'Invalid credentials', 401
    return render_template('login.html')

# Маршрут для выхода
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Пример маршрута с ограничением по роли
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return 'Access denied', 403
    return 'Welcome to the admin panel'

@app.route('/user')
@login_required
def user_panel():
    if current_user.role != 'user':
        return 'Access denied', 403
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