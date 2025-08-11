from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import db  # Импортируем модуль db
import socket
import threading

# Настройка Flask
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Flask-Login User class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = db.validate_user_by_id(user_id)
    if user:
        return User(id=user[0], username=user[1], role=user[2])
    return None

# Маршрут для входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.validate_user(username, password)
        if user:
            login_user(User(id=user[0], username=user[1], role=user[2]))
            return redirect(url_for('home'))
        return 'Invalid credentials', 401
    return render_template('login.html')

# Маршрут для выхода
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Главная страница
@app.route('/')
@login_required
def home():
    if current_user.role == 'admin':
        return redirect(url_for('admin_panel'))
    return redirect(url_for('user_panel'))

# Маршрут для админ-панели
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return 'Access denied', 403
    return render_template('admin.html')

# Маршрут для пользовательской панели
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
    logs = db.get_logs()
    return render_template('logs.html', logs=logs)

# Маршрут для изменения пароля
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if current_user.role != 'admin':
        return 'Access denied', 403

    if request.method == 'POST':
        new_password = request.form['new_password']
        if not new_password:
            return 'Password cannot be empty', 400

        db.update_user_password('admin', new_password)
        return 'Password updated successfully', 200

    return render_template('change_password.html')

# Маршрут для настроек
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.role != 'admin':
        return 'Access denied', 403

    if request.method == 'POST':
        old_port = int(db.get_settings().get('log_server_port', 1514))
        for key, value in request.form.items():
            db.update_setting(key, value)

        # Проверяем, изменился ли порт
        new_port = int(db.get_settings().get('log_server_port', 1514))
        if old_port != new_port:
            print(f"Port changed from {old_port} to {new_port}. Restarting log server...")
            start_log_server()  # Перезапускаем сервер логов

    settings = db.get_settings()
    return render_template('settings.html', settings=settings)

# Функция для приема логов
def start_log_server(host='0.0.0.0'):
    """Запуск сервера для приема логов."""
    # Получаем порт из настроек
    port = int(db.get_settings().get('log_server_port', 1514))  # Значение по умолчанию — 1514

    def handle_logs():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        print(f"Log server started on {host}:{port}")
        while True:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8')
            print(f"Received log from {addr}: {message}")
            db.insert_log(addr[0], message)

    thread = threading.Thread(target=handle_logs, daemon=True)
    thread.start()
# Запуск сервера логов при старте приложения
if __name__ == '__main__':
    db.init_db()
    start_log_server()
    app.run(host='0.0.0.0', port=5000)