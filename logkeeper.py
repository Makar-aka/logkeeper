from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import db  # Импортируем модуль db
import socket
import threading
import logging
import sqlite3
import os  # Импортируем os для работы с файловой системой

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,  # Уровень логирования (INFO, DEBUG, ERROR и т.д.)
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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

@app.route('/admin/routers', methods=['GET', 'POST'])
@login_required
def manage_routers():
    if current_user.role != 'admin':
        return 'Access denied', 403

    if request.method == 'POST':
        # Получаем данные из формы
        pending_ip = request.form.get('pending_ip')
        device_id = request.form.get('device_id')
        model = request.form.get('model')
        description = request.form.get('description', '')

        # Если выбран IP из ожидающих, добавляем его в разрешенные
        if pending_ip:
            db.add_allowed_ip(pending_ip)
            device_id = pending_ip  # Используем IP как идентификатор устройства

        # Добавляем или обновляем настройки роутера
        if device_id and model:
            db.add_router_setting(device_id, model, description)

        # Удаляем IP из списка ожидающих, если он был выбран
        if pending_ip:
            db.remove_pending_ip(pending_ip)

    # Загрузка данных для отображения
    router_models = db.load_router_models()
    router_settings = db.get_router_settings()
    pending_ips = db.get_pending_ips()  # Получаем список ожидающих IP
    return render_template(
        'routers.html',
        router_settings=router_settings,
        router_models=router_models,
        pending_ips=pending_ips
    )

@app.route('/devices', methods=['GET'])
@login_required
def view_devices():
    # Подключение к базе данных logs
    conn_logs = sqlite3.connect(db.LOGS_DB_NAME)
    cursor_logs = conn_logs.cursor()
    cursor_logs.execute('SELECT DISTINCT device_id FROM logs ORDER BY device_id ASC')
    devices = cursor_logs.fetchall()
    conn_logs.close()

    # Подключение к базе данных routers для получения описаний
    conn_routers = sqlite3.connect(db.ROUTERS_DB_NAME)
    cursor_routers = conn_routers.cursor()
    cursor_routers.execute('SELECT identifier, description FROM router_settings')
    router_descriptions = {row[0]: row[1] for row in cursor_routers.fetchall()}
    conn_routers.close()

    # Объединяем данные
    devices_with_descriptions = [
        (device[0], router_descriptions.get(device[0], "Описание отсутствует"))
        for device in devices
    ]

    return render_template('devices.html', devices=devices_with_descriptions)
@app.route('/logs/<device_id>', methods=['GET'])
@login_required
def view_logs_by_device(device_id):
    # Получаем параметры из запроса
    page = int(request.args.get('page', 1))  # Текущая страница
    rows_per_page = int(request.args.get('rows_per_page', 10))  # Количество строк на странице

    # Подключение к базе данных
    conn = sqlite3.connect(db.LOGS_DB_NAME)
    cursor = conn.cursor()

    # Подсчет общего количества строк
    cursor.execute('SELECT COUNT(*) FROM logs WHERE device_id = ?', (device_id,))
    total_logs = cursor.fetchone()[0]

    # Вычисление количества страниц
    total_pages = (total_logs + rows_per_page - 1) // rows_per_page

    # Получение логов для текущей страницы
    offset = (page - 1) * rows_per_page
    cursor.execute('SELECT * FROM logs WHERE device_id = ? ORDER BY id DESC LIMIT ? OFFSET ?', (device_id, rows_per_page, offset))
    logs = cursor.fetchall()
    conn.close()

    # Передача данных в шаблон
    return render_template(
        'logs.html',
        logs=logs,
        device_id=device_id,
        page=page,
        rows_per_page=rows_per_page,
        total_pages=total_pages
    )

# Веб-интерфейс для просмотра логов
@app.route('/logs', methods=['GET'])
@login_required
def view_logs():
    logs = db.get_logs()
    return render_template('logs.html', logs=logs)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return 'Access denied', 403

    conn = sqlite3.connect(db.USERS_DB_NAME)
    cursor = conn.cursor()

    if request.method == 'POST':
        # Добавление нового пользователя
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if username and password and role:
            try:
                hashed_password = db.hash_password(password)  # Хэшируем пароль
                cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
                conn.commit()
            except sqlite3.IntegrityError:
                return 'Пользователь с таким именем уже существует', 400

    # Получение списка пользователей
    cursor.execute('SELECT id, username, role FROM users ORDER BY id ASC')
    users = cursor.fetchall()
    conn.close()

    return render_template('users.html', users=users)

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

@app.route('/statistics', methods=['GET'])
@login_required
def view_statistics():
    conn = sqlite3.connect(db.LOGS_DB_NAME)
    cursor = conn.cursor()

    # Размер базы данных
    db_size = os.path.getsize(db.LOGS_DB_NAME) / (1024 * 1024)  # Размер в МБ

    # Количество строк в таблице logs
    cursor.execute('SELECT COUNT(*) FROM logs')
    total_logs = cursor.fetchone()[0]

    # Количество уникальных устройств
    cursor.execute('SELECT COUNT(DISTINCT device_id) FROM logs')
    unique_devices = cursor.fetchone()[0]

    # Последний лог
    cursor.execute('SELECT MAX(id), log FROM logs')
    last_log = cursor.fetchone()

    # Логи за последние 24 часа
    cursor.execute('SELECT COUNT(*) FROM logs WHERE timestamp >= datetime("now", "-1 day")')
    logs_last_24h = cursor.fetchone()[0]

    # Самый активный IP
    cursor.execute('SELECT ip, COUNT(*) as count FROM logs GROUP BY ip ORDER BY count DESC LIMIT 1')
    most_active_ip = cursor.fetchone()

    # Самое активное устройство
    cursor.execute('SELECT device_id, COUNT(*) as count FROM logs GROUP BY device_id ORDER BY count DESC LIMIT 1')
    most_active_device = cursor.fetchone()

    conn.close()

    return render_template(
        'statistics.html',
        db_size=db_size,
        total_logs=total_logs,
        unique_devices=unique_devices,
        last_log=last_log,
        logs_last_24h=logs_last_24h,
        most_active_ip=most_active_ip,
        most_active_device=most_active_device
    )
@app.route('/admin/approve_ip', methods=['POST'])
@login_required
def approve_ip():
    if current_user.role != 'admin':
        return 'Access denied', 403

    pending_ip = request.form.get('pending_ip')
    model = request.form.get('model')

    if not pending_ip or not model:
        return 'Invalid data', 400

    # Добавляем IP в разрешенные
    db.add_allowed_ip(pending_ip)
    # Добавляем настройки роутера
    db.add_router_setting(pending_ip, model)
    # Удаляем IP из списка ожидающих
    db.remove_pending_ip(pending_ip)

    return redirect(url_for('manage_routers'))

@app.route('/admin/delete_router/<identifier>', methods=['POST'])
@login_required
def delete_router(identifier):
    if current_user.role != 'admin':
        return 'Access denied', 403

    db.delete_router_setting(identifier)  # Удаляем роутер из базы данных
    return redirect(url_for('manage_routers'))

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

def start_log_server(host='0.0.0.0', port=1514):  # Используем порт 1514 по умолчанию
    """Запуск сервера для приема логов."""
    def handle_logs():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        logging.info(f"Log server started on {host}:{port}")
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                message = data.decode('utf-8')
                client_ip = addr[0]

                # Проверяем, разрешен ли IP
                if not db.is_ip_allowed(client_ip):
                    logging.info(f"Received log from unapproved IP {client_ip}: {message}")
                    db.add_pending_ip(client_ip)  # Добавляем IP в список ожидающих одобрения
                    continue

                logging.info(f"Received log from {client_ip}: {message}")
                db.insert_log(client_ip, message, client_ip)  # Передаем IP как device_id
            except Exception as e:
                logging.error(f"Error while processing log: {e}")

    thread = threading.Thread(target=handle_logs, daemon=True)
    thread.start()

if __name__ == '__main__':
    db.init_db()
    start_log_server()
    app.run(host='0.0.0.0', port=5000)