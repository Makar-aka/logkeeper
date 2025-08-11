from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import db  # Импортируем модуль db

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
    conn = sqlite3.connect(db.DB_NAME)
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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.role != 'admin':
        return 'Access denied', 403

    if request.method == 'POST':
        # Обновление настроек
        for key, value in request.form.items():
            db.update_setting(key, value)

    # Получение текущих настроек
    settings = db.get_settings()
    return render_template('settings.html', settings=settings)

# Веб-интерфейс для просмотра логов
@app.route('/logs', methods=['GET'])
@login_required
def view_logs():
    conn = sqlite3.connect(db.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    conn.close()

    return jsonify(logs)

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

        conn = sqlite3.connect(db.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, 'admin'))
        conn.commit()
        conn.close()

        return 'Password updated successfully', 200

    return render_template('change_password.html')

# Инициализация базы данных
if __name__ == '__main__':
    db.init_db()
    app.run(host='0.0.0.0', port=5000)