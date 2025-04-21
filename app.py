from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.exceptions import HTTPException
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta
from flask_talisman import Talisman
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
import pyotp

# Настройка логирования
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Создание папки для логов
if not os.path.exists('logs'):
    os.makedirs('logs')

# Настройка вращения логов
file_handler = RotatingFileHandler('logs/app.log', maxBytes=1024*1024*100, backupCount=20)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Создание приложения
app = Flask(__name__, template_folder='templates', static_folder='static')

# Настройки приложения
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/'
app.config['MONGO_DBNAME'] = 'users_db'
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['CACHE_TYPE'] = 'simple'

# Инициализация расширений
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
Talisman(app)
cache = Cache(app)
csrf = CSRFProtect(app)

# Настройка лимитера
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute", "50 per second"]
)

# Секретный ключ для шифрования
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

# Маршрут для главной страницы
@app.route('/')
def home():
    return render_template('home.html')

# Маршрут для регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    try:
        data = request.json
        if not data:
            return jsonify({"message": "No data provided"}), 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({"message": "Please provide username, email and password"}), 400

        # Проверка на существование пользователя
        user = mongo.db.users.find_one({'username': username})
        if user:
            return jsonify({"message": "Username already exists"}), 400

        user = mongo.db.users.find_one({'email': email})
        if user:
            return jsonify({"message": "Email already exists"}), 400

        # Хэширование пароля
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Создание нового пользователя
        new_user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'active': True,
            'created_at': datetime.utcnow()
        }

        # Добавление пользователя в базу данных
        mongo.db.users.insert_one(new_user)

        return jsonify({"message": "User created successfully"}), 201

    except Exception as e:
        logger.error(f"Ошибка регистрации: {str(e)}")
        return jsonify({"message": "An error occurred during registration"}), 500

# Маршрут для авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        data = request.json
        if not data:
            return jsonify({"message": "No data provided"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Please provide username and password"}), 400

        # Поиск пользователя по username
        user = mongo.db.users.find_one({'username': username})

        if not user:
            return jsonify({"message": "Invalid credentials"}), 401

        # Проверка пароля
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({"message": "Invalid credentials"}), 401

        # Создание токена доступа
        access_token = create_access_token(identity=user['username'])

        return jsonify({
            "message": "Logged in successfully",
            "user": {
                "id": str(user['_id']),
                "username": user['username'],
                "email": user['email']
            },
            "token": access_token
        }), 200

    except Exception as e:
        logger.error(f"Ошибка авторизации: {str(e)}")
        return jsonify({"message": "An error occurred during login"}), 500

# Маршрут для выхода
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    try:
        # В этом случае мы просто возвращаем сообщение, так как JWT токен уже истечет через час
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        logger.error(f"Ошибка выхода: {str(e)}")
        return jsonify({"message": "An error occurred during logout"}), 500

# Маршрут для получения списка пользователей (только для авторизованных пользователей)
@app.route('/users', methods=['GET'])
@jwt_required
@cache.cached(query_string=True)
def get_users():
    try:
        # Текущий пользователь
        current_user_username = get_jwt_identity()

        # Получение всех пользователей
        users = mongo.db.users.find({'active': True}, {'password': 0})

        # Преобразование объектов в список словарей
        users_list = []
        for user in users:
            user['_id'] = str(user['_id'])
            users_list.append(user)

        return jsonify(users_list), 200
    except Exception as e:
        logger.error(f"Ошибка получения пользователей: {str(e)}")
        return jsonify({"message": "An error occurred while fetching users"}), 500

# Маршрут для обновления профиля
@app.route('/update-profile', methods=['PUT'])
@jwt_required
def update_profile():
    try:
        current_user_username = get_jwt_identity()
        user = mongo.db.users.find_one({'username': current_user_username})

        if not user:
            return jsonify({"message": "User not found"}), 404

        data = request.json
        if not data:
            return jsonify({"message": "No data provided"}), 400

        # Обновление данных пользователя
        update_data = {}
        if 'username' in data:
            update_data['username'] = data['username']
        if 'email' in data:
            update_data['email'] = data['email']

        # Проверка на существование нового username или email
        if 'username' in update_data:
            existing_user = mongo.db.users.find_one({'username': update_data['username']})
            if existing_user and existing_user['_id'] != user['_id']:
                return jsonify({"message": "Username already exists"}), 400

        if 'email' in update_data:
            existing_user = mongo.db.users.find_one({'email': update_data['email']})
            if existing_user and existing_user['_id'] != user['_id']:
                return jsonify({"message": "Email already exists"}), 400

        # Обновление данных в базе данных
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': update_data}
        )

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        logger.error(f"Ошибка обновления профиля: {str(e)}")
        return jsonify({"message": "An error occurred while updating profile"}), 500

# Маршрут для удаления пользователя
@app.route('/delete-user', methods=['DELETE'])
@jwt_required
def delete_user():
    try:
        current_user_username = get_jwt_identity()
        user = mongo.db.users.find_one({'username': current_user_username})

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Установка active в False
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'active': False}}
        )

        return jsonify({"message": "User deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Ошибка удаления пользователя: {str(e)}")
        return jsonify({"message": "An error occurred while deleting user"}), 500

# Маршрут для изменения пароля
@app.route('/change-password', methods=['PUT'])
@jwt_required
def change_password():
    try:
        current_user_username = get_jwt_identity()
        user = mongo.db.users.find_one({'username': current_user_username})

        if not user:
            return jsonify({"message": "User not found"}), 404

        data = request.json
        if not data:
            return jsonify({"message": "No data provided"}), 400

        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({"message": "Please provide current and new passwords"}), 400

        # Проверка текущего пароля
        if not bcrypt.check_password_hash(user['password'], current_password):
            return jsonify({"message": "Invalid current password"}), 401

        # Хэширование нового пароля
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Обновление пароля в базе данных
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password}}
        )

        return jsonify({"message": "Password changed successfully"}), 200

    except Exception as e:
        logger.error(f"Ошибка изменения пароля: {str(e)}")
        return jsonify({"message": "An error occurred while changing password"}), 500

# Маршрут для шифрования данных
@app.route('/encrypt-data', methods=['POST'])
def encrypt_data():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({"message": "No data provided"}), 400

        # Шифрование данных
        encrypted_data = cipher_suite.encrypt(data.encode('utf-8')).decode('utf-8')

        return jsonify({
            "message": "Data encrypted successfully",
            "encrypted_data": encrypted_data
        }), 200

    except Exception as e:
        logger.error(f"Ошибка шифрования данных: {str(e)}")
        return jsonify({"message": "An error occurred during data encryption"}), 500

# Маршрут для расшифровки данных
@app.route('/decrypt-data', methods=['POST'])
def decrypt_data():
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({"message": "No encrypted data provided"}), 400

        # Расшифровка данных
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

        return jsonify({
            "message": "Data decrypted successfully",
            "decrypted_data": decrypted_data
        }), 200

    except Exception as e:
        logger.error(f"Ошибка расшифровки данных: {str(e)}")
        return jsonify({"message": "An error occurred during data decryption"}), 500

# Маршрут для активации двухфакторной аутентификации
@app.route('/enable-2fa', methods=['POST'])
@jwt_required
def enable_2fa():
    try:
        current_user_username = get_jwt_identity()
        user = mongo.db.users.find_one({'username': current_user_username})

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Генерация секретного ключа для 2FA
        secret_key = os.urandom(16).hex()
        # Создание QR-кода
        qr_code = f"otpauth://totp/{current_user_username}:YourApp?secret={secret_key}&issuer=YourApp"

        # Сохранение секретного ключа в базе данных
        mongo.db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'secret_key_2fa': secret_key}}
        )

        return jsonify({
            "message": "2FA enabled successfully",
            "secret_key": secret_key,
            "qr_code": qr_code
        }), 200

    except Exception as e:
        logger.error(f"Ошибка активации 2FA: {str(e)}")
        return jsonify({"message": "An error occurred while enabling 2FA"}), 500

# Маршрут для верификации 2FA
@app.route('/verify-2fa', methods=['POST'])
@jwt_required
def verify_2fa():
    try:
        current_user_username = get_jwt_identity()
        user = mongo.db.users.find_one({'username': current_user_username})

        if not user or 'secret_key_2fa' not in user:
            return jsonify({"message": "2FA is not enabled for this user"}), 400

        secret_key = user['secret_key_2fa']
        provided_code = request.json.get('code')

        if not provided_code:
            return jsonify({"message": "Please provide the 2FA code"}), 400

        # Верификация кода
        totp = pyotp.TOTP(secret_key)
        if not totp.verify(provided_code):
            return jsonify({"message": "Invalid 2FA code"}), 401

        return jsonify({"message": "2FA code is valid"}), 200

    except Exception as e:
        logger.error(f"Ошибка верификации 2FA: {str(e)}")
        return jsonify({"message": "An error occurred while verifying 2FA"}), 500

# Маршрут для защищённой страницы
@app.route('/protected')
@jwt_required
def protected():
    try:
        current_user_username = get_jwt_identity()
        return render_template('protected.html', username=current_user_username)
    except Exception as e:
        logger.error(f"Ошибка доступа к защищённой странице: {str(e)}")
        return redirect(url_for('login'))

# Обработка ошибок
@app.errorhandler(HTTPException)
def handle_exception(e):
    response = {
        "error": {
            "type": e.name,
            "message": e.description,
            "code": e.code
        }
    }
    logger.error(f"Ошибка {e.code}: {e.description}")
    return jsonify(response), e.code

# Если __name__ == '__main__'
if __name__ == '__main__':
    # Создание таблицы в базе данных
    with app.app_context():
        # Создание индексов
        mongo.db.users.create_index('username', unique=True)
        mongo.db.users.create_index('email', unique=True)

    # Запуск приложения
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
