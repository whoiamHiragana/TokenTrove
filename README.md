## 📖 Инструкция по использованию

### 📋 Требования

- Python 3.8+  
- MongoDB 4.0+  
- `virtualenv` (опционально)

### 🚀 Установка

1. Клонируйте репозиторий и перейдите в его папку:
   ```bash
   git clone https://github.com/ваш-ник/ваш-репозиторий.git
   cd ваш-репозиторий
   ```
2. Создайте виртуальное окружение и активируйте его:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Linux / macOS
   venv\Scripts\activate      # Windows
   ```
3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

### 🔧 Настройка

1. Создайте файл `.env` в корне проекта:
   ```dotenv
   # Flask
   FLASK_ENV=production      # или development, testing
   SECRET_KEY=ваш_секрет_для_FLASK
   JWT_SECRET_KEY=ваш_секрет_для_JWT

   # MongoDB
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DBNAME=users_db

   # Шифрование
   FERNET_KEY=ваш_Fernet_ключ

   # Порт
   FLASK_RUN_PORT=5000
   ```
2. При необходимости добавьте другие переменные окружения для кеша, лимитера и прочих расширений.

### ▶️ Запуск

```bash
# Через flask CLI
export FLASK_APP=app.py
flask run --host=0.0.0.0 --port=${FLASK_RUN_PORT}

# Или напрямую
python app.py
```

### 📡 Эндпоинты

Все запросы принимают и возвращают JSON, если не указано иное.

1. **Главная страница**  
   `GET /`  
   Отдаёт HTML‑шаблон `home.html`

2. **Регистрация**  
   `POST /register`  
   ```json
   {
     "username": "ivan",
     "email": "ivan@example.com",
     "password": "пароль"
   }
   ```  
   **Ответы:**  
   - `201 Created` — успешно  
   - `400 Bad Request` / `500 Internal Server Error`

3. **Авторизация**  
   `POST /login`  
   ```json
   {
     "username": "ivan",
     "password": "пароль"
   }
   ```  
   **Успешный ответ:**  
   ```json
   {
     "message": "Logged in successfully",
     "user": { "id": "...", "username": "ivan", "email": "ivan@example.com" },
     "token": "JWT_TOKEN"
   }
   ```

4. **Защищённые маршруты**  
   Все ниже требуют заголовок:
   ```
   Authorization: Bearer <JWT_TOKEN>
   ```
   - `GET /users` — список активных пользователей  
   - `POST /logout` — выход  
   - `PUT /update-profile` — обновление `username` и/или `email`  
   - `DELETE /delete-user` — деактивация аккаунта  
   - `PUT /change-password`  
     ```json
     {
       "current_password": "старый",
       "new_password": "новый"
     }
     ```
   - `POST /enable-2fa` — включение 2FA, возвращает `secret_key` и `qr_code`  
   - `POST /verify-2fa`  
     ```json
     { "code": "123456" }
     ```
   - `GET /protected` — защищённая страница `protected.html`

5. **Шифрование / Расшифровка**  
   - `POST /encrypt-data`  
     ```json
     { "data": "текст для шифрования" }
     ```
   - `POST /decrypt-data`  
     ```json
     { "encrypted_data": "<строка>" }
     ```

### 📝 Лицензия

MIT License

Copyright (c) 2025 whoiamHiragana

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
