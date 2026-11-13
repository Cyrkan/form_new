# Form Sender

Тулза для масової відправки заявок через форму `https://linkreclamatiogrwc.uk/`.

## Запуск через Docker Compose

Потрібні встановлені Docker і Docker Compose.

1. Створіть файл налаштувань:

```bash
cp .env.example .env
```

2. Відкрийте `.env` і вкажіть:

```env
TWOCAPTCHA_API_KEY=ваш_ключ_2captcha
ADMIN_PASSWORD=пароль_оператора
SECRET_KEY=довгий_випадковий_секрет
```

3. Запустіть однією командою:

```bash
docker compose up --build
```

4. Відкрийте в браузері:

<http://localhost:5000>

Для входу використовуйте пароль з `ADMIN_PASSWORD`.

## Запуск без Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a; . ./.env; set +a
python app.py
```

Після запуску відкрийте <http://localhost:5000>.

## Змінні середовища

- `FORM_URL` — URL зовнішньої форми;
- `TWOCAPTCHA_API_KEY` — API-ключ 2Captcha;
- `ADMIN_PASSWORD` — пароль оператора;
- `SECRET_KEY` — секрет Flask-сесії;
- `MAX_TARGETS` — максимальна кількість цілей за один запуск.

Не публікуйте файл `.env` і API-ключ 2Captcha у GitHub.
