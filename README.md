# Form Sender

Програма для масової відправки заявок через форму `linkreclamatiogrwc.uk`.

## Запуск

Потрібні Docker і Docker Compose.

1. У папці проєкту виконайте `cp .env.example .env`.
2. Відкрийте `.env` і вкажіть `TWOCAPTCHA_API_KEY`, `ADMIN_PASSWORD` та `SECRET_KEY`.
3. Запустіть програму командою `docker compose up --build`.
4. Відкрийте в браузері [http://localhost:5000](http://localhost:5000).

Пароль для входу береться з `ADMIN_PASSWORD`.

## Запуск без Docker

Створіть віртуальне середовище, встановіть залежності з `requirements.txt`, завантажте змінні з `.env` і запустіть `python app.py`.

Після запуску відкрийте [http://localhost:5000](http://localhost:5000).
