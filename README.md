# Form Sender

Це невелика програма для масової відправки заявок через форму:

<https://linkreclamatiogrwc.uk/>

## Як запустити через Docker

Потрібно, щоб на комп’ютері були встановлені Docker і Docker Compose.

Спочатку створіть файл налаштувань:

```bash
cp .env.example .env
```

Відкрийте `.env` і додайте свої значення:

```env
TWOCAPTCHA_API_KEY=ваш_ключ_2captcha
ADMIN_PASSWORD=пароль_для_входу
SECRET_KEY=будь-який_довгий_секрет
```

Після цього запустіть програму однією командою:

```bash
docker compose up --build
```

Відкрийте в браузері:

<http://localhost:5000>

Для входу використовуйте пароль, який вказали в `ADMIN_PASSWORD`.

## Як запустити без Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a
source .env
set +a
python app.py
```

Потім відкрийте <http://localhost:5000>.

## Важливо

- не залишайте порожнім `TWOCAPTCHA_API_KEY`, якщо потрібно відправляти заявки;
- не додавайте файл `.env` у GitHub;
- не показуйте API-ключ 2Captcha іншим людям.
