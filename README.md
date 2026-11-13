# Form Sender

Локальная админ-панель для последовательной массовой отправки заявок через форму, указанную в `FORM_URL`.

Для каждой строки инструмент отдельно:

1. загружает страницу формы и получает актуальный `form_token`;
2. создаёт задачу reCAPTCHA v2 в 2Captcha и ждёт решение;
3. отправляет одну цель с нужным полем (`domain`, `ip` или `url`), reason, threat type, согласием с условиями и общим вложением;
4. извлекает код подтверждения формата `CF-XXXXXXXX`;
5. сохраняет статус, код или понятную причину ошибки.

## Быстрый запуск

```bash
cp .env.example .env
# откройте .env и укажите TWOCAPTCHA_API_KEY, ADMIN_PASSWORD и SECRET_KEY
docker compose up --build
```

Откройте <http://localhost:5000>. Пароль берётся из `ADMIN_PASSWORD`.

Без Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# задайте переменные окружения из .env
set -a; . ./.env; set +a
python app.py
```

## Переменные окружения

| Переменная | Назначение |
|---|---|
| `FORM_URL` | URL страницы формы, по умолчанию `https://linkreclamatiogrwc.uk/` |
| `TWOCAPTCHA_API_KEY` | API-ключ 2Captcha; хранить только в `.env`/секретах деплоя |
| `ADMIN_PASSWORD` | Пароль локальной админ-панели |
| `SECRET_KEY` | Секрет Flask-сессии |
| `RATE_LIMIT_SECONDS` | Пауза между строками, по умолчанию 1 секунда |
| `CAPTCHA_POLL_SECONDS` | Интервал проверки 2Captcha |
| `CAPTCHA_TIMEOUT_SECONDS` | Максимальное ожидание одного решения |
| `REQUEST_TIMEOUT_SECONDS` | Таймаут HTTP-запросов к форме и 2Captcha |
| `MAX_TARGETS` | Максимальное число строк за один запуск |

Данные сохраняются в `data/submissions.db`, вложения — в `uploads/`. Эти каталоги подключены как Docker volumes и исключены из Git.

## Интерфейс

- `/admin/sender` — ввод параметров, массовая отправка и результаты по каждой строке;
- `/admin` — история последних отправок;
- неудачные строки можно повторить отдельно или кнопкой «Повторить ошибки».

Обратите внимание: каждая CAPTCHA имеет одноразовый токен, поэтому при повторе создаётся новая задача 2Captcha. Не коммитьте `.env` и не публикуйте API-ключ.
