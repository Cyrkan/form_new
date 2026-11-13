# Threat Reporter

Веб-инструмент для массовой подачи репортов об угрозах (домены, IP, URL).

## Возможности

- Submission Type: Domain / IP / URL
- Массовая отправка: несколько целей за раз (по одной на строку)
- Threat Type: Phishing, Malware, Spam, Botnet, Ransomware, Scam, C2, Other
- Прикладывание файла-доказательства (jpg, jpeg, png, pdf, до 2 МБ)
- Результат по каждой строке: статус + код подтверждения (CF-XXXXXXXX)
- Повторная отправка для строк с ошибкой
- Фильтр и поиск по результатам
- Данные хранятся в SQLite (файл `data/reports.db`)

---

## Запуск — Docker Compose (рекомендуется)

```bash
docker compose up --build
```

Откройте браузер: **http://localhost:5000**

Для фонового запуска:

```bash
docker compose up --build -d
```

Остановка:

```bash
docker compose down
```

---

## Запуск — Python (без Docker)

Требуется Python 3.10+.

```bash
cd threat-reporter
pip install -r requirements.txt
python app.py
```

Откройте браузер: **http://localhost:5000**

---

## Структура файлов

```
threat-reporter/
├── app.py               # Flask-приложение (API + инициализация БД)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── templates/
│   └── index.html       # Веб-интерфейс (SPA на ванильном JS)
├── uploads/             # Загруженные файлы (создаётся автоматически)
└── data/
    └── reports.db       # SQLite-база (создаётся автоматически)
```

---

## API (для интеграций)

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/submit` | Отправить batch (multipart/form-data) |
| `GET` | `/api/reports` | Список всех репортов |
| `POST` | `/api/reports/:id/retry` | Повторить отправку |
| `DELETE` | `/api/reports/:id` | Удалить репорт |

### POST /api/submit — поля формы

| Поле | Тип | Описание |
|------|-----|----------|
| `sub_type` | string | `Domain` / `IP` / `URL` |
| `targets` | string | Цели, по одной на строку |
| `threat_type` | string | Тип угрозы |
| `reason` | string | Описание |
| `file` | file | Опционально: jpg/jpeg/png/pdf ≤ 2 МБ |
