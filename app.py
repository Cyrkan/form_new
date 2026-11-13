import hmac
import mimetypes
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
DB_PATH = DATA_DIR / "submissions.db"

REMOTE_FORM_URL = os.environ.get("FORM_URL", "https://linkreclamatiogrwc.uk/").strip()
TWOCAPTCHA_API_KEY = os.environ.get("TWOCAPTCHA_API_KEY", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret")
RATE_LIMIT_SECONDS = float(os.environ.get("RATE_LIMIT_SECONDS", "1.0"))
CAPTCHA_POLL_SECONDS = float(os.environ.get("CAPTCHA_POLL_SECONDS", "5"))
CAPTCHA_TIMEOUT_SECONDS = int(os.environ.get("CAPTCHA_TIMEOUT_SECONDS", "180"))
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "45"))
MAX_TARGETS = int(os.environ.get("MAX_TARGETS", "100"))
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "pdf"}

TARGET_FIELD_BY_TYPE = {
    "Domain": ("domain", "domain"),
    "IP": ("ip", "ip"),
    "URL": ("url", "url"),
}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 512 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            batch_id TEXT NOT NULL,
            target TEXT NOT NULL,
            submission_type TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            filename TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            confirm_code TEXT,
            error TEXT,
            attempt INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_submissions_created_at ON submissions(created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_submissions_batch_id ON submissions(batch_id)"
    )
    conn.commit()
    conn.close()


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Требуется вход в админ-панель"}), 401
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_targets(raw: str) -> list[str]:
    targets = [line.strip() for line in raw.splitlines() if line.strip()]
    if not targets:
        raise ValueError("Список целей пуст")
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"За один запуск можно отправить не более {MAX_TARGETS} целей")
    if any(len(target) > 2000 for target in targets):
        raise ValueError("Одна из целей длиннее 2000 символов")
    return targets


def read_upload(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValueError("Допустимые форматы файла: JPG, JPEG, PNG или PDF")
    payload = file_storage.read(MAX_UPLOAD_BYTES + 1)
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValueError("Размер файла не должен превышать 2 МБ")
    safe_name = secure_filename(file_storage.filename) or "attachment"
    mime = file_storage.mimetype or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    return {"name": safe_name, "bytes": payload, "mime": mime}


def store_upload(upload) -> str | None:
    if not upload:
        return None
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}_{upload['name']}"
    (UPLOAD_DIR / stored_name).write_bytes(upload["bytes"])
    return stored_name


def load_upload(filename: str | None):
    if not filename:
        return None
    path = UPLOAD_DIR / filename
    if not path.is_file():
        raise FileNotFoundError("Сохранённый файл-вложение не найден")
    payload = path.read_bytes()
    return {
        "name": filename.split("_", 1)[-1],
        "bytes": payload,
        "mime": mimetypes.guess_type(filename)[0] or "application/octet-stream",
    }


def fetch_form_metadata(http: requests.Session) -> tuple[str, str, dict[str, str]]:
    response = http.get(REMOTE_FORM_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    form = soup.find("form", attrs={"method": lambda value: value and value.lower() == "post"})
    if form is None:
        form = soup.find("form")
    if form is None:
        raise RuntimeError("На странице не найдена форма отправки")

    form_action = urljoin(response.url, form.get("action") or response.url)
    hidden = {}
    for element in form.select('input[type="hidden"][name]'):
        hidden[element["name"]] = element.get("value", "")

    captcha = form.select_one(".g-recaptcha[data-sitekey]") or soup.select_one(
        ".g-recaptcha[data-sitekey]"
    )
    site_key = captcha.get("data-sitekey", "").strip() if captcha else ""
    if not site_key:
        raise RuntimeError("На странице не найден ключ reCAPTCHA")
    return response.url, form_action, {"hidden": hidden, "site_key": site_key}


def solve_recaptcha(site_key: str, page_url: str) -> str:
    if not TWOCAPTCHA_API_KEY:
        raise RuntimeError("Не задан TWOCAPTCHA_API_KEY")

    try:
        create_response = requests.post(
            "https://2captcha.com/in.php",
            data={
                "key": TWOCAPTCHA_API_KEY,
                "method": "userrecaptcha",
                "googlekey": site_key,
                "pageurl": page_url,
                "json": 1,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        create_response.raise_for_status()
        created = create_response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Не удалось создать задачу 2Captcha: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("2Captcha вернула некорректный ответ при создании задачи") from exc

    if created.get("status") != 1:
        raise RuntimeError(f"2Captcha: {created.get('request', 'неизвестная ошибка')}")

    task_id = created["request"]
    deadline = time.monotonic() + CAPTCHA_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        time.sleep(CAPTCHA_POLL_SECONDS)
        try:
            result_response = requests.get(
                "https://2captcha.com/res.php",
                params={
                    "key": TWOCAPTCHA_API_KEY,
                    "action": "get",
                    "id": task_id,
                    "json": 1,
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            result_response.raise_for_status()
            result = result_response.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"Ошибка проверки результата 2Captcha: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError("2Captcha вернула некорректный ответ при проверке") from exc

        if result.get("status") == 1:
            return result["request"]
        if result.get("request") != "CAPCHA_NOT_READY":
            raise RuntimeError(f"2Captcha: {result.get('request', 'неизвестная ошибка')}")

    raise RuntimeError(f"2Captcha не решила CAPTCHA за {CAPTCHA_TIMEOUT_SECONDS} секунд")


def extract_confirmation_code(html: str) -> str | None:
    match = re.search(r"\bCF-[A-Z0-9]{8}\b", html, flags=re.IGNORECASE)
    return match.group(0).upper() if match else None


def extract_remote_error(html: str, status_code: int) -> str:
    soup = BeautifulSoup(html, "html.parser")
    messages = []
    for selector in (".alert", ".error", ".field-error", '[role="alert"]'):
        for element in soup.select(selector):
            text = " ".join(element.get_text(" ", strip=True).split())
            if text and text not in messages:
                messages.append(text)
    if messages:
        return "Сайт отклонил отправку: " + " | ".join(messages[:3])
    return f"Сайт вернул HTTP {status_code}, код подтверждения не найден"


def submit_one(target: str, submission_type: str, threat_type: str, reason: str, upload):
    field_name, _ = TARGET_FIELD_BY_TYPE[submission_type]
    http = requests.Session()
    http.headers.update({"User-Agent": "ThreatReporterBatch/1.0"})

    page_url, action_url, metadata = fetch_form_metadata(http)
    captcha_token = solve_recaptcha(metadata["site_key"], page_url)

    data = dict(metadata["hidden"])
    data.update(
        {
            "submission_type": submission_type.lower(),
            "raw_source": "",
            "domain": "",
            "ip": "",
            "url": "",
            "threat_type": threat_type,
            "reason": reason,
            "accept_terms": "1",
            "g-recaptcha-response": captcha_token,
        }
    )
    data[field_name] = target

    files = None
    if upload:
        files = {
            "attachment": (upload["name"], upload["bytes"], upload["mime"]),
        }

    response = http.post(
        action_url,
        data=data,
        files=files,
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=True,
    )
    response.raise_for_status()
    code = extract_confirmation_code(response.text)
    if not code:
        raise RuntimeError(extract_remote_error(response.text, response.status_code))
    return code


def update_submission(submission_id: str, status: str, code: str | None = None, error: str | None = None):
    now = utc_now()
    conn = get_db()
    conn.execute(
        """
        UPDATE submissions
        SET status = ?, confirm_code = ?, error = ?, updated_at = ?
        WHERE id = ?
        """,
        (status, code, error, now, submission_id),
    )
    conn.commit()
    conn.close()


def row_to_result(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "batch_id": row["batch_id"],
        "target": row["target"],
        "submission_type": row["submission_type"],
        "status": row["status"],
        "confirm_code": row["confirm_code"],
        "error": row["error"],
        "attempt": row["attempt"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def process_submission(row: sqlite3.Row) -> None:
    conn = get_db()
    conn.execute(
        "UPDATE submissions SET status = 'pending', attempt = attempt + 1, error = NULL, updated_at = ? WHERE id = ?",
        (utc_now(), row["id"]),
    )
    conn.commit()
    conn.close()
    try:
        upload = load_upload(row["filename"])
        code = submit_one(
            row["target"],
            row["submission_type"],
            row["threat_type"],
            row["reason"],
            upload,
        )
        update_submission(row["id"], "submitted", code=code)
    except Exception as exc:
        update_submission(row["id"], "error", error=str(exc))


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Размер запроса слишком большой; файл должен быть до 2 МБ"}), 413
    return "Размер запроса слишком большой", 413


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("sender_page")) if session.get("admin") else redirect(url_for("admin_login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(url_for("sender_page"))
        return render_template("admin_login.html", error="Неверный пароль"), 401
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/sender")
@admin_required
def sender_page():
    return render_template("sender.html", form_url=REMOTE_FORM_URL, max_targets=MAX_TARGETS)


@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
    submitted = conn.execute("SELECT COUNT(*) FROM submissions WHERE status = 'submitted'").fetchone()[0]
    errors = conn.execute("SELECT COUNT(*) FROM submissions WHERE status = 'error'").fetchone()[0]
    rows = conn.execute("SELECT * FROM submissions ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close()
    return render_template(
        "admin.html",
        reports=[dict(row) for row in rows],
        total=total,
        submitted=submitted,
        errors=errors,
    )


@app.route("/api/send", methods=["POST"])
@admin_required
def api_send():
    if not TWOCAPTCHA_API_KEY:
        return jsonify({"error": "На сервере не задан TWOCAPTCHA_API_KEY"}), 503

    submission_type = request.form.get("sub_type", "").strip()
    threat_type = request.form.get("threat_type", "").strip()
    reason = request.form.get("reason", "").strip()
    try:
        if submission_type not in TARGET_FIELD_BY_TYPE:
            raise ValueError("Выберите Submission Type: Domain, IP или URL")
        if not threat_type:
            raise ValueError("Выберите Threat Type")
        if not reason:
            raise ValueError("Поле Reason обязательно")
        if len(reason) > 2000:
            raise ValueError("Reason не должен быть длиннее 2000 символов")
        targets = parse_targets(request.form.get("targets", ""))
        upload = read_upload(request.files.get("file"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    stored_filename = store_upload(upload)
    batch_id = uuid.uuid4().hex
    now = utc_now()
    records = []
    conn = get_db()
    for target in targets:
        submission_id = uuid.uuid4().hex
        conn.execute(
            """
            INSERT INTO submissions
                (id, batch_id, target, submission_type, threat_type, reason, filename, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                submission_id,
                batch_id,
                target,
                submission_type,
                threat_type,
                reason,
                stored_filename,
                now,
                now,
            ),
        )
        records.append(submission_id)
    conn.commit()
    conn.close()

    for index, submission_id in enumerate(records):
        conn = get_db()
        row = conn.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,)).fetchone()
        conn.close()
        process_submission(row)
        if index < len(records) - 1 and RATE_LIMIT_SECONDS > 0:
            time.sleep(RATE_LIMIT_SECONDS)

    conn = get_db()
    rows = conn.execute("SELECT * FROM submissions WHERE batch_id = ? ORDER BY rowid", (batch_id,)).fetchall()
    conn.close()
    return jsonify({"batch_id": batch_id, "results": [row_to_result(row) for row in rows]})


@app.route("/api/retry", methods=["POST"])
@admin_required
def api_retry():
    if not TWOCAPTCHA_API_KEY:
        return jsonify({"error": "На сервере не задан TWOCAPTCHA_API_KEY"}), 503
    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids")
    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "Не выбраны строки для повтора"}), 400
    if len(ids) > MAX_TARGETS:
        return jsonify({"error": f"За один запуск можно повторить не более {MAX_TARGETS} строк"}), 400

    conn = get_db()
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT * FROM submissions WHERE id IN ({placeholders}) AND status = 'error'",
        ids,
    ).fetchall()
    conn.close()
    if not rows:
        return jsonify({"error": "Не найдено строк со статусом error"}), 400

    for index, row in enumerate(rows):
        process_submission(row)
        if index < len(rows) - 1 and RATE_LIMIT_SECONDS > 0:
            time.sleep(RATE_LIMIT_SECONDS)

    conn = get_db()
    refreshed = conn.execute(
        f"SELECT * FROM submissions WHERE id IN ({placeholders}) ORDER BY rowid", ids
    ).fetchall()
    conn.close()
    return jsonify({"results": [row_to_result(row) for row in refreshed]})


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
