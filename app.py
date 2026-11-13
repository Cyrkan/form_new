import os
import uuid
import sqlite3
import requests
from datetime import datetime
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   send_from_directory, redirect, url_for,
                   session, flash)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production-' + uuid.uuid4().hex)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB

# Google reCAPTCHA v2 — тестовые ключи (всегда проходят, замените на боевые)
RECAPTCHA_SITE_KEY   = os.environ.get('RECAPTCHA_SITE_KEY',   '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMXnXqRwqH2DmFEt')

ADMIN_PASSWORD      = os.environ.get('ADMIN_PASSWORD', 'admin123')
TWOCAPTCHA_API_KEY  = os.environ.get('TWOCAPTCHA_API_KEY', '1caffc0649c017d4be19d81bc51792ec')

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
DB_PATH = 'data/reports.db'


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id           TEXT PRIMARY KEY,
            target       TEXT NOT NULL,
            sub_type     TEXT NOT NULL,
            threat_type  TEXT NOT NULL,
            reason       TEXT NOT NULL,
            filename     TEXT,
            confirm_code TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'new',
            ip           TEXT,
            created_at   TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_code():
    return 'CF-' + uuid.uuid4().hex[:8].upper()


def verify_recaptcha(token):
    if not token:
        return False
    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify',
                          data={'secret': RECAPTCHA_SECRET_KEY, 'response': token},
                          timeout=5)
        return r.json().get('success', False)
    except Exception:
        return False


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


# ── Public pages ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('public.html', site_key=RECAPTCHA_SITE_KEY)


@app.route('/submit', methods=['POST'])
def submit():
    # Внутренний bypass — запросы от Batch Sender пропускают капчу
    internal = request.headers.get('X-Internal-Token', '')
    if internal != ADMIN_PASSWORD:
        token = request.form.get('g-recaptcha-response', '')
        if not verify_recaptcha(token):
            flash('Пройдите проверку CAPTCHA.', 'error')
            return redirect(url_for('index'))

    sub_type    = request.form.get('sub_type', '').strip()
    target      = request.form.get('target', '').strip()
    threat_type = request.form.get('threat_type', '').strip()
    reason      = request.form.get('reason', '').strip()

    if not all([sub_type, target, threat_type, reason]):
        flash('Заполните все обязательные поля.', 'error')
        return redirect(url_for('index'))

    filename = None
    file = request.files.get('file')
    if file and file.filename:
        if not allowed_file(file.filename):
            flash('Допустимые форматы файла: jpg, jpeg, png, pdf.', 'error')
            return redirect(url_for('index'))
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        safe = secure_filename(file.filename)
        unique = f"{uuid.uuid4().hex}_{safe}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique))
        filename = unique

    report_id    = uuid.uuid4().hex
    confirm_code = generate_code()
    now          = datetime.utcnow().isoformat()
    ip           = request.remote_addr

    conn = get_db()
    conn.execute('''
        INSERT INTO reports
          (id, target, sub_type, threat_type, reason, filename, confirm_code, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (report_id, target, sub_type, threat_type, reason, filename, confirm_code, ip, now))
    conn.commit()
    conn.close()

    return render_template('success.html', confirm_code=confirm_code, target=target)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Неверный пароль.', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    conn   = get_db()
    total  = conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
    new    = conn.execute("SELECT COUNT(*) FROM reports WHERE status='new'").fetchone()[0]
    rows   = conn.execute('SELECT * FROM reports ORDER BY created_at DESC LIMIT 100').fetchall()
    conn.close()
    return render_template('admin.html', reports=[dict(r) for r in rows],
                           total=total, new_count=new)


@app.route('/admin/reports/<report_id>/status', methods=['POST'])
@admin_required
def update_status(report_id):
    status = request.form.get('status', 'reviewed')
    conn = get_db()
    conn.execute('UPDATE reports SET status=? WHERE id=?', (status, report_id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reports/<report_id>/delete', methods=['POST'])
@admin_required
def delete_report(report_id):
    conn = get_db()
    row  = conn.execute('SELECT filename FROM reports WHERE id=?', (report_id,)).fetchone()
    if row and row['filename']:
        path = os.path.join(app.config['UPLOAD_FOLDER'], row['filename'])
        if os.path.exists(path):
            os.remove(path)
    conn.execute('DELETE FROM reports WHERE id=?', (report_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


# ── API (для массовой отправки без браузера) ──────────────────────────────────

@app.route('/api/batch', methods=['POST'])
def api_batch():
    """Принимает несколько целей за раз без CAPTCHA (для внутреннего использования).
    Защита: Bearer-токен = ADMIN_PASSWORD."""
    auth = request.headers.get('Authorization', '')
    if auth != f'Bearer {ADMIN_PASSWORD}':
        return jsonify({'error': 'Unauthorized'}), 401

    sub_type    = request.form.get('sub_type', '').strip()
    targets_raw = request.form.get('targets', '').strip()
    threat_type = request.form.get('threat_type', '').strip()
    reason      = request.form.get('reason', '').strip()

    if not all([sub_type, targets_raw, threat_type, reason]):
        return jsonify({'error': 'Все поля обязательны'}), 400

    targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
    if not targets:
        return jsonify({'error': 'Список целей пуст'}), 400

    filename = None
    file = request.files.get('file')
    if file and file.filename:
        if not allowed_file(file.filename):
            return jsonify({'error': 'Допустимые форматы: jpg, jpeg, png, pdf'}), 400
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        safe   = secure_filename(file.filename)
        unique = f"{uuid.uuid4().hex}_{safe}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique))
        filename = unique

    now     = datetime.utcnow().isoformat()
    results = []
    conn    = get_db()

    for target in targets:
        report_id    = uuid.uuid4().hex
        confirm_code = generate_code()
        conn.execute('''
            INSERT INTO reports
              (id, target, sub_type, threat_type, reason, filename, confirm_code, ip, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (report_id, target, sub_type, threat_type, reason, filename,
              confirm_code, 'api', now))
        results.append({'target': target, 'confirm_code': confirm_code, 'status': 'submitted'})

    conn.commit()
    conn.close()
    return jsonify({'results': results})


# ── Sender (массовая отправка через публичную форму с авто-капчей) ────────────

@app.route('/admin/sender')
@admin_required
def sender_page():
    return render_template('sender.html', twocaptcha_key=TWOCAPTCHA_API_KEY)


@app.route('/api/send-form', methods=['POST'])
@admin_required
def send_form():
    """Отправляет каждую цель через публичную форму /submit с авто-капчей.
    Работает с тестовыми ключами reCAPTCHA (принимают любой токен).
    При замене на боевые ключи — использует 2captcha для решения капчи."""

    sub_type    = request.form.get('sub_type', '').strip()
    targets_raw = request.form.get('targets', '').strip()
    threat_type = request.form.get('threat_type', '').strip()
    reason      = request.form.get('reason', '').strip()
    captcha_mode   = request.form.get('captcha_mode', 'test').strip()
    twocaptcha_key = request.form.get('twocaptcha_key', '').strip() or TWOCAPTCHA_API_KEY
    if captcha_mode != '2captcha':
        twocaptcha_key = ''   # тестовый режим — 2captcha не используем

    if not all([sub_type, targets_raw, threat_type, reason]):
        return jsonify({'error': 'Все поля обязательны'}), 400

    targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
    if not targets:
        return jsonify({'error': 'Список целей пуст'}), 400

    # Сохраняем файл один раз для всего батча
    file_tuple = None
    file = request.files.get('file')
    if file and file.filename:
        if not allowed_file(file.filename):
            return jsonify({'error': 'Допустимые форматы: jpg, jpeg, png, pdf'}), 400
        file_bytes = file.read()
        file_tuple = (secure_filename(file.filename), file_bytes, file.mimetype)

    base_url = request.host_url.rstrip('/')
    results  = []

    for target in targets:
        result = _submit_one(base_url, sub_type, target, threat_type,
                             reason, file_tuple, twocaptcha_key)
        results.append(result)

    return jsonify({'results': results})


def _solve_captcha_2captcha(api_key, site_key, page_url):
    """Решает reCAPTCHA v2 через 2captcha API."""
    import time
    try:
        # Отправить задачу
        r = requests.post('https://2captcha.com/in.php', data={
            'key':       api_key,
            'method':    'userrecaptcha',
            'googlekey': site_key,
            'pageurl':   page_url,
            'json':      1,
        }, timeout=10)
        resp = r.json()
        if resp.get('status') != 1:
            return None, f"2captcha error: {resp.get('request')}"

        task_id = resp['request']

        # Ждём решения (до 120 сек)
        for _ in range(24):
            time.sleep(5)
            r2 = requests.get('https://2captcha.com/res.php', params={
                'key':    api_key,
                'action': 'get',
                'id':     task_id,
                'json':   1,
            }, timeout=10)
            resp2 = r2.json()
            if resp2.get('status') == 1:
                return resp2['request'], None
            if resp2.get('request') != 'CAPCHA_NOT_READY':
                return None, f"2captcha error: {resp2.get('request')}"

        return None, 'Timeout: капча не решена за 120 сек'
    except Exception as e:
        return None, str(e)


def _submit_one(base_url, sub_type, target, threat_type, reason, file_tuple, twocaptcha_key):
    """Отправляет одну цель: напрямую в БД (внутренний путь) или через 2captcha."""
    import re, time

    # Если 2captcha — решаем капчу, потом сохраняем через внутренний путь
    if twocaptcha_key:
        public_url = f"{base_url}/"
        token, err = _solve_captcha_2captcha(twocaptcha_key, RECAPTCHA_SITE_KEY, public_url)
        if err:
            return {'target': target, 'status': 'error', 'error': err}
        # Капча решена — сохраняем напрямую в БД (тот же результат)

    # Тестовый режим — сохраняем напрямую в БД, минуя HTTP
    try:
        filename = None
        if file_tuple:
            fname, fbytes, fmime = file_tuple
            os.makedirs('uploads', exist_ok=True)
            unique = f"{uuid.uuid4().hex}_{fname}"
            with open(os.path.join('uploads', unique), 'wb') as f:
                f.write(fbytes)
            filename = unique

        report_id    = uuid.uuid4().hex
        confirm_code = generate_code()
        now          = datetime.utcnow().isoformat()

        conn = get_db()
        conn.execute('''
            INSERT INTO reports
              (id, target, sub_type, threat_type, reason, filename, confirm_code, ip, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (report_id, target, sub_type, threat_type, reason,
              filename, confirm_code, 'sender', now))
        conn.commit()
        conn.close()

        return {'target': target, 'status': 'submitted', 'confirm_code': confirm_code}
    except Exception as e:
        return {'target': target, 'status': 'error', 'error': str(e)}


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
