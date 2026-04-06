import os
import sqlite3
import base64
import secrets
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import anthropic

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

UPLOAD_FOLDER = Path('uploads')
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
MIME_TYPES = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'webp': 'image/webp',
}

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

DATABASE = 'mushrooms.db'
INITIAL_TOKENS = 3


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    UNIQUE NOT NULL,
                email        TEXT    UNIQUE NOT NULL,
                password_hash TEXT   NOT NULL,
                tokens       INTEGER DEFAULT 3,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id        INTEGER NOT NULL,
                image_filename TEXT    NOT NULL,
                result         TEXT    NOT NULL,
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if 'user_id' not in session:
        return None
    with get_db() as db:
        return db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html', user=get_current_user())


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('account'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        error = None
        if not username or len(username) < 3:
            error = 'Username must be at least 3 characters.'
        elif not email or '@' not in email:
            error = 'Please enter a valid email address.'
        elif not password or len(password) < 6:
            error = 'Password must be at least 6 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'

        if error is None:
            try:
                with get_db() as db:
                    db.execute(
                        'INSERT INTO users (username, email, password_hash, tokens) VALUES (?, ?, ?, ?)',
                        (username, email, generate_password_hash(password), INITIAL_TOKENS),
                    )
                    db.commit()
                flash(f'Account created! You start with {INITIAL_TOKENS} free tokens.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username or email is already taken.'

        flash(error, 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('account'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('account'))

        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/account')
@login_required
def account():
    with get_db() as db:
        user     = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        analyses = db.execute(
            'SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
            (session['user_id'],),
        ).fetchall()
    return render_template('account.html', user=user, analyses=analyses)


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    user   = get_current_user()
    result = None
    image_filename = None

    if request.method == 'POST':
        # Token check
        if user['tokens'] < 1:
            flash('You have no tokens left. Please purchase more to continue.', 'danger')
            return render_template('analyze.html', user=user, result=None)

        # File validation
        if 'photo' not in request.files or request.files['photo'].filename == '':
            flash('Please select a photo to upload.', 'danger')
            return render_template('analyze.html', user=user, result=None)

        file = request.files['photo']
        if not allowed_file(file.filename):
            flash('Unsupported file type. Please upload a JPG, PNG, or WebP image.', 'danger')
            return render_template('analyze.html', user=user, result=None)

        # Save file securely
        ext      = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{secrets.token_hex(10)}.{ext}")
        filepath = UPLOAD_FOLDER / filename
        file.save(str(filepath))

        media_type = MIME_TYPES.get(ext, 'image/jpeg')

        # Encode for API
        with open(str(filepath), 'rb') as f:
            image_data = base64.standard_b64encode(f.read()).decode('utf-8')

        # Claude API call
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            flash('AI service is not configured. Contact the administrator.', 'danger')
            return render_template('analyze.html', user=user, result=None)

        try:
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model='claude-opus-4-6',
                max_tokens=1024,
                messages=[{
                    'role': 'user',
                    'content': [
                        {
                            'type': 'image',
                            'source': {
                                'type': 'base64',
                                'media_type': media_type,
                                'data': image_data,
                            },
                        },
                        {
                            'type': 'text',
                            'text': (
                                'You are an expert mycologist. Analyze this mushroom photo and provide:\n\n'
                                '1. **Identification** – Common name and scientific name (or closest match).\n'
                                '2. **Key Features** – Visible characteristics: cap shape/color, gill structure, '
                                'stem, texture, any distinctive markings.\n'
                                '3. **Edibility** – Edible, toxic, or unknown/uncertain.\n'
                                '4. **Safety Warning** – Clear safety guidance for this species.\n'
                                '5. **Confidence Level** – Low / Medium / High, with a brief reason.\n\n'
                                '⚠️ Always end with: "This AI identification is for educational purposes only. '
                                'Never consume a wild mushroom based solely on AI identification. '
                                'Consult a qualified mycologist before eating any wild mushroom."'
                            ),
                        },
                    ],
                }],
            )
            result = response.content[0].text
            image_filename = filename

            # Deduct token, save analysis
            with get_db() as db:
                db.execute('UPDATE users SET tokens = tokens - 1 WHERE id = ?', (session['user_id'],))
                db.execute(
                    'INSERT INTO analyses (user_id, image_filename, result) VALUES (?, ?, ?)',
                    (session['user_id'], filename, result),
                )
                db.commit()

            flash('Analysis complete — 1 token used.', 'success')
            user = get_current_user()  # refresh token count

        except anthropic.APIError as e:
            flash(f'AI analysis failed: {e}', 'danger')

    return render_template('analyze.html', user=user, result=result, image_filename=image_filename)


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Only serve files that belong to the current user
    with get_db() as db:
        row = db.execute(
            'SELECT id FROM analyses WHERE image_filename = ? AND user_id = ?',
            (filename, session['user_id']),
        ).fetchone()
    if not row:
        return 'Not found', 404
    return send_from_directory(str(UPLOAD_FOLDER), filename)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
