"""
InsecureHub - A Deliberately Vulnerable Flask Web Application
=============================================================
FOR EDUCATIONAL PURPOSES ONLY. DO NOT DEPLOY IN PRODUCTION.

Vulnerabilities included:
  [1] IDOR   - Insecure Direct Object Reference (profile/file access)
  [2] SSTI   - Server-Side Template Injection (custom bio renderer)
  [3] SSRF   - Server-Side Request Forgery (URL fetcher feature)
  [4] Pickle - Deserialization RCE (remember-me cookie)
  [5] SQLi   - SQL Injection (search feature)
  [6] Broken Auth - Weak session / password reset token
  [7] Path Traversal - File download endpoint
  [8] XSS    - Stored XSS in posts/comments
"""

import os
import sqlite3
import pickle
import base64
import hashlib
import requests
import urllib.parse
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, render_template_string,
    request, redirect, url_for, session, flash,
    send_file, jsonify, g
)

# ─────────────────────────────────────────────
#  App Config
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "supersecretkey123"          # VULN: Hardcoded weak secret
DATABASE = "insecurehub.db"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────
#  Database helpers
# ─────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                bio TEXT DEFAULT 'Hello, I am a developer!',
                role TEXT DEFAULT 'user',
                reset_token TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                content TEXT,
                is_private INTEGER DEFAULT 0,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                filepath TEXT,
                is_private INTEGER DEFAULT 0,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER,
                user_id INTEGER,
                content TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                content TEXT,
                is_private INTEGER DEFAULT 1
            );
        """)

        # Seed admin user
        existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            db.execute("""
                INSERT INTO users (username, password, email, bio, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "admin",
                hashlib.md5(b"admin123").hexdigest(),   # VULN: MD5 password hashing
                "admin@insecurehub.local",
                "I am the administrator.",
                "admin",
                datetime.now().isoformat()
            ))

            # Seed regular user
            db.execute("""
                INSERT INTO users (username, password, email, bio, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "alice",
                hashlib.md5(b"password123").hexdigest(),
                "alice@insecurehub.local",
                "Hi! I love coding in Python.",
                "user",
                datetime.now().isoformat()
            ))

            db.execute("""
                INSERT INTO users (username, password, email, bio, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "bob",
                hashlib.md5(b"bob123").hexdigest(),
                "bob@insecurehub.local",
                "Security researcher.",
                "user",
                datetime.now().isoformat()
            ))

            # Seed posts
            db.execute("""
                INSERT INTO posts (user_id, title, content, is_private, created_at)
                VALUES (1, 'Welcome to InsecureHub!', 'This platform is for sharing code snippets.', 0, ?)
            """, (datetime.now().isoformat(),))

            db.execute("""
                INSERT INTO posts (user_id, title, content, is_private, created_at)
                VALUES (1, 'Admin Secret Notes', 'FLAG{IDOR_SUCCESS_YOU_FOUND_ADMIN_POST}', 1, ?)
            """, (datetime.now().isoformat(),))

            db.execute("""
                INSERT INTO posts (user_id, title, content, is_private, created_at)
                VALUES (2, 'My First Snippet', 'print("Hello World")', 0, ?)
            """, (datetime.now().isoformat(),))

            # Seed files
            secret_path = os.path.join(UPLOAD_FOLDER, "admin_secret.txt")
            with open(secret_path, "w") as f:
                f.write("FLAG{PATH_TRAVERSAL_FILE_READ}\nAdmin API Key: sk-prod-9f8e7d6c5b4a3210\n")

            db.execute("""
                INSERT INTO files (user_id, filename, filepath, is_private, created_at)
                VALUES (1, 'admin_secret.txt', ?, 1, ?)
            """, (secret_path, datetime.now().isoformat()))

            db.execute("""
                INSERT INTO files (user_id, filename, filepath, is_private, created_at)
                VALUES (2, 'hello.py', 'uploads/hello.py', 0, ?)
            """, (datetime.now().isoformat(),))

            # Seed notes
            db.execute("""
                INSERT INTO notes (user_id, title, content, is_private)
                VALUES (1, 'Admin Private Note', 'FLAG{IDOR_NOTE_ACCESS} - DB password: Adm1n@Secure!', 1)
            """)
            db.execute("""
                INSERT INTO notes (user_id, title, content, is_private)
                VALUES (2, 'Alice Note', 'My shopping list', 0)
            """)

            db.commit()

# ─────────────────────────────────────────────
#  Auth helpers
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()   # VULN: MD5

# ─────────────────────────────────────────────
#  Routes: Public
# ─────────────────────────────────────────────
@app.route("/")
def index():
    db = get_db()
    posts = db.execute(
        "SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id WHERE p.is_private=0 ORDER BY p.created_at DESC LIMIT 10"
    ).fetchall()
    return render_template("index.html", posts=posts)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "")
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, 'user', ?)",
                (username, hash_password(password), email, datetime.now().isoformat())
            )
            db.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()
        # VULN: No rate limiting, no lockout
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, hash_password(password))
        ).fetchone()

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]

            # VULN: Pickle deserialization in remember-me cookie
            if request.form.get("remember"):
                user_data = {"user_id": user["id"], "username": user["username"], "role": user["role"]}
                remember_cookie = base64.b64encode(pickle.dumps(user_data)).decode()
                resp = redirect(url_for("dashboard"))
                resp.set_cookie("remember_me", remember_cookie, max_age=86400*30)
                return resp

            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# ─────────────────────────────────────────────
#  Routes: Dashboard
# ─────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    posts = db.execute(
        "SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id WHERE p.user_id=? ORDER BY p.created_at DESC",
        (session["user_id"],)
    ).fetchall()
    files = db.execute(
        "SELECT * FROM files WHERE user_id=?", (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", posts=posts, files=files)

# ─────────────────────────────────────────────
#  Routes: Profile — VULN: IDOR
# ─────────────────────────────────────────────
@app.route("/profile/<int:user_id>")
def profile(user_id):
    db = get_db()
    # VULN: No authorization check — any user_id works
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("index"))
    posts = db.execute(
        "SELECT * FROM posts WHERE user_id=? AND is_private=0", (user_id,)
    ).fetchall()
    return render_template("profile.html", profile_user=user, posts=posts)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    db = get_db()
    if request.method == "POST":
        bio = request.form.get("bio", "")
        # VULN: SSTI — bio is rendered as a Jinja2 template
        db.execute("UPDATE users SET bio=? WHERE id=?", (bio, session["user_id"]))
        db.commit()
        flash("Profile updated!", "success")
        return redirect(url_for("profile", user_id=session["user_id"]))
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("edit_profile.html", user=user)

# ─────────────────────────────────────────────
#  Routes: Posts
# ─────────────────────────────────────────────
@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")
        private = 1 if request.form.get("private") else 0
        db = get_db()
        db.execute(
            "INSERT INTO posts (user_id, title, content, is_private, created_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], title, content, private, datetime.now().isoformat())
        )
        db.commit()
        flash("Post created!", "success")
        return redirect(url_for("dashboard"))
    return render_template("new_post.html")

@app.route("/post/<int:post_id>")
def view_post(post_id):
    db = get_db()
    # VULN: IDOR — private posts accessible by ID without auth check
    post = db.execute(
        "SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?",
        (post_id,)
    ).fetchone()
    if not post:
        flash("Post not found.", "danger")
        return redirect(url_for("index"))
    comments = db.execute(
        "SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.post_id=?",
        (post_id,)
    ).fetchall()
    return render_template("view_post.html", post=post, comments=comments)

@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    # VULN: Stored XSS — content not sanitized
    content = request.form.get("content", "")
    db = get_db()
    db.execute(
        "INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
        (post_id, session["user_id"], content, datetime.now().isoformat())
    )
    db.commit()
    flash("Comment added!", "success")
    return redirect(url_for("view_post", post_id=post_id))

# ─────────────────────────────────────────────
#  Routes: Notes — VULN: IDOR
# ─────────────────────────────────────────────
@app.route("/notes")
@login_required
def notes():
    db = get_db()
    my_notes = db.execute("SELECT * FROM notes WHERE user_id=?", (session["user_id"],)).fetchall()
    return render_template("notes.html", notes=my_notes)

@app.route("/note/<int:note_id>")
@login_required
def view_note(note_id):
    db = get_db()
    # VULN: IDOR — no ownership check
    note = db.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    if not note:
        flash("Note not found.", "danger")
        return redirect(url_for("notes"))
    return render_template("view_note.html", note=note)

@app.route("/note/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")
        private = 1 if request.form.get("private") else 0
        db = get_db()
        db.execute(
            "INSERT INTO notes (user_id, title, content, is_private) VALUES (?, ?, ?, ?)",
            (session["user_id"], title, content, private)
        )
        db.commit()
        flash("Note saved!", "success")
        return redirect(url_for("notes"))
    return render_template("new_note.html")

# ─────────────────────────────────────────────
#  Routes: Search — VULN: SQL Injection
# ─────────────────────────────────────────────
@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = []
    if query:
        db = get_db()
        # VULN: Raw string interpolation = SQL injection
        try:
            raw_sql = f"SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id WHERE p.title LIKE '%{query}%' AND p.is_private=0"
            results = db.execute(raw_sql).fetchall()
        except Exception as e:
            flash(f"Search error: {e}", "danger")
    return render_template("search.html", results=results, query=query)

# ─────────────────────────────────────────────
#  Routes: File Download — VULN: Path Traversal + IDOR
# ─────────────────────────────────────────────
@app.route("/files")
@login_required
def files():
    db = get_db()
    all_files = db.execute(
        "SELECT f.*, u.username FROM files f JOIN users u ON f.user_id=u.id WHERE f.is_private=0"
    ).fetchall()
    my_files = db.execute("SELECT * FROM files WHERE user_id=?", (session["user_id"],)).fetchall()
    return render_template("files.html", all_files=all_files, my_files=my_files)

@app.route("/file/download/<int:file_id>")
@login_required
def download_file(file_id):
    db = get_db()
    # VULN: IDOR — no ownership check on private files
    file_rec = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_rec:
        flash("File not found.", "danger")
        return redirect(url_for("files"))
    return send_file(file_rec["filepath"], as_attachment=True, download_name=file_rec["filename"])

@app.route("/file/read")
@login_required
def read_file():
    # VULN: Path Traversal — filename param not sanitized
    filename = request.args.get("name", "")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return render_template("file_read.html", content=content, filename=filename)
    except Exception as e:
        flash(f"Error reading file: {e}", "danger")
        return redirect(url_for("files"))

@app.route("/file/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("upload_file"))
        # VULN: No file type validation — allows .py, .sh, etc.
        filename = f.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        f.save(filepath)
        private = 1 if request.form.get("private") else 0
        db = get_db()
        db.execute(
            "INSERT INTO files (user_id, filename, filepath, is_private, created_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], filename, filepath, private, datetime.now().isoformat())
        )
        db.commit()
        flash(f"File '{filename}' uploaded!", "success")
        return redirect(url_for("files"))
    return render_template("upload_file.html")

# ─────────────────────────────────────────────
#  Routes: URL Fetcher — VULN: SSRF
# ─────────────────────────────────────────────
@app.route("/fetch", methods=["GET", "POST"])
@login_required
def fetch_url():
    result = None
    error  = None
    url    = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # VULN: SSRF — fetches any URL including internal ones
            resp = requests.get(url, timeout=5, allow_redirects=True)
            result = resp.text[:5000]
        except Exception as e:
            error = str(e)
    return render_template("fetch_url.html", result=result, error=error, url=url)

# ─────────────────────────────────────────────
#  Routes: Template Renderer — VULN: SSTI
# ─────────────────────────────────────────────
@app.route("/render", methods=["GET", "POST"])
@login_required
def render_template_page():
    output = None
    template_input = ""
    if request.method == "POST":
        template_input = request.form.get("template", "")
        try:
            # VULN: SSTI — user input rendered directly as Jinja2 template
            output = render_template_string(template_input)
        except Exception as e:
            output = f"Template Error: {e}"
    return render_template("render_template.html", output=output, template_input=template_input)

# ─────────────────────────────────────────────
#  Routes: Profile Bio Viewer — VULN: SSTI
# ─────────────────────────────────────────────
@app.route("/bio/<int:user_id>")
def render_bio(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return "User not found", 404
    # VULN: SSTI — bio stored in DB and rendered as template
    rendered_bio = render_template_string(user["bio"])
    return render_template("bio.html", user=user, rendered_bio=rendered_bio)

# ─────────────────────────────────────────────
#  Routes: Pickle Cookie — VULN: Deserialization RCE
# ─────────────────────────────────────────────
@app.route("/restore-session")
def restore_session():
    """Auto-login via remember_me cookie (pickle deserialized)."""
    cookie = request.cookies.get("remember_me")
    if cookie:
        try:
            # VULN: Pickle deserialization of user-controlled cookie
            data = pickle.loads(base64.b64decode(cookie))
            session["user_id"]  = data.get("user_id")
            session["username"] = data.get("username")
            session["role"]     = data.get("role")
            flash(f"Session restored for {data.get('username')}!", "success")
        except Exception as e:
            flash(f"Session restore failed: {e}", "danger")
    return redirect(url_for("dashboard"))

# ─────────────────────────────────────────────
#  Routes: Password Reset — VULN: Weak Token
# ─────────────────────────────────────────────
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user:
            # VULN: Predictable reset token (MD5 of username)
            token = hashlib.md5(username.encode()).hexdigest()
            db.execute("UPDATE users SET reset_token=? WHERE username=?", (token, username))
            db.commit()
            flash(f"Reset token (check email): {token}", "info")
        else:
            flash("User not found.", "danger")
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "")
    if request.method == "POST":
        token    = request.form.get("token", "")
        new_pass = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE reset_token=?", (token,)).fetchone()
        if user:
            db.execute(
                "UPDATE users SET password=?, reset_token=NULL WHERE id=?",
                (hash_password(new_pass), user["id"])
            )
            db.commit()
            flash("Password reset! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid or expired token.", "danger")
    return render_template("reset_password.html", token=token)

# ─────────────────────────────────────────────
#  Routes: Admin Panel
# ─────────────────────────────────────────────
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    posts = db.execute("SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id").fetchall()
    return render_template("admin.html", users=users, posts=posts)

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_panel"))

# ─────────────────────────────────────────────
#  Routes: API — VULN: IDOR via API
# ─────────────────────────────────────────────
@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    db = get_db()
    # VULN: IDOR — exposes all user data including password hash and email
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(user))

@app.route("/api/note/<int:note_id>")
def api_note(note_id):
    db = get_db()
    # VULN: IDOR — no auth check
    note = db.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    if not note:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(note))

# ─────────────────────────────────────────────
#  Routes: Debug / Info Disclosure
# ─────────────────────────────────────────────
@app.route("/debug")
def debug_info():
    # VULN: Information disclosure — exposes env, config, session
    info = {
        "secret_key": app.secret_key,
        "database": DATABASE,
        "upload_folder": UPLOAD_FOLDER,
        "session": dict(session),
        "env": {k: v for k, v in os.environ.items() if "KEY" in k or "SECRET" in k or "PASS" in k},
        "python_path": os.sys.path,
    }
    return jsonify(info)

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
