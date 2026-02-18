# InsecureHub

A deliberately vulnerable Flask app for learning web pentesting. Simulates a code-sharing platform with intentional security flaws covering OWASP Top 10 and common CTF categories.

---

## Setup

```bash
pip install -r requirements.txt
python app.py
# Runs at http://127.0.0.1:5000
```

**Test accounts:**

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin123 | Admin |
| alice    | password123 | User |
| bob      | bob123   | User  |

---

## Vulnerabilities

| # | Type | Endpoint |
|---|------|----------|
| 1 | IDOR | `/note/<id>`, `/post/<id>`, `/file/download/<id>`, `/api/user/<id>` |
| 2 | SSTI | `/render`, `/bio/<id>`, `/profile/edit` |
| 3 | SQL Injection | `/search?q=` |
| 4 | SSRF | `/fetch` |
| 5 | Pickle RCE | `remember_me` cookie + `/restore-session` |
| 6 | Path Traversal | `/file/read?name=` |
| 7 | Stored XSS | Post comments |
| 8 | Weak Reset Token | `/forgot-password` (MD5) |
| 9 | Info Disclosure | `/debug` |
| 10 | Broken Auth | MD5 passwords, no rate limiting |

---

## Project Structure

```
InsecureHub/
├── app.py
├── requirements.txt
├── static/style.css
├── templates/
├── exploits/exploit_all.py
└── uploads/
```

---

**Resources:** [OWASP Top 10](https://owasp.org/www-project-top-ten/) · [PortSwigger Academy](https://portswigger.net/web-security) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)