import sqlite3
import bcrypt
import uuid
import os
from datetime import datetime

# Если папка /app/data существует (мы на Railway с Volume), сохраняем туда.
DB_DIR = "/app/data" if os.path.exists("/app/data") else "."
if os.path.exists("/app"):
    os.makedirs(DB_DIR, exist_ok=True)
    
DB_PATH = os.path.join(DB_DIR, "thepass.db")

# ── Настройки первого админа ─────────────────
LOGIN    = "admin"
PASSWORD = "admin123"
USERNAME = "Admin"
# ─────────────────────────────────────────────

conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA journal_mode=WAL")

# Создаём таблицу если нет
conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        login         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        username      TEXT,
        role          TEXT NOT NULL DEFAULT 'user',
        sub_until     TEXT,
        avatar_url    TEXT,
        credits       INTEGER NOT NULL DEFAULT 0,
        tg_uid        INTEGER,
        created_at    TEXT NOT NULL,
        created_by    INTEGER,
        changed_password INTEGER NOT NULL DEFAULT 0,
        active        INTEGER NOT NULL DEFAULT 1,
        note          TEXT DEFAULT ''
    );
""")

# Проверяем что такого логина ещё нет
existing = conn.execute("SELECT id FROM users WHERE login=?", (LOGIN,)).fetchone()
if existing:
    print(f"⚠️ Пользователь '{LOGIN}' уже существует.")
else:
    uid = str(uuid.uuid4())
    pwd = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    conn.execute("""
        INSERT INTO users
          (id, login, password_hash, username, role, credits, created_at, changed_password, active, note)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (uid, LOGIN, pwd, USERNAME, 'admin', 999, datetime.utcnow().isoformat(), 0, 1, ''))
    conn.commit()
    print(f"✅ Админ создан!")

conn.close()
