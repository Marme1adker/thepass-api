import sqlite3
import bcrypt
import uuid
import os
from datetime import datetime

# Настройки путей (с поддержкой Volume на Railway)
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

# 1. Создаем таблицы (теперь с num_id)
conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        num_id        INTEGER UNIQUE,
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

    CREATE TABLE IF NOT EXISTS sessions (
        token     TEXT PRIMARY KEY,
        user_id   TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    TEXT,
        action     TEXT NOT NULL,
        detail     TEXT,
        ip         TEXT,
        ts         TEXT NOT NULL
    );
""")

# 2. УМНЫЙ ПАТЧ: Если таблица старая и в ней нет num_id — добавляем и нумеруем юзеров
try:
    conn.execute("ALTER TABLE users ADD COLUMN num_id INTEGER")
    users = conn.execute("SELECT id FROM users ORDER BY created_at").fetchall()
    for i, u in enumerate(users, 1):
        conn.execute("UPDATE users SET num_id=? WHERE id=?", (i, u[0]))
    conn.commit()
    print("✅ База обновлена: всем старым аккаунтам выданы короткие ID.")
except sqlite3.OperationalError:
    pass # Колонка уже существует, всё ок

# 3. Проверка админа
existing = conn.execute("SELECT id FROM users WHERE login=?", (LOGIN,)).fetchone()
if existing:
    print(f"⚠️ Пользователь '{LOGIN}' уже существует.")
else:
    uid = str(uuid.uuid4())
    pwd = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    
    max_id = conn.execute("SELECT MAX(num_id) FROM users").fetchone()[0] or 0
    new_num_id = max_id + 1
    
    conn.execute("""
        INSERT INTO users
          (id, num_id, login, password_hash, username, role, credits, created_at, changed_password, active, note)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (uid, new_num_id, LOGIN, pwd, USERNAME, 'admin', 999, datetime.utcnow().isoformat(), 0, 1, ''))
    conn.commit()
    print(f"✅ Админ создан! Твой ID: #{new_num_id}")

conn.close()
