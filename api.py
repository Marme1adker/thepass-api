"""
api.py — бэкенд системы аккаунтов The Pass

Запуск:
    pip install fastapi uvicorn python-jose[cryptography] bcrypt python-multipart aiofiles
    python api.py

Работает на порту 8000. Статические файлы сайта раздаются тоже отсюда.
SQLite-база создаётся автоматически в файле thepass.db
"""

import os
import uuid
import hashlib
import secrets
import string
import asyncio
import aiofiles
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import urllib.parse
import hmac

import bcrypt
import sqlite3
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError

# ══════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════

JWT_SECRET    = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_H  = 24 * 7   # 7 дней

DB_DIR        = "/app/data" if os.path.exists("/app/data") else "."
DB_PATH       = os.path.join(DB_DIR, "thepass.db")

UPLOAD_DIR    = Path(DB_DIR) / "uploads" / "avatars"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_AVATAR_MB = 5

# Telegram-бот токен для синхронизации
TG_BOT_TOKEN  = os.getenv("TG_TOKEN", "")

# ══════════════════════════════════════════════════════════════════
# БАЗА ДАННЫХ — SQLite
# ══════════════════════════════════════════════════════════════════

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Создаёт таблицы и патчит их, если они старые."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           TEXT PRIMARY KEY,
                num_id       INTEGER UNIQUE,
                login        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                username     TEXT,
                role         TEXT NOT NULL DEFAULT 'user',
                sub_until    TEXT,
                avatar_url   TEXT,
                banner_url   TEXT,
                credits      INTEGER NOT NULL DEFAULT 0,
                tg_uid       INTEGER,
                created_at   TEXT NOT NULL,
                created_by   INTEGER,
                changed_password INTEGER NOT NULL DEFAULT 0,
                active       INTEGER NOT NULL DEFAULT 1,
                note         TEXT DEFAULT ''
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
        try:
            db.execute("ALTER TABLE users ADD COLUMN num_id INTEGER")
            users = db.execute("SELECT id FROM users ORDER BY created_at").fetchall()
            for i, u in enumerate(users, 1):
                db.execute("UPDATE users SET num_id=? WHERE id=?", (i, u[0]))
        except Exception:
            pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN banner_url TEXT")
        except Exception:
            pass
    print("✅ БД инициализирована:", DB_PATH)


# ══════════════════════════════════════════════════════════════════
# УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def make_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H)
    return jwt.encode(
        {"sub": user_id, "exp": expire},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def gen_id() -> str:
    return str(uuid.uuid4())


def gen_password(length=12) -> str:
    alphabet = string.ascii_letters + string.digits
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    for _ in range(length - 3):
        pwd.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def row_to_user(row) -> dict:
    if not row:
        return None
    d = dict(row)
    # Убираем hash из ответа
    d.pop("password_hash", None)
    d.pop("changed_password", None)
    return d


def log_action(db, user_id: str, action: str, detail: str = "", ip: str = ""):
    db.execute(
        "INSERT INTO audit_log (user_id, action, detail, ip, ts) VALUES (?,?,?,?,?)",
        (user_id, action, detail, ip, datetime.utcnow().isoformat())
    )


# ══════════════════════════════════════════════════════════════════
# FASTAPI
# ══════════════════════════════════════════════════════════════════

app = FastAPI(title="The Pass API", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Optional[dict]:
    if not creds:
        return None
    user_id = decode_token(creds.credentials)
    if not user_id:
        return None
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
    return row_to_user(row) if row else None


def require_user(user=Depends(get_current_user)) -> dict:
    if not user:
        raise HTTPException(401, "Не авторизован")
    return user


def require_admin(user=Depends(get_current_user)) -> dict:
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Только для администраторов")
    return user


# ══════════════════════════════════════════════════════════════════
# МОДЕЛИ
# ══════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    login:    str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class ChangeUsernameRequest(BaseModel):
    username: str

class CreateAccountRequest(BaseModel):
    login:    str
    username: Optional[str] = None
    note:     Optional[str] = ""
    tg_uid:   Optional[int] = None

class AdminSetRoleRequest(BaseModel):
    role: str   # user | premium | admin

class AdminSetSubRequest(BaseModel):
    months: int

class AdminSetCreditsRequest(BaseModel):
    amount: int

# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — АВТОРИЗАЦИЯ
# ══════════════════════════════════════════════════════════════════
# ── Бесшовный вход через Telegram Web App ─────────────────────────

class TelegramAuthRequest(BaseModel):
    init_data: str

def verify_telegram_web_app_data(init_data: str, bot_token: str) -> Optional[dict]:
    """
    Верификация подписи Telegram Web App по официальной документации:
    https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    """
    try:
        import json
        parsed_data = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        if "hash" not in parsed_data:
            return None

        hash_val = parsed_data.pop("hash")
        data_check_string = "\n".join(
            f"{k}={v}" for k, v in sorted(parsed_data.items())
        )

        # Правильный алгоритм: secret_key = HMAC-SHA256("WebAppData", bot_token)
        secret_key = hmac.new(
            key=b"WebAppData",
            msg=bot_token.encode("utf-8"),
            digestmod=hashlib.sha256
        ).digest()

        calc_hash = hmac.new(
            key=secret_key,
            msg=data_check_string.encode("utf-8"),
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calc_hash, hash_val):
            return None

        user_str = parsed_data.get("user", "{}")
        return json.loads(user_str)

    except Exception as e:
        print(f"[TG verify] Ошибка верификации: {e}")
        return None

@app.post("/api/auth/telegram")
async def auth_telegram(body: TelegramAuthRequest, request: Request):
    if not TG_BOT_TOKEN:
        raise HTTPException(500, "TG_TOKEN не настроен на сервере")

    tg_user = verify_telegram_web_app_data(body.init_data, TG_BOT_TOKEN)
    if not tg_user or "id" not in tg_user:
        raise HTTPException(401, "Недействительная подпись")

    tg_uid = tg_user["id"]
    
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE tg_uid=? AND active=1", (tg_uid,)).fetchone()
        
        if not row:
            uid = gen_id()
            login = f"tg_{tg_uid}"
            password = gen_password(16)
            pwd_hash = hash_password(password)
            username = tg_user.get("first_name", f"User{tg_uid}")[:32]
            now = datetime.utcnow().isoformat()
            
            # Получаем следующий ID
            max_id = db.execute("SELECT MAX(num_id) FROM users").fetchone()
            num_id = (max_id[0] or 0) + 1

            db.execute("""
                INSERT INTO users
                  (id, num_id, login, password_hash, username, role, credits, tg_uid,
                   created_at, changed_password, active, note)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (uid, num_id, login, pwd_hash, username, "user", 0, tg_uid, now, 0, 1, ""))
            row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            log_action(db, uid, "register_telegram")

        token = make_token(row["id"])
        user  = row_to_user(row)
        log_action(db, row["id"], "login_telegram", ip=request.client.host if request.client else "")

    return {"token": token, "user": user}


@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE login=? AND active=1", (body.login.strip(),)
        ).fetchone()

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Неверный логин или пароль")

    token = make_token(row["id"])
    user  = row_to_user(row)

    with get_db() as db:
        log_action(db, row["id"], "login", ip=request.client.host if request.client else "")

    return {"token": token, "user": user}


@app.get("/api/auth/me")
async def me(user=Depends(require_user)):
    return user


@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest, user=Depends(require_user)):
    if len(body.new_password) < 8:
        raise HTTPException(400, "Минимум 8 символов")

    with get_db() as db:
        row = db.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(body.old_password, row["password_hash"]):
            raise HTTPException(400, "Неверный текущий пароль")

        new_hash = hash_password(body.new_password)
        db.execute(
            "UPDATE users SET password_hash=?, changed_password=1 WHERE id=?",
            (new_hash, user["id"])
        )
        log_action(db, user["id"], "change_password")

    # Синхронизируем с ботом если привязан TG
    if user.get("tg_uid"):
        asyncio.create_task(_notify_tg(
            user["tg_uid"],
            "🔑 Ваш пароль от The Pass был изменён."
        ))

    return {"ok": True}


@app.post("/api/auth/change-username")
async def change_username(body: ChangeUsernameRequest, user=Depends(require_user)):
    name = body.username.strip()
    if len(name) < 2 or len(name) > 32:
        raise HTTPException(400, "Юзернейм: от 2 до 32 символов")

    with get_db() as db:
        db.execute("UPDATE users SET username=? WHERE id=?", (name, user["id"]))
        log_action(db, user["id"], "change_username", detail=name)

    # Синхронизируем с ботом
    if user.get("tg_uid"):
        asyncio.create_task(_notify_tg(
            user["tg_uid"],
            f"✏️ Ваш юзернейм изменён на: {name}"
        ))

    return {"ok": True, "username": name}


@app.post("/api/auth/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    user=Depends(require_user)
):
    # Проверка типа
    if file.content_type not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
        raise HTTPException(400, "Только JPEG, PNG, WebP или GIF")

    # Проверка размера
    contents = await file.read()
    if len(contents) > MAX_AVATAR_MB * 1024 * 1024:
        raise HTTPException(400, f"Максимум {MAX_AVATAR_MB} МБ")

    ext      = file.filename.rsplit(".", 1)[-1].lower()
    filename = f"{user['id']}.{ext}"
    path     = UPLOAD_DIR / filename

    async with aiofiles.open(path, "wb") as f:
        await f.write(contents)

    avatar_url = f"/uploads/avatars/{filename}"

    with get_db() as db:
        db.execute("UPDATE users SET avatar_url=? WHERE id=?", (avatar_url, user["id"]))
        log_action(db, user["id"], "upload_avatar")

    return {"avatar_url": avatar_url}

@app.post("/api/auth/banner")
async def upload_banner(
    file: UploadFile = File(...),
    user=Depends(require_user)
):
    if file.content_type not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
        raise HTTPException(400, "Только JPEG, PNG, WebP или GIF")

    contents = await file.read()
    if len(contents) > 8 * 1024 * 1024:
        raise HTTPException(400, "Максимум 8 МБ")

    # Папка для баннеров
    banner_dir = Path(DB_DIR) / "uploads" / "banners"
    banner_dir.mkdir(parents=True, exist_ok=True)

    ext      = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "jpg"
    filename = f"{user['id']}.{ext}"
    path     = banner_dir / filename

    async with aiofiles.open(path, "wb") as f:
        await f.write(contents)

    banner_url = f"/uploads/banners/{filename}"

    with get_db() as db:
        db.execute("UPDATE users SET banner_url=? WHERE id=?", (banner_url, user["id"]))
        log_action(db, user["id"], "upload_banner")

    return {"banner_url": banner_url}
# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — АККАУНТЫ (только для вебхуков от бота)
# ══════════════════════════════════════════════════════════════════

@app.post("/api/bot/sync-user")
async def bot_sync_user(request: Request):
    """
    Эндпоинт для бота — синхронизирует данные пользователя.
    Вызывается из admin.py / database.py при изменениях.
    Защита: секретный заголовок X-Bot-Secret.
    """
    secret = request.headers.get("X-Bot-Secret", "")
    if secret != os.getenv("BOT_SECRET", "changeme"):
        raise HTTPException(403, "Forbidden")

    body = await request.json()
    tg_uid  = body.get("tg_uid")
    updates = body.get("updates", {})   # {role, sub_until, credits}

    if not tg_uid:
        raise HTTPException(400, "tg_uid required")

    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE tg_uid=?", (tg_uid,)).fetchone()
        if not row:
            return {"ok": False, "reason": "user not found"}

        allowed = {"role", "sub_until", "credits", "active"}
        sets    = []
        vals    = []
        for k, v in updates.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(v)

        if sets:
            vals.append(row["id"])
            db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)
            log_action(db, row["id"], "bot_sync", detail=str(updates))

    return {"ok": True}

# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — КОМЬЮНИТИ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/community/users")
async def get_community_users():
    with get_db() as db:
        rows = db.execute(
            "SELECT num_id, login, username, role, avatar_url, banner_url, credits, sub_until, created_at "
            "FROM users WHERE active=1 ORDER BY num_id ASC"
        ).fetchall()
    
    users = []
    for r in rows:
        users.append({
            "num_id":     r["num_id"],
            "login":      r["login"],
            "username":   r["username"],
            "role":       r["role"],
            "avatar_url": r["avatar_url"],
            "banner_url": r["banner_url"],
            "credits":    r["credits"] or 0,
            "sub_until":  r["sub_until"],
            "created_at": r["created_at"],
        })
    return users
# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — ADMIN
# ══════════════════════════════════════════════════════════════════

@app.get("/api/admin/users")
async def admin_list_users(admin=Depends(require_admin)):
    with get_db() as db:
        rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [row_to_user(r) for r in rows]


@app.post("/api/admin/users")
async def admin_create_user(body: CreateAccountRequest, admin=Depends(require_admin)):
    login = body.login.strip()
    if not login or len(login) < 3:
        raise HTTPException(400, "Логин минимум 3 символа")

    with get_db() as db:
        exists = db.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()
        if exists:
            raise HTTPException(400, f"Логин «{login}» уже занят")

        password    = gen_password()
        uid         = gen_id()
        now         = datetime.utcnow().isoformat()

        db.execute("""
            INSERT INTO users
              (id, login, password_hash, username, role, credits, tg_uid,
               created_at, created_by, changed_password, active, note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            uid, login, hash_password(password),
            body.username or login,
            "user", 0, body.tg_uid,
            now, admin["id"], 0, 1, body.note or ""
        ))
        log_action(db, admin["id"], "create_user", detail=login)

    return {
        "id":       uid,
        "login":    login,
        "password": password,   # plain — только здесь, один раз
        "created_at": now,
    }


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin=Depends(require_admin)):
    with get_db() as db:
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        log_action(db, admin["id"], "delete_user", detail=user_id)
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/role")
async def admin_set_role(user_id: str, body: AdminSetRoleRequest, admin=Depends(require_admin)):
    if body.role not in ("user", "premium", "admin"):
        raise HTTPException(400, "Роль: user | premium | admin")
    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE id=?", (body.role, user_id))
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        log_action(db, admin["id"], "set_role", detail=f"{user_id} → {body.role}")

    # Уведомляем пользователя через Telegram
    if row and row["tg_uid"]:
        role_text = {"premium": "💎 Premium", "admin": "👑 Admin", "user": "👤 User"}
        asyncio.create_task(_notify_tg(
            row["tg_uid"],
            f"🎭 Ваша роль изменена: *{role_text.get(body.role, body.role)}*"
        ))

    return {"ok": True}


@app.post("/api/admin/users/{user_id}/subscription")
async def admin_set_sub(user_id: str, body: AdminSetSubRequest, admin=Depends(require_admin)):
    if body.months < 1:
        raise HTTPException(400, "Минимум 1 месяц")

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Пользователь не найден")

        now  = datetime.utcnow()
        base = now
        if row["sub_until"]:
            cur = datetime.fromisoformat(row["sub_until"])
            if cur > now:
                base = cur
        new_until = (base + timedelta(days=30 * body.months)).isoformat()

        db.execute("UPDATE users SET sub_until=?, role='premium' WHERE id=?", (new_until, user_id))
        log_action(db, admin["id"], "set_sub", detail=f"{user_id} +{body.months}m")

    if row["tg_uid"]:
        end_str = datetime.fromisoformat(new_until).strftime("%d.%m.%Y")
        asyncio.create_task(_notify_tg(
            row["tg_uid"],
            f"💎 Вам выдана подписка The Pass до *{end_str}*!"
        ))

    return {"ok": True, "sub_until": new_until}


@app.post("/api/admin/users/{user_id}/credits")
async def admin_set_credits(user_id: str, body: AdminSetCreditsRequest, admin=Depends(require_admin)):
    with get_db() as db:
        db.execute(
            "UPDATE users SET credits = MAX(0, credits + ?) WHERE id=?",
            (body.amount, user_id)
        )
        row = db.execute("SELECT credits FROM users WHERE id=?", (user_id,)).fetchone()
        log_action(db, admin["id"], "set_credits", detail=f"{user_id} {body.amount:+}")
    return {"ok": True, "credits": row["credits"] if row else 0}


@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id: str, admin=Depends(require_admin)):
    new_pwd = gen_password()
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Пользователь не найден")
        db.execute(
            "UPDATE users SET password_hash=?, changed_password=0 WHERE id=?",
            (hash_password(new_pwd), user_id)
        )
        log_action(db, admin["id"], "reset_password", detail=user_id)

    if row["tg_uid"]:
        asyncio.create_task(_notify_tg(
            row["tg_uid"],
            f"🔑 Ваш пароль сброшен администратором.\n\n"
            f"Логин: `{row['login']}`\nНовый пароль: `{new_pwd}`\n\n"
            f"Войдите на сайт и смените пароль."
        ))

    return {"ok": True, "password": new_pwd}


# ── Списание 1 кредита при поиске игры (вызывается с фронта) ─────
@app.post("/api/auth/spend-credit")
async def spend_credit(user=Depends(require_user)):
    """
    Тратит 1 кредит (activation) при нажатии кнопки «Найти игру».
    Доступен любому залогиненному пользователю с credits > 0.
    """
    with get_db() as db:
        row = db.execute("SELECT credits FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row or row["credits"] <= 0:
            raise HTTPException(400, "Нет доступных активаций")
        db.execute(
            "UPDATE users SET credits = credits - 1 WHERE id=? AND credits > 0",
            (user["id"],)
        )
        updated = db.execute("SELECT credits FROM users WHERE id=?", (user["id"],)).fetchone()
        log_action(db, user["id"], "spend_credit", detail=f"remaining={updated['credits']}")
    return {"ok": True, "credits": updated["credits"]}


# ── Сброс подписки пользователя (только admin) ─────────────────────
@app.post("/api/admin/users/{user_id}/reset-sub")
async def admin_reset_sub(user_id: str, admin=Depends(require_admin)):
    """Убирает подписку: sub_until=NULL, role='user'."""
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Пользователь не найден")
        db.execute(
            "UPDATE users SET sub_until=NULL, role='user' WHERE id=?",
            (user_id,)
        )
        log_action(db, admin["id"], "reset_sub", detail=user_id)

    if row["tg_uid"]:
        asyncio.create_task(_notify_tg(
            row["tg_uid"],
            "ℹ️ Ваша подписка The Pass была сброшена администратором."
        ))

    return {"ok": True}


@app.get("/api/admin/logs")
async def admin_logs(limit: int = 100, admin=Depends(require_admin)):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════
# СИНХРОНИЗАЦИЯ С TELEGRAM-БОТОМ
# ══════════════════════════════════════════════════════════════════

async def _notify_tg(tg_uid: int, text: str):
    """Отправляет сообщение пользователю через бот."""
    if not TG_BOT_TOKEN:
        return
    import httpx
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json={
                "chat_id":    tg_uid,
                "text":       text,
                "parse_mode": "Markdown",
            }, timeout=10)
    except Exception as e:
        print(f"[TG notify] Ошибка: {e}")


# ══════════════════════════════════════════════════════════════════
# СТАТИЧЕСКИЕ ФАЙЛЫ
# ══════════════════════════════════════════════════════════════════

# Раздаём загруженные аватары
# Раздаём загруженные аватары
upload_base = Path(DB_DIR) / "uploads"
upload_base.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(upload_base)), name="uploads")

# Раздаём сам сайт (index.html и все .js/.css)
# Папку "site" создай рядом с api.py и положи туда все файлы сайта
_site_dir = Path("site")
if _site_dir.exists():
    app.mount("/", StaticFiles(directory=str(_site_dir), html=True), name="site")


# ══════════════════════════════════════════════════════════════════
# ИНИЦИАЛИЗАЦИЯ БД — запускается при старте модуля (Railway/gunicorn)
# ══════════════════════════════════════════════════════════════════

init_db()


# ══════════════════════════════════════════════════════════════════
# ЗАПУСК (локально)
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False,
    )
