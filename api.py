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

DB_PATH       = "thepass.db"
UPLOAD_DIR    = Path("uploads/avatars")
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
    """Создаёт таблицы если не существуют."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           TEXT PRIMARY KEY,
                login        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                username     TEXT,
                role         TEXT NOT NULL DEFAULT 'user',
                sub_until    TEXT,
                avatar_url   TEXT,
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

            CREATE TABLE IF NOT EXISTS last_games (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    TEXT NOT NULL,
                game_title TEXT NOT NULL,
                game_img   TEXT,
                game_group TEXT,
                played_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id    TEXT PRIMARY KEY,
                banner_url TEXT,
                last_seen  TEXT,
                is_online  INTEGER NOT NULL DEFAULT 0
            );
        """)
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
    allow_credentials=True,
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

class LastGameRequest(BaseModel):
    game_title: str
    game_img:   Optional[str] = None
    game_group: Optional[str] = None

# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — АВТОРИЗАЦИЯ
# ══════════════════════════════════════════════════════════════════

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


@app.get("/api/admin/logs")
async def admin_logs(limit: int = 100, admin=Depends(require_admin)):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — LAST GAMES (история игр, не удаляется)
# ══════════════════════════════════════════════════════════════════

@app.post("/api/profile/last-games")
async def add_last_game(body: LastGameRequest, user=Depends(require_user)):
    """Добавить/обновить игру в last_games. Если уже есть — поднимает наверх."""
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        # Удаляем старую запись этой игры если есть
        db.execute(
            "DELETE FROM last_games WHERE user_id=? AND game_title=?",
            (user["id"], body.game_title)
        )
        # Вставляем новую (она будет первой по played_at)
        db.execute(
            "INSERT INTO last_games (user_id, game_title, game_img, game_group, played_at) VALUES (?,?,?,?,?)",
            (user["id"], body.game_title, body.game_img, body.game_group, now)
        )
        # Оставляем максимум 50 игр на пользователя
        db.execute("""
            DELETE FROM last_games WHERE user_id=? AND id NOT IN (
                SELECT id FROM last_games WHERE user_id=? ORDER BY played_at DESC LIMIT 50
            )
        """, (user["id"], user["id"]))

    return {"ok": True}


@app.get("/api/profile/last-games")
async def get_last_games(user=Depends(require_user)):
    """Получить last_games текущего пользователя."""
    with get_db() as db:
        rows = db.execute(
            "SELECT game_title, game_img, game_group, played_at FROM last_games "
            "WHERE user_id=? ORDER BY played_at DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/profile/last-games/{user_id}")
async def get_last_games_by_user(user_id: str, current=Depends(require_user)):
    """Получить last_games другого пользователя (для комьюнити)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT game_title, game_img, game_group, played_at FROM last_games "
            "WHERE user_id=? ORDER BY played_at DESC LIMIT 50",
            (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — ПРОФИЛЬ (баннер, онлайн-статус)
# ══════════════════════════════════════════════════════════════════

@app.post("/api/profile/banner")
async def upload_banner(file: UploadFile = File(...), user=Depends(require_user)):
    """Загрузить баннер профиля."""
    if file.content_type not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
        raise HTTPException(400, "Только JPEG, PNG, WebP или GIF")

    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:  # 10MB для баннера
        raise HTTPException(400, "Максимум 10 МБ")

    banner_dir = Path("uploads/banners")
    banner_dir.mkdir(parents=True, exist_ok=True)

    ext      = file.filename.rsplit(".", 1)[-1].lower()
    filename = f"{user['id']}_banner.{ext}"
    path     = banner_dir / filename

    async with aiofiles.open(path, "wb") as f:
        await f.write(contents)

    banner_url = f"/uploads/banners/{filename}"

    with get_db() as db:
        db.execute("""
            INSERT INTO user_profiles (user_id, banner_url) VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET banner_url=excluded.banner_url
        """, (user["id"], banner_url))
        log_action(db, user["id"], "upload_banner")

    return {"banner_url": banner_url}


@app.post("/api/profile/online")
async def set_online(user=Depends(require_user)):
    """Обновить онлайн-статус (вызывается при открытии сайта)."""
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute("""
            INSERT INTO user_profiles (user_id, last_seen, is_online) VALUES (?, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen, is_online=1
        """, (user["id"], now))
    return {"ok": True}


@app.post("/api/profile/offline")
async def set_offline(user=Depends(require_user)):
    """Обновить оффлайн-статус."""
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute("""
            INSERT INTO user_profiles (user_id, last_seen, is_online) VALUES (?, ?, 0)
            ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen, is_online=0
        """, (user["id"], now))
    return {"ok": True}


@app.get("/api/profile/{user_id}")
async def get_user_profile(user_id: str, current=Depends(require_user)):
    """Получить публичный профиль пользователя."""
    with get_db() as db:
        user_row = db.execute(
            "SELECT id, login, username, role, sub_until, avatar_url, credits, created_at "
            "FROM users WHERE id=? AND active=1",
            (user_id,)
        ).fetchone()
        if not user_row:
            raise HTTPException(404, "Пользователь не найден")

        profile_row = db.execute(
            "SELECT banner_url, last_seen, is_online FROM user_profiles WHERE user_id=?",
            (user_id,)
        ).fetchone()

        games_count = db.execute(
            "SELECT COUNT(*) as cnt FROM last_games WHERE user_id=?", (user_id,)
        ).fetchone()["cnt"]

    result = dict(user_row)
    result.pop("password_hash", None)
    if profile_row:
        result["banner_url"] = profile_row["banner_url"]
        result["last_seen"]  = profile_row["last_seen"]
        result["is_online"]  = bool(profile_row["is_online"])
    else:
        result["banner_url"] = None
        result["last_seen"]  = None
        result["is_online"]  = False
    result["games_count"] = games_count
    return result


# ══════════════════════════════════════════════════════════════════
# ЭНДПОИНТЫ — КОМЬЮНИТИ
# ══════════════════════════════════════════════════════════════════

@app.get("/api/community/users")
async def community_users(current=Depends(require_user)):
    """Список всех активных пользователей для комьюнити."""
    with get_db() as db:
        rows = db.execute("""
            SELECT u.id, u.username, u.login, u.role, u.avatar_url, u.created_at,
                   p.banner_url, p.last_seen, p.is_online,
                   (SELECT COUNT(*) FROM last_games lg WHERE lg.user_id = u.id) as games_count
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
            WHERE u.active = 1
            ORDER BY p.is_online DESC, p.last_seen DESC
        """).fetchall()
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
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Раздаём сам сайт (index.html и все .js/.css)
# Папку "site" создай рядом с api.py и положи туда все файлы сайта
_site_dir = Path("site")
if _site_dir.exists():
    app.mount("/", StaticFiles(directory=str(_site_dir), html=True), name="site")


# ══════════════════════════════════════════════════════════════════
# ЗАПУСК
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()

    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False,
    )
