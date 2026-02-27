"""
api.py — бэкенд системы аккаунтов The Pass
"""

import os, uuid, hashlib, hmac, secrets, string, asyncio, aiofiles
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

import bcrypt, sqlite3
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError

JWT_SECRET    = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_H  = 24 * 7
DB_PATH       = "thepass.db"
UPLOAD_DIR    = Path("uploads/avatars")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
Path("uploads/banners").mkdir(parents=True, exist_ok=True)
MAX_AVATAR_MB = 5
TG_BOT_TOKEN  = os.getenv("TG_TOKEN", "")

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
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id               TEXT PRIMARY KEY,
                login            TEXT UNIQUE NOT NULL,
                password_hash    TEXT NOT NULL,
                username         TEXT,
                role             TEXT NOT NULL DEFAULT 'user',
                sub_until        TEXT,
                avatar_url       TEXT,
                credits          INTEGER NOT NULL DEFAULT 0,
                tg_uid           INTEGER,
                created_at       TEXT NOT NULL,
                created_by       INTEGER,
                changed_password INTEGER NOT NULL DEFAULT 0,
                active           INTEGER NOT NULL DEFAULT 1,
                note             TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT,
                action TEXT NOT NULL, detail TEXT, ip TEXT, ts TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS last_games (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                game_title TEXT NOT NULL, game_img TEXT, game_group TEXT, played_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY, banner_url TEXT,
                last_seen TEXT, is_online INTEGER NOT NULL DEFAULT 0
            );
        """)
    print("DB ready")

def hash_password(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def verify_password(p, h):
    try: return bcrypt.checkpw(p.encode(), h.encode())
    except: return False
def make_token(uid):
    return jwt.encode({"sub": uid, "exp": datetime.utcnow()+timedelta(hours=JWT_EXPIRE_H)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
def decode_token(t):
    try: return jwt.decode(t, JWT_SECRET, algorithms=[JWT_ALGORITHM]).get("sub")
    except: return None
def gen_id(): return str(uuid.uuid4())
def gen_password(n=12):
    a=string.ascii_letters+string.digits
    p=[secrets.choice(string.ascii_uppercase),secrets.choice(string.ascii_lowercase),secrets.choice(string.digits)]
    for _ in range(n-3): p.append(secrets.choice(a))
    secrets.SystemRandom().shuffle(p)
    return "".join(p)
def row_to_user(r):
    if not r: return None
    d=dict(r); d.pop("password_hash",None); d.pop("changed_password",None); return d
def log_action(db, uid, action, detail="", ip=""):
    db.execute("INSERT INTO audit_log (user_id,action,detail,ip,ts) VALUES (?,?,?,?,?)",
               (uid,action,detail,ip,datetime.utcnow().isoformat()))

def verify_telegram_data(init_data: str):
    if not TG_BOT_TOKEN: return None
    try:
        params={}
        for part in init_data.split("&"):
            if "=" in part:
                k,v=part.split("=",1); params[unquote(k)]=unquote(v)
        got_hash=params.pop("hash",None)
        if not got_hash: return None
        data_check="\n".join(f"{k}={v}" for k,v in sorted(params.items()))
        secret_key=hmac.new(b"WebAppData",TG_BOT_TOKEN.encode(),hashlib.sha256).digest()
        computed=hmac.new(secret_key,data_check.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed,got_hash): return None
        import json
        return json.loads(params.get("user","{}"))
    except Exception as e:
        print(f"[TG verify] {e}"); return None

app = FastAPI(title="The Pass API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
bearer_scheme = HTTPBearer(auto_error=False)

def get_current_user(creds: Optional[HTTPAuthorizationCredentials]=Depends(bearer_scheme)):
    if not creds: return None
    uid=decode_token(creds.credentials)
    if not uid: return None
    with get_db() as db:
        row=db.execute("SELECT * FROM users WHERE id=? AND active=1",(uid,)).fetchone()
    return row_to_user(row) if row else None

def require_user(user=Depends(get_current_user)):
    if not user: raise HTTPException(401,"Не авторизован")
    return user
def require_admin(user=Depends(get_current_user)):
    if not user or user["role"]!="admin": raise HTTPException(403,"Только для администраторов")
    return user

class LoginRequest(BaseModel):
    login: str; password: str
class TelegramAuthRequest(BaseModel):
    init_data: str
class ChangePasswordRequest(BaseModel):
    old_password: str; new_password: str
class ChangeUsernameRequest(BaseModel):
    username: str
class CreateAccountRequest(BaseModel):
    login: str; username: Optional[str]=None; note: Optional[str]=""; tg_uid: Optional[int]=None
class AdminSetRoleRequest(BaseModel):
    role: str
class AdminSetSubRequest(BaseModel):
    months: int
class AdminSetCreditsRequest(BaseModel):
    amount: int
class LastGameRequest(BaseModel):
    game_title: str; game_img: Optional[str]=None; game_group: Optional[str]=None

@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    with get_db() as db:
        row=db.execute("SELECT * FROM users WHERE login=? AND active=1",(body.login.strip(),)).fetchone()
    if not row or not verify_password(body.password,row["password_hash"]):
        raise HTTPException(401,"Неверный логин или пароль")
    token=make_token(row["id"]); user=row_to_user(row)
    with get_db() as db:
        log_action(db,row["id"],"login",ip=request.client.host if request.client else "")
    return {"token":token,"user":user}

@app.post("/api/auth/telegram")
async def telegram_auth(body: TelegramAuthRequest, request: Request):
    tg_user=verify_telegram_data(body.init_data)
    if tg_user is None and not TG_BOT_TOKEN:
        import json
        try:
            for part in body.init_data.split("&"):
                if part.startswith("user="):
                    tg_user=json.loads(unquote(part[5:])); break
        except: pass
    if not tg_user:
        raise HTTPException(401,"Недействительные данные Telegram")
    tg_id=tg_user.get("id")
    tg_name=tg_user.get("first_name") or tg_user.get("username") or f"user{tg_id}"
    tg_username=tg_user.get("username") or f"user{tg_id}"
    if not tg_id: raise HTTPException(401,"Не удалось получить Telegram ID")
    now=datetime.utcnow().isoformat()
    with get_db() as db:
        row=db.execute("SELECT * FROM users WHERE tg_uid=? AND active=1",(tg_id,)).fetchone()
        if not row:
            uid=gen_id(); login=f"tg_{tg_id}"; password=gen_password()
            if db.execute("SELECT id FROM users WHERE login=?",(login,)).fetchone():
                login=f"tg_{tg_id}_{secrets.token_hex(3)}"
            db.execute("""INSERT INTO users (id,login,password_hash,username,role,credits,tg_uid,
                created_at,created_by,changed_password,active,note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid,login,hash_password(password),tg_name,"user",0,tg_id,now,None,0,1,f"auto TG @{tg_username}"))
            db.execute("""INSERT INTO user_profiles (user_id,last_seen,is_online) VALUES (?,?,1)
                ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen,is_online=1""",(uid,now))
            log_action(db,uid,"register_tg",detail=f"tg_uid={tg_id}",ip=request.client.host if request.client else "")
            row=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        else:
            db.execute("""INSERT INTO user_profiles (user_id,last_seen,is_online) VALUES (?,?,1)
                ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen,is_online=1""",(row["id"],now))
            log_action(db,row["id"],"login_tg",ip=request.client.host if request.client else "")
    return {"token":make_token(row["id"]),"user":row_to_user(row)}

@app.get("/api/auth/me")
async def me(user=Depends(require_user)): return user

@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest, user=Depends(require_user)):
    if len(body.new_password)<8: raise HTTPException(400,"Минимум 8 символов")
    with get_db() as db:
        row=db.execute("SELECT password_hash FROM users WHERE id=?",(user["id"],)).fetchone()
        if not verify_password(body.old_password,row["password_hash"]): raise HTTPException(400,"Неверный текущий пароль")
        db.execute("UPDATE users SET password_hash=?,changed_password=1 WHERE id=?",(hash_password(body.new_password),user["id"]))
        log_action(db,user["id"],"change_password")
    if user.get("tg_uid"): asyncio.create_task(_notify_tg(user["tg_uid"],"🔑 Ваш пароль от The Pass был изменён."))
    return {"ok":True}

@app.post("/api/auth/change-username")
async def change_username(body: ChangeUsernameRequest, user=Depends(require_user)):
    name=body.username.strip()
    if len(name)<2 or len(name)>32: raise HTTPException(400,"Юзернейм: от 2 до 32 символов")
    with get_db() as db:
        db.execute("UPDATE users SET username=? WHERE id=?",(name,user["id"]))
        log_action(db,user["id"],"change_username",detail=name)
    if user.get("tg_uid"): asyncio.create_task(_notify_tg(user["tg_uid"],f"✏️ Юзернейм изменён на: {name}"))
    return {"ok":True,"username":name}

@app.post("/api/auth/avatar")
async def upload_avatar(file: UploadFile=File(...), user=Depends(require_user)):
    if file.content_type not in ("image/jpeg","image/png","image/webp","image/gif"):
        raise HTTPException(400,"Только JPEG, PNG, WebP или GIF")
    contents=await file.read()
    if len(contents)>MAX_AVATAR_MB*1024*1024: raise HTTPException(400,f"Максимум {MAX_AVATAR_MB} МБ")
    ext=file.filename.rsplit(".",1)[-1].lower(); filename=f"{user['id']}.{ext}"; path=UPLOAD_DIR/filename
    async with aiofiles.open(path,"wb") as f: await f.write(contents)
    url=f"/uploads/avatars/{filename}"
    with get_db() as db:
        db.execute("UPDATE users SET avatar_url=? WHERE id=?",(url,user["id"]))
        log_action(db,user["id"],"upload_avatar")
    return {"avatar_url":url}

@app.post("/api/profile/last-games")
async def add_last_game(body: LastGameRequest, user=Depends(require_user)):
    now=datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute("DELETE FROM last_games WHERE user_id=? AND game_title=?",(user["id"],body.game_title))
        db.execute("INSERT INTO last_games (user_id,game_title,game_img,game_group,played_at) VALUES (?,?,?,?,?)",
                   (user["id"],body.game_title,body.game_img,body.game_group,now))
        db.execute("""DELETE FROM last_games WHERE user_id=? AND id NOT IN (
            SELECT id FROM last_games WHERE user_id=? ORDER BY played_at DESC LIMIT 50)""",
                   (user["id"],user["id"]))
    return {"ok":True}

@app.get("/api/profile/last-games")
async def get_last_games(user=Depends(require_user)):
    with get_db() as db:
        rows=db.execute("SELECT game_title,game_img,game_group,played_at FROM last_games WHERE user_id=? ORDER BY played_at DESC LIMIT 50",(user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/profile/last-games/{user_id}")
async def get_last_games_by_user(user_id: str, current=Depends(require_user)):
    with get_db() as db:
        rows=db.execute("SELECT game_title,game_img,game_group,played_at FROM last_games WHERE user_id=? ORDER BY played_at DESC LIMIT 50",(user_id,)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/profile/banner")
async def upload_banner(file: UploadFile=File(...), user=Depends(require_user)):
    if file.content_type not in ("image/jpeg","image/png","image/webp","image/gif"):
        raise HTTPException(400,"Только JPEG, PNG, WebP или GIF")
    contents=await file.read()
    if len(contents)>10*1024*1024: raise HTTPException(400,"Максимум 10 МБ")
    d=Path("uploads/banners"); d.mkdir(parents=True,exist_ok=True)
    ext=file.filename.rsplit(".",1)[-1].lower(); filename=f"{user['id']}_banner.{ext}"; path=d/filename
    async with aiofiles.open(path,"wb") as f: await f.write(contents)
    url=f"/uploads/banners/{filename}"
    with get_db() as db:
        db.execute("""INSERT INTO user_profiles (user_id,banner_url) VALUES (?,?)
            ON CONFLICT(user_id) DO UPDATE SET banner_url=excluded.banner_url""",(user["id"],url))
        log_action(db,user["id"],"upload_banner")
    return {"banner_url":url}

@app.post("/api/profile/online")
async def set_online(user=Depends(require_user)):
    now=datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute("""INSERT INTO user_profiles (user_id,last_seen,is_online) VALUES (?,?,1)
            ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen,is_online=1""",(user["id"],now))
    return {"ok":True}

@app.post("/api/profile/offline")
async def set_offline(user=Depends(require_user)):
    now=datetime.utcnow().isoformat()
    with get_db() as db:
        db.execute("""INSERT INTO user_profiles (user_id,last_seen,is_online) VALUES (?,?,0)
            ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen,is_online=0""",(user["id"],now))
    return {"ok":True}

@app.get("/api/profile/{user_id}")
async def get_user_profile(user_id: str, current=Depends(require_user)):
    with get_db() as db:
        row=db.execute("SELECT id,login,username,role,sub_until,avatar_url,credits,created_at FROM users WHERE id=? AND active=1",(user_id,)).fetchone()
        if not row: raise HTTPException(404,"Пользователь не найден")
        p=db.execute("SELECT banner_url,last_seen,is_online FROM user_profiles WHERE user_id=?",(user_id,)).fetchone()
        cnt=db.execute("SELECT COUNT(*) as c FROM last_games WHERE user_id=?",(user_id,)).fetchone()["c"]
    r=dict(row)
    r["banner_url"]=p["banner_url"] if p else None
    r["last_seen"]=p["last_seen"] if p else None
    r["is_online"]=bool(p["is_online"]) if p else False
    r["games_count"]=cnt
    return r

@app.get("/api/community/users")
async def community_users(current=Depends(require_user)):
    with get_db() as db:
        rows=db.execute("""
            SELECT u.id,u.username,u.login,u.role,u.avatar_url,u.created_at,
                   p.banner_url,p.last_seen,p.is_online,
                   (SELECT COUNT(*) FROM last_games lg WHERE lg.user_id=u.id) as games_count
            FROM users u LEFT JOIN user_profiles p ON p.user_id=u.id
            WHERE u.active=1
            ORDER BY COALESCE(p.is_online,0) DESC, COALESCE(p.last_seen,u.created_at) DESC
        """).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/bot/sync-user")
async def bot_sync_user(request: Request):
    if request.headers.get("X-Bot-Secret","")!=os.getenv("BOT_SECRET","changeme"):
        raise HTTPException(403,"Forbidden")
    body=await request.json(); tg_uid=body.get("tg_uid"); updates=body.get("updates",{})
    if not tg_uid: raise HTTPException(400,"tg_uid required")
    with get_db() as db:
        row=db.execute("SELECT id FROM users WHERE tg_uid=?",(tg_uid,)).fetchone()
        if not row: return {"ok":False,"reason":"user not found"}
        allowed={"role","sub_until","credits","active"}; sets=[]; vals=[]
        for k,v in updates.items():
            if k in allowed: sets.append(f"{k}=?"); vals.append(v)
        if sets:
            vals.append(row["id"])
            db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?",vals)
            log_action(db,row["id"],"bot_sync",detail=str(updates))
    return {"ok":True}

@app.get("/api/admin/users")
async def admin_list_users(admin=Depends(require_admin)):
    with get_db() as db:
        rows=db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [row_to_user(r) for r in rows]

@app.post("/api/admin/users")
async def admin_create_user(body: CreateAccountRequest, admin=Depends(require_admin)):
    login=body.login.strip()
    if not login or len(login)<3: raise HTTPException(400,"Логин минимум 3 символа")
    with get_db() as db:
        if db.execute("SELECT id FROM users WHERE login=?",(login,)).fetchone():
            raise HTTPException(400,f"Логин «{login}» уже занят")
        password=gen_password(); uid=gen_id(); now=datetime.utcnow().isoformat()
        db.execute("""INSERT INTO users (id,login,password_hash,username,role,credits,tg_uid,
            created_at,created_by,changed_password,active,note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid,login,hash_password(password),body.username or login,"user",0,body.tg_uid,now,admin["id"],0,1,body.note or ""))
        log_action(db,admin["id"],"create_user",detail=login)
    return {"id":uid,"login":login,"password":password,"created_at":now}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin=Depends(require_admin)):
    with get_db() as db:
        db.execute("DELETE FROM users WHERE id=?",(user_id,))
        log_action(db,admin["id"],"delete_user",detail=user_id)
    return {"ok":True}

@app.post("/api/admin/users/{user_id}/role")
async def admin_set_role(user_id: str, body: AdminSetRoleRequest, admin=Depends(require_admin)):
    if body.role not in ("user","premium","admin"): raise HTTPException(400,"Роль: user | premium | admin")
    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE id=?",(body.role,user_id))
        row=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
        log_action(db,admin["id"],"set_role",detail=f"{user_id}→{body.role}")
    if row and row["tg_uid"]:
        asyncio.create_task(_notify_tg(row["tg_uid"],f"🎭 Роль изменена: *{body.role}*"))
    return {"ok":True}

@app.post("/api/admin/users/{user_id}/subscription")
async def admin_set_sub(user_id: str, body: AdminSetSubRequest, admin=Depends(require_admin)):
    if body.months<1: raise HTTPException(400,"Минимум 1 месяц")
    with get_db() as db:
        row=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
        if not row: raise HTTPException(404,"Не найден")
        now=datetime.utcnow(); base=now
        if row["sub_until"]:
            cur=datetime.fromisoformat(row["sub_until"])
            if cur>now: base=cur
        new_until=(base+timedelta(days=30*body.months)).isoformat()
        db.execute("UPDATE users SET sub_until=?,role='premium' WHERE id=?",(new_until,user_id))
        log_action(db,admin["id"],"set_sub",detail=f"{user_id}+{body.months}m")
    if row["tg_uid"]:
        asyncio.create_task(_notify_tg(row["tg_uid"],f"💎 Подписка до *{datetime.fromisoformat(new_until).strftime('%d.%m.%Y')}*!"))
    return {"ok":True,"sub_until":new_until}

@app.post("/api/admin/users/{user_id}/credits")
async def admin_set_credits(user_id: str, body: AdminSetCreditsRequest, admin=Depends(require_admin)):
    with get_db() as db:
        db.execute("UPDATE users SET credits=MAX(0,credits+?) WHERE id=?",(body.amount,user_id))
        row=db.execute("SELECT credits FROM users WHERE id=?",(user_id,)).fetchone()
        log_action(db,admin["id"],"set_credits",detail=f"{user_id}{body.amount:+}")
    return {"ok":True,"credits":row["credits"] if row else 0}

@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id: str, admin=Depends(require_admin)):
    new_pwd=gen_password()
    with get_db() as db:
        row=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
        if not row: raise HTTPException(404,"Не найден")
        db.execute("UPDATE users SET password_hash=?,changed_password=0 WHERE id=?",(hash_password(new_pwd),user_id))
        log_action(db,admin["id"],"reset_password",detail=user_id)
    if row["tg_uid"]:
        asyncio.create_task(_notify_tg(row["tg_uid"],f"🔑 Пароль сброшен.\nЛогин: `{row['login']}`\nПароль: `{new_pwd}`"))
    return {"ok":True,"password":new_pwd}

@app.get("/api/admin/logs")
async def admin_logs(limit: int=100, admin=Depends(require_admin)):
    with get_db() as db:
        rows=db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

async def _notify_tg(tg_uid: int, text: str):
    if not TG_BOT_TOKEN: return
    import httpx
    try:
        async with httpx.AsyncClient() as c:
            await c.post(f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={"chat_id":tg_uid,"text":text,"parse_mode":"Markdown"},timeout=10)
    except Exception as e:
        print(f"[TG] {e}")

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
_site_dir=Path("site")
if _site_dir.exists():
    app.mount("/", StaticFiles(directory=str(_site_dir), html=True), name="site")

if __name__=="__main__":
    init_db()
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=int(os.getenv("PORT",8000)), reload=False)
