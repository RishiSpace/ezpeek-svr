"""
ezpeek cloud API + reverse-proxy control plane.

Run:
  uvicorn app:app --host 0.0.0.0 --port 8787
Relay TCP on 8788 started alongside.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from .crypto_store import CryptoBox
from .db import Database
from .relay import RelayHub, start_relay_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ezpeek.cloud")

DATA_DIR = Path(os.environ.get("EZPEEK_DATA", Path.home() / "ezpeek-cloud-data"))
JWT_SECRET = os.environ.get("EZPEEK_JWT_SECRET") or secrets.token_hex(32)
JWT_ALG = "HS256"
API_PORT = int(os.environ.get("EZPEEK_API_PORT", "8787"))
RELAY_PORT = int(os.environ.get("EZPEEK_RELAY_PORT", "8788"))
PUBLIC_HOST = os.environ.get("EZPEEK_PUBLIC_HOST", "162.35.166.14")

crypto = CryptoBox(DATA_DIR)
db = Database(DATA_DIR / "ezpeek.db", crypto)
hub = RelayHub(auth_lookup=lambda t: None)  # patched in lifespan


def _user_from_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = int(payload["sub"])
        row = db.get_user_by_id(uid)
        if not row:
            return None
        # also check server-side session table
        if not db.user_for_token(token):
            return None
        return {"id": row["id"], "username": row["username"]}
    except Exception:
        return None


def _resolve_username(username: str):
    return db.get_user_by_username(username)


def _are_friends(a: int, b: int) -> bool:
    row = db.conn.execute(
        """
        SELECT 1 FROM friendships
        WHERE status='accepted' AND (
          (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
        )
        """,
        (a, b, b, a),
    ).fetchone()
    return row is not None


@asynccontextmanager
async def lifespan(app: FastAPI):
    hub.auth_lookup = _user_from_token
    hub.resolve_username = _resolve_username
    hub.are_friends = _are_friends

    loop = asyncio.get_event_loop()
    relay_task = loop.create_task(start_relay_server(hub, port=RELAY_PORT))
    logger.info("API ready; data=%s public=%s", DATA_DIR, PUBLIC_HOST)
    yield
    relay_task.cancel()
    try:
        await relay_task
    except Exception:
        pass
    db.close()


app = FastAPI(title="ezpeek cloud", version="0.3.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- models ----------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    login: str  # username or email
    password: str


class FriendIn(BaseModel):
    username: str


class PresenceIn(BaseModel):
    online: bool = True
    hosting: bool = False
    lan_ips: list[str] = []
    video_port: Optional[int] = None
    ctrl_port: Optional[int] = None
    relay_ready: bool = False


# ---------- auth deps ----------
def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    row = db.user_for_token(token)
    if not row:
        raise HTTPException(401, "invalid or expired session")
    return {"id": row["id"], "username": row["username"], "token": token, "row": row}


def _issue_token(user_id: int, username: str) -> str:
    token = jwt.encode(
        {"sub": str(user_id), "username": username},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )
    # PyJWT may return bytes on old versions
    if isinstance(token, bytes):
        token = token.decode()
    db.create_session(user_id, token)
    return token


# ---------- routes ----------
@app.get("/")
def root():
    """Browser-friendly landing (avoids bare FastAPI {'detail':'Not Found'})."""
    return {
        "service": "ezpeek-cloud",
        "status": "ok",
        "message": "EzPeek auth / friends / relay API. Use the EzPeek app to sign in.",
        "health": "/health",
        "docs": "/docs",
        "auth": {
            "register": "POST /auth/register",
            "login": "POST /auth/login",
            "me": "GET /auth/me",
        },
        "friends": {
            "list": "GET /friends",
            "add": "POST /friends/add",
            "accept": "POST /friends/accept",
        },
        "public_host": PUBLIC_HOST,
        "api_port": API_PORT,
        "relay_port": RELAY_PORT,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ezpeek-cloud",
        "public_host": PUBLIC_HOST,
        "api_port": API_PORT,
        "relay_port": RELAY_PORT,
    }


@app.post("/auth/register")
def register(body: RegisterIn):
    try:
        uid = db.create_user(body.username, body.email, body.password)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "username already taken")
    except ValueError as e:
        raise HTTPException(400, str(e))
    token = _issue_token(uid, body.username.strip())
    row = db.get_user_by_id(uid)
    return {"token": token, "user": db.user_public(row)}


# late import for IntegrityError
import sqlite3  # noqa: E402


@app.post("/auth/login")
def login(body: LoginIn):
    row = db.verify_login(body.login, body.password)
    if not row:
        raise HTTPException(401, "invalid credentials")
    token = _issue_token(row["id"], row["username"])
    return {"token": token, "user": db.user_public(row)}


@app.get("/auth/me")
def me(user=Depends(current_user)):
    return {"user": db.user_public(user["row"])}


@app.post("/auth/logout")
def logout(user=Depends(current_user)):
    db.delete_session(user["token"])
    return {"ok": True}


@app.post("/friends/add")
def friends_add(body: FriendIn, user=Depends(current_user)):
    try:
        status = db.add_friend_request(user["id"], body.username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": status, "username": body.username}


@app.post("/friends/accept")
def friends_accept(body: FriendIn, user=Depends(current_user)):
    try:
        db.accept_friend(user["id"], body.username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.get("/friends")
def friends_list(user=Depends(current_user)):
    return {"friends": db.list_friends(user["id"])}


@app.post("/presence")
def presence_set(body: PresenceIn, user=Depends(current_user)):
    db.set_presence(
        user["id"],
        online=body.online,
        hosting=body.hosting,
        lan_ips=json.dumps(body.lan_ips),
        video_port=body.video_port,
        ctrl_port=body.ctrl_port,
        relay_ready=body.relay_ready,
    )
    return {"ok": True}


@app.get("/friends/{username}/connect")
def friend_connect(username: str, user=Depends(current_user)):
    """Return how to reach a friend: LAN if possible, else relay via greenbird."""
    friend = db.get_user_by_username(username)
    if not friend:
        raise HTTPException(404, "user not found")
    if not _are_friends(user["id"], friend["id"]):
        raise HTTPException(403, "not friends")
    pres = db.get_presence(friend["id"])
    if not pres or not pres["online"]:
        raise HTTPException(409, "friend offline")
    try:
        ips = json.loads(pres["lan_ips"] or "[]")
    except Exception:
        ips = []
    return {
        "username": friend["username"],
        "online": bool(pres["online"]),
        "hosting": bool(pres["hosting"]),
        "lan_ips": ips,
        "video_port": pres["video_port"],
        "ctrl_port": pres["ctrl_port"],
        "relay_ready": bool(pres["relay_ready"]),
        "relay": {
            "host": PUBLIC_HOST,
            "port": RELAY_PORT,
            # viewer authenticates with own token; host username is the friend
            "friend_username": friend["username"],
        },
    }


def main():
    import uvicorn

    uvicorn.run(
        "ezpeek_cloud.app:app",
        host="0.0.0.0",
        port=API_PORT,
        factory=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
