"""
ezpeek cloud API + reverse-proxy control plane + STUN/TURN.

Run:
  uvicorn app:app --host 0.0.0.0 --port 8787
Relay TCP on 8788 and STUN/TURN UDP on 3478 start alongside.

Clients dial OUT only — no inbound ports required on user machines:
  - 8787  HTTP API (auth / friends / presence / ice)
  - 8788  TCP reverse-proxy (control + video channels)
  - 3478  STUN (public address) + TURN (UDP relay when enabled)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
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
STUN_PORT = int(os.environ.get("EZPEEK_STUN_PORT", "3478"))
# TURN on by default so symmetric NATs can relay UDP without opening home ports.
TURN_ENABLED = os.environ.get("EZPEEK_TURN_ENABLED", "1").strip() not in ("0", "false", "no")
TURN_REALM = os.environ.get("EZPEEK_TURN_REALM", "ezpeek")
# Shared long-term TURN password (issued to logged-in clients via GET /ice).
TURN_USER = os.environ.get("EZPEEK_TURN_USER", "ezpeek")


def _load_or_create_turn_password() -> str:
    env = os.environ.get("EZPEEK_TURN_PASSWORD")
    if env:
        return env
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "turn.password"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    pw = secrets.token_hex(16)
    path.write_text(pw + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return pw


TURN_PASSWORD = _load_or_create_turn_password()

crypto = CryptoBox(DATA_DIR)
db = Database(DATA_DIR / "ezpeek.db", crypto)
hub = RelayHub(auth_lookup=lambda t: None)  # patched in lifespan
_stun_turn = None  # set in lifespan


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
    global _stun_turn
    hub.auth_lookup = _user_from_token
    hub.resolve_username = _resolve_username
    hub.are_friends = _are_friends

    loop = asyncio.get_event_loop()
    relay_task = loop.create_task(start_relay_server(hub, port=RELAY_PORT))

    # STUN (+ optional TURN) on UDP so clients need zero inbound ports at home.
    try:
        from .stun_turn_svc import StunTurnServer

        _stun_turn = StunTurnServer(
            host="0.0.0.0",
            port=STUN_PORT,
            realm=TURN_REALM,
            enable_turn=TURN_ENABLED,
            relay_ip=PUBLIC_HOST,
        )
        if TURN_ENABLED:
            _stun_turn.credentials.add_credential(TURN_USER, TURN_PASSWORD)
            # Also accept JWT-secret-derived password for username == ezpeek user
            _stun_turn.credentials.add_credential("ezpeek-turn", TURN_PASSWORD)
        await _stun_turn.start()
        logger.info(
            "STUN%s on UDP %s (realm=%s public=%s)",
            "+TURN" if TURN_ENABLED else "",
            STUN_PORT,
            TURN_REALM,
            PUBLIC_HOST,
        )
    except Exception as e:
        logger.exception("STUN/TURN failed to start: %s", e)
        _stun_turn = None

    logger.info(
        "API ready; data=%s public=%s api=%s relay=%s stun=%s",
        DATA_DIR,
        PUBLIC_HOST,
        API_PORT,
        RELAY_PORT,
        STUN_PORT,
    )
    yield
    relay_task.cancel()
    try:
        await relay_task
    except Exception:
        pass
    if _stun_turn is not None:
        try:
            await _stun_turn.stop()
        except Exception:
            pass
    db.close()


app = FastAPI(title="ezpeek cloud", version="0.4.0", lifespan=lifespan)
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
def _ice_payload(*, include_turn_secrets: bool = False) -> dict:
    """ICE / connectivity config for clients (no home firewall holes)."""
    stun_url = f"stun:{PUBLIC_HOST}:{STUN_PORT}"
    out: dict = {
        "public_host": PUBLIC_HOST,
        "api_port": API_PORT,
        "relay": {
            "host": PUBLIC_HOST,
            "port": RELAY_PORT,
            "channels": ["control", "video"],
            "note": "Both peers dial out over TCP; server pairs streams. No inbound ports on clients.",
        },
        "stun": [
            {"urls": stun_url, "host": PUBLIC_HOST, "port": STUN_PORT},
        ],
        "turn_enabled": TURN_ENABLED and _stun_turn is not None,
        "stun_running": _stun_turn is not None,
    }
    if TURN_ENABLED and _stun_turn is not None:
        turn_url = f"turn:{PUBLIC_HOST}:{STUN_PORT}?transport=udp"
        turn_entry: dict = {
            "urls": turn_url,
            "host": PUBLIC_HOST,
            "port": STUN_PORT,
            "realm": TURN_REALM,
        }
        if include_turn_secrets:
            turn_entry["username"] = TURN_USER
            turn_entry["credential"] = TURN_PASSWORD
        out["turn"] = [turn_entry]
    else:
        out["turn"] = []
    return out


@app.get("/")
def root():
    """Browser-friendly landing (avoids bare FastAPI {'detail':'Not Found'})."""
    return {
        "service": "ezpeek-cloud",
        "status": "ok",
        "message": "EzPeek auth / friends / TCP relay / STUN-TURN API. Use the EzPeek app to sign in.",
        "health": "/health",
        "ice": "/ice (auth required for TURN credentials)",
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
        "stun_port": STUN_PORT,
        "turn_enabled": TURN_ENABLED,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ezpeek-cloud",
        "public_host": PUBLIC_HOST,
        "api_port": API_PORT,
        "relay_port": RELAY_PORT,
        "stun_port": STUN_PORT,
        "stun_running": _stun_turn is not None,
        "turn_enabled": TURN_ENABLED and _stun_turn is not None,
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


@app.get("/ice")
def ice_config(user=Depends(current_user)):
    """
    Return STUN/TURN + TCP relay endpoints for the logged-in client.

    Clients only need *outbound* access to these server ports — no inbound
    firewall rules on user machines for cloud remoting.
    """
    _ = user
    return _ice_payload(include_turn_secrets=True)


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
    ice = _ice_payload(include_turn_secrets=True)
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
            "channels": ["control", "video"],
        },
        "ice": ice,
        # Preferred remote path: TCP reverse-proxy (no client inbound ports).
        "preferred_path": "lan" if ips else "tcp_relay",
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
