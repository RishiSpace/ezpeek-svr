"""SQLite schema + helpers. Sensitive columns stored as AES blobs."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from .crypto_store import CryptoBox


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email_enc BLOB NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    status TEXT NOT NULL,  -- pending | accepted
    created_at REAL NOT NULL,
    UNIQUE(user_id, friend_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(friend_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS presence (
    user_id INTEGER PRIMARY KEY,
    online INTEGER NOT NULL DEFAULT 0,
    hosting INTEGER NOT NULL DEFAULT 0,
    lan_ips TEXT NOT NULL DEFAULT '[]',
    video_port INTEGER,
    ctrl_port INTEGER,
    relay_ready INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


class Database:
    def __init__(self, path: Path, crypto: CryptoBox):
        self.path = path
        self.crypto = crypto
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ---- users ----
    def create_user(self, username: str, email: str, password: str) -> int:
        username = username.strip()
        email = email.strip().lower()
        if not username or not email or not password:
            raise ValueError("username, email, password required")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        email_enc = self.crypto.encrypt(email)
        pw_hash = self.crypto.hash_password(password)
        cur = self.conn.execute(
            "INSERT INTO users (username, email_enc, password_hash, created_at) VALUES (?,?,?,?)",
            (username, email_enc, pw_hash, time.time()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()

    def get_user_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def user_public(self, row: sqlite3.Row) -> dict[str, Any]:
        email = ""
        try:
            email = self.crypto.decrypt(row["email_enc"])
        except Exception:
            email = ""
        return {
            "id": row["id"],
            "username": row["username"],
            "email": email,
            "created_at": row["created_at"],
        }

    def verify_login(self, login: str, password: str) -> Optional[sqlite3.Row]:
        """login = username or email."""
        login = login.strip()
        # try username
        row = self.get_user_by_username(login)
        if row and self.crypto.verify_password(row["password_hash"], password):
            return row
        # try email (scan decrypt — fine for small deployments)
        for r in self.conn.execute("SELECT * FROM users").fetchall():
            try:
                if self.crypto.decrypt(r["email_enc"]).lower() == login.lower():
                    if self.crypto.verify_password(r["password_hash"], password):
                        return r
            except Exception:
                continue
        return None

    # ---- sessions ----
    def create_session(self, user_id: int, token: str, ttl_sec: int = 86400 * 14) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?,?,?)",
            (token, user_id, time.time() + ttl_sec),
        )
        self.conn.commit()

    def user_for_token(self, token: str) -> Optional[sqlite3.Row]:
        row = self.conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > ?",
            (token, time.time()),
        ).fetchone()
        return row

    def delete_session(self, token: str) -> None:
        self.conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.conn.commit()

    # ---- friends ----
    def add_friend_request(self, user_id: int, friend_username: str) -> str:
        friend = self.get_user_by_username(friend_username)
        if not friend:
            raise ValueError("user not found")
        if friend["id"] == user_id:
            raise ValueError("cannot friend yourself")
        existing = self.conn.execute(
            "SELECT * FROM friendships WHERE user_id=? AND friend_id=?",
            (user_id, friend["id"]),
        ).fetchone()
        if existing:
            return existing["status"]
        # reverse pending?
        rev = self.conn.execute(
            "SELECT * FROM friendships WHERE user_id=? AND friend_id=?",
            (friend["id"], user_id),
        ).fetchone()
        if rev and rev["status"] == "pending":
            # auto-accept mutual
            self.conn.execute(
                "UPDATE friendships SET status='accepted' WHERE id=?",
                (rev["id"],),
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO friendships (user_id, friend_id, status, created_at) VALUES (?,?,?,?)",
                (user_id, friend["id"], "accepted", time.time()),
            )
            self.conn.commit()
            return "accepted"
        self.conn.execute(
            "INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?,?,?,?)",
            (user_id, friend["id"], "pending", time.time()),
        )
        self.conn.commit()
        return "pending"

    def accept_friend(self, user_id: int, from_username: str) -> None:
        other = self.get_user_by_username(from_username)
        if not other:
            raise ValueError("user not found")
        row = self.conn.execute(
            "SELECT * FROM friendships WHERE user_id=? AND friend_id=? AND status='pending'",
            (other["id"], user_id),
        ).fetchone()
        if not row:
            raise ValueError("no pending request from that user")
        self.conn.execute(
            "UPDATE friendships SET status='accepted' WHERE id=?",
            (row["id"],),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO friendships (user_id, friend_id, status, created_at) VALUES (?,?,?,?)",
            (user_id, other["id"], "accepted", time.time()),
        )
        self.conn.commit()

    def list_friends(self, user_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT u.id, u.username, f.status, f.user_id AS from_id, f.friend_id AS to_id,
                   p.online, p.hosting, p.lan_ips, p.video_port, p.ctrl_port, p.relay_ready, p.updated_at
            FROM friendships f
            JOIN users u ON (
                (f.user_id = ? AND u.id = f.friend_id) OR
                (f.friend_id = ? AND u.id = f.user_id AND f.status = 'pending')
            )
            LEFT JOIN presence p ON p.user_id = u.id
            WHERE f.user_id = ? OR (f.friend_id = ? AND f.status = 'pending')
            """,
            (user_id, user_id, user_id, user_id),
        ).fetchall()
        # Deduplicate and classify
        seen = set()
        out = []
        for r in rows:
            if r["id"] in seen or r["id"] == user_id:
                continue
            seen.add(r["id"])
            direction = "outgoing" if r["from_id"] == user_id else "incoming"
            out.append(
                {
                    "username": r["username"],
                    "status": r["status"],
                    "direction": direction if r["status"] == "pending" else "friend",
                    "online": bool(r["online"]) if r["online"] is not None else False,
                    "hosting": bool(r["hosting"]) if r["hosting"] is not None else False,
                    "lan_ips": r["lan_ips"] or "[]",
                    "video_port": r["video_port"],
                    "ctrl_port": r["ctrl_port"],
                    "relay_ready": bool(r["relay_ready"]) if r["relay_ready"] is not None else False,
                    "updated_at": r["updated_at"],
                }
            )
        return out

    # ---- presence ----
    def set_presence(
        self,
        user_id: int,
        *,
        online: bool,
        hosting: bool = False,
        lan_ips: str = "[]",
        video_port: Optional[int] = None,
        ctrl_port: Optional[int] = None,
        relay_ready: bool = False,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO presence (user_id, online, hosting, lan_ips, video_port, ctrl_port, relay_ready, updated_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
              online=excluded.online,
              hosting=excluded.hosting,
              lan_ips=excluded.lan_ips,
              video_port=excluded.video_port,
              ctrl_port=excluded.ctrl_port,
              relay_ready=excluded.relay_ready,
              updated_at=excluded.updated_at
            """,
            (
                user_id,
                1 if online else 0,
                1 if hosting else 0,
                lan_ips,
                video_port,
                ctrl_port,
                1 if relay_ready else 0,
                time.time(),
            ),
        )
        self.conn.commit()

    def get_presence(self, user_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM presence WHERE user_id=?", (user_id,)
        ).fetchone()
