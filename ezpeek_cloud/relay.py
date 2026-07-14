"""
TCP reverse-proxy / rendezvous for ezpeek.

Both peers dial OUT to greenbird (no inbound ports needed on home NAT):

  Host:   TCP connect → send "HOST <session_token>\\n"  then wait
  Viewer: TCP connect → send "VIEW <session_token> <friend_username>\\n"

Server pairs them and bi-directionally pipes bytes (control + optional video
streams can open separate connections with ROLE=control|video).

Protocol line 1 (ASCII):
  HOST <jwt>
  VIEW <jwt> <friend_username> [channel]
channel defaults to "control"; use "video" for the video tunnel.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logger = logging.getLogger("ezpeek.relay")


@dataclass
class WaitingHost:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    user_id: int
    username: str
    channel: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    peer_writer: Optional[asyncio.StreamWriter] = None
    peer_reader: Optional[asyncio.StreamReader] = None


class RelayHub:
    def __init__(self, auth_lookup):
        """
        auth_lookup(token: str) -> dict|None  with keys id, username
        """
        self.auth_lookup = auth_lookup
        # (host_user_id, channel) -> WaitingHost
        self._hosts: Dict[Tuple[int, str], WaitingHost] = {}
        self._lock = asyncio.Lock()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line:
                writer.close()
                return
            text = line.decode("utf-8", errors="ignore").strip()
            parts = text.split()
            if len(parts) < 2:
                writer.write(b"ERR bad handshake\n")
                await writer.drain()
                writer.close()
                return

            role = parts[0].upper()
            token = parts[1]
            user = self.auth_lookup(token)
            if not user:
                writer.write(b"ERR auth\n")
                await writer.drain()
                writer.close()
                return

            if role == "HOST":
                channel = parts[2] if len(parts) > 2 else "control"
                await self._host_side(user, channel, reader, writer, peer)
            elif role == "VIEW":
                if len(parts) < 3:
                    writer.write(b"ERR need friend username\n")
                    await writer.drain()
                    writer.close()
                    return
                friend = parts[2]
                channel = parts[3] if len(parts) > 3 else "control"
                await self._view_side(user, friend, channel, reader, writer, peer)
            else:
                writer.write(b"ERR role\n")
                await writer.drain()
                writer.close()
        except Exception as e:
            logger.exception("relay error from %s: %s", peer, e)
            try:
                writer.close()
            except Exception:
                pass

    async def _host_side(self, user, channel, reader, writer, peer):
        key = (int(user["id"]), channel)
        wh = WaitingHost(
            reader=reader,
            writer=writer,
            user_id=int(user["id"]),
            username=user["username"],
            channel=channel,
        )
        async with self._lock:
            old = self._hosts.get(key)
            if old:
                try:
                    old.writer.close()
                except Exception:
                    pass
            self._hosts[key] = wh

        writer.write(b"OK HOST waiting\n")
        await writer.drain()
        logger.info("HOST ready user=%s channel=%s peer=%s", user["username"], channel, peer)

        try:
            # Wait until a viewer pairs or connection drops
            while not wh.event.is_set():
                if reader.at_eof():
                    break
                try:
                    await asyncio.wait_for(wh.event.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
            if wh.peer_reader and wh.peer_writer:
                writer.write(b"OK PAIRED\n")
                await writer.drain()
                await _pipe_pair(reader, writer, wh.peer_reader, wh.peer_writer)
        finally:
            async with self._lock:
                if self._hosts.get(key) is wh:
                    del self._hosts[key]
            try:
                writer.close()
            except Exception:
                pass

    async def _view_side(self, user, friend_username, channel, reader, writer, peer):
        # Resolve friend user id via auth_lookup side channel — we need db.
        # auth_lookup only does tokens; friend resolution done in app via closure.
        friend = self.auth_lookup  # placeholder
        friend_row = getattr(self, "resolve_username", lambda u: None)(friend_username)
        if not friend_row:
            writer.write(b"ERR friend not found\n")
            await writer.drain()
            writer.close()
            return

        # Must be friends — checked in resolve if provided
        if getattr(self, "are_friends", None):
            if not self.are_friends(int(user["id"]), int(friend_row["id"])):
                writer.write(b"ERR not friends\n")
                await writer.drain()
                writer.close()
                return

        key = (int(friend_row["id"]), channel)
        async with self._lock:
            wh = self._hosts.get(key)

        if not wh:
            writer.write(b"ERR host not relay-ready\n")
            await writer.drain()
            writer.close()
            return

        writer.write(b"OK VIEW pairing\n")
        await writer.drain()
        wh.peer_reader = reader
        wh.peer_writer = writer
        wh.event.set()
        logger.info(
            "VIEW paired viewer=%s host=%s channel=%s peer=%s",
            user["username"],
            friend_username,
            channel,
            peer,
        )
        # Host side runs the pipe; just wait until closed
        try:
            while not reader.at_eof():
                await asyncio.sleep(0.5)
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def _pipe_pair(r1, w1, r2, w2):
    async def one_way(rin, wout):
        try:
            while True:
                data = await rin.read(65536)
                if not data:
                    break
                wout.write(data)
                await wout.drain()
        except Exception:
            pass
        try:
            wout.close()
        except Exception:
            pass

    await asyncio.gather(one_way(r1, w2), one_way(r2, w1))


async def start_relay_server(hub: RelayHub, host: str = "0.0.0.0", port: int = 8788):
    server = await asyncio.start_server(hub.handle, host, port)
    sockets = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    logger.info("Relay listening on %s", sockets)
    async with server:
        await server.serve_forever()
