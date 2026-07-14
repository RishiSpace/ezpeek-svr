"""
EzPeek STUN/TURN Server

A lightweight STUN/TURN server implementation for NAT traversal.
Designed to be deployed on cloud infrastructure.

Usage:
    python -m server.stun_turn_server --host 0.0.0.0 --port 3478

For TURN (relay) functionality, credentials must be configured:
    python -m server.stun_turn_server --host 0.0.0.0 --port 3478 \\
        --turn --realm ezpeek.io --credentials users.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("stun_turn_server")

# Constants from RFC 5389/5766
STUN_MAGIC_COOKIE = 0x2112A442
STUN_HEADER_SIZE = 20

# Message Types
MSG_BINDING_REQUEST = 0x0001
MSG_BINDING_RESPONSE = 0x0101
MSG_BINDING_ERROR_RESPONSE = 0x0111
MSG_ALLOCATE_REQUEST = 0x0003
MSG_ALLOCATE_RESPONSE = 0x0103
MSG_ALLOCATE_ERROR_RESPONSE = 0x0113
MSG_REFRESH_REQUEST = 0x0004
MSG_REFRESH_RESPONSE = 0x0104
MSG_REFRESH_ERROR_RESPONSE = 0x0114
MSG_SEND_INDICATION = 0x0016
MSG_DATA_INDICATION = 0x0017
MSG_CREATE_PERMISSION_REQUEST = 0x0008
MSG_CREATE_PERMISSION_RESPONSE = 0x0108
MSG_CREATE_PERMISSION_ERROR_RESPONSE = 0x0118
MSG_CHANNEL_BIND_REQUEST = 0x0009
MSG_CHANNEL_BIND_RESPONSE = 0x0109

# Attribute Types
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
# TURN specific
ATTR_CHANNEL_NUMBER = 0x000C
ATTR_LIFETIME = 0x000D
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_REQUESTED_TRANSPORT = 0x0019

# Error Codes
ERR_TRY_ALTERNATE = 300
ERR_BAD_REQUEST = 400
ERR_UNAUTHORIZED = 401
ERR_FORBIDDEN = 403
ERR_UNKNOWN_ATTRIBUTE = 420
ERR_ALLOCATION_MISMATCH = 437
ERR_STALE_NONCE = 438
ERR_INSUFFICIENT_CAPACITY = 508

SOFTWARE_NAME = b"EzPeek STUN/TURN Server 1.0"
DEFAULT_ALLOCATION_LIFETIME = 600  # 10 minutes
MAX_ALLOCATION_LIFETIME = 3600  # 1 hour
NONCE_LIFETIME = 3600  # 1 hour
PERMISSION_LIFETIME = 300  # 5 minutes


@dataclass
class StunAttribute:
    type: int
    value: bytes


@dataclass
class StunMessage:
    message_type: int
    transaction_id: bytes
    attributes: List[StunAttribute] = field(default_factory=list)

    def get_attribute(self, attr_type: int) -> Optional[StunAttribute]:
        for attr in self.attributes:
            if attr.type == attr_type:
                return attr
        return None

    @classmethod
    def decode(cls, data: bytes) -> Optional["StunMessage"]:
        if len(data) < STUN_HEADER_SIZE:
            return None

        message_type, message_length, magic_cookie = struct.unpack(">HHI", data[:8])
        
        if magic_cookie != STUN_MAGIC_COOKIE:
            return None

        # Check first two bits are 0 (STUN indicator)
        if message_type & 0xC000:
            return None

        transaction_id = data[8:20]
        
        attributes = []
        offset = STUN_HEADER_SIZE
        while offset < STUN_HEADER_SIZE + message_length:
            if offset + 4 > len(data):
                break
            attr_type, attr_length = struct.unpack(">HH", data[offset:offset+4])
            offset += 4
            
            if offset + attr_length > len(data):
                break
            attr_value = data[offset:offset+attr_length]
            attributes.append(StunAttribute(attr_type, attr_value))
            
            # Padding to 4-byte boundary
            offset += attr_length
            offset += (4 - attr_length % 4) % 4

        return cls(message_type, transaction_id, attributes)

    def encode(self, key: Optional[bytes] = None) -> bytes:
        """Encode message with optional MESSAGE_INTEGRITY and FINGERPRINT."""
        attrs_data = b""
        
        for attr in self.attributes:
            value = attr.value
            padding = (4 - len(value) % 4) % 4
            attr_header = struct.pack(">HH", attr.type, len(value))
            attrs_data += attr_header + value + (b"\x00" * padding)

        # Calculate length (with MESSAGE_INTEGRITY and FINGERPRINT if key)
        message_length = len(attrs_data)
        if key:
            message_length += 24  # MESSAGE_INTEGRITY
            message_length += 8   # FINGERPRINT

        header = struct.pack(
            ">HHI",
            self.message_type,
            message_length,
            STUN_MAGIC_COOKIE
        ) + self.transaction_id

        message = header + attrs_data

        if key:
            # Update length for MESSAGE_INTEGRITY calculation
            msg_for_integrity = struct.pack(
                ">HHI",
                self.message_type,
                len(attrs_data) + 24,  # Length with MESSAGE_INTEGRITY
                STUN_MAGIC_COOKIE
            ) + self.transaction_id + attrs_data

            integrity = hmac.new(key, msg_for_integrity, hashlib.sha1).digest()
            integrity_attr = struct.pack(">HH", ATTR_MESSAGE_INTEGRITY, 20) + integrity
            message = header + attrs_data + integrity_attr

            # FINGERPRINT
            import binascii
            crc = binascii.crc32(message) ^ 0x5354554E
            fingerprint_attr = struct.pack(">HHI", ATTR_FINGERPRINT, 4, crc & 0xFFFFFFFF)
            message += fingerprint_attr

        return message


@dataclass
class Allocation:
    """Represents a TURN allocation."""
    client_addr: Tuple[str, int]
    relayed_addr: Tuple[str, int]
    transport: asyncio.DatagramTransport
    username: str
    realm: str
    created_at: float
    expires_at: float
    permissions: Dict[str, float] = field(default_factory=dict)  # peer_ip -> expires_at
    channels: Dict[int, Tuple[str, int]] = field(default_factory=dict)  # channel -> peer_addr


class CredentialStore:
    """Manages user credentials for TURN authentication."""

    def __init__(self, credentials_file: Optional[str] = None):
        self.credentials: Dict[str, str] = {}  # username -> password
        self._static_credentials: Dict[str, str] = {}
        
        if credentials_file and os.path.exists(credentials_file):
            self._load_credentials(credentials_file)

    def _load_credentials(self, path: str):
        try:
            with open(path) as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._static_credentials = data
                    logger.info(f"Loaded {len(data)} credentials from {path}")
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")

    def add_credential(self, username: str, password: str):
        """Add a credential."""
        self.credentials[username] = password

    def get_password(self, username: str) -> Optional[str]:
        """Get password for username."""
        return self._static_credentials.get(username) or self.credentials.get(username)

    def compute_key(self, username: str, realm: str) -> Optional[bytes]:
        """Compute long-term credential key."""
        password = self.get_password(username)
        if not password:
            return None
        credential = f"{username}:{realm}:{password}"
        return hashlib.md5(credential.encode()).digest()


class NonceManager:
    """Manages nonces for authentication."""

    def __init__(self, lifetime: int = NONCE_LIFETIME):
        self.lifetime = lifetime
        self._nonces: Dict[str, float] = {}  # nonce -> created_at

    def generate(self) -> bytes:
        """Generate a new nonce."""
        nonce = secrets.token_hex(16)
        self._nonces[nonce] = time.time()
        return nonce.encode()

    def validate(self, nonce: bytes) -> bool:
        """Check if nonce is valid."""
        nonce_str = nonce.decode() if isinstance(nonce, bytes) else nonce
        if nonce_str not in self._nonces:
            return False
        created_at = self._nonces[nonce_str]
        if time.time() - created_at > self.lifetime:
            del self._nonces[nonce_str]
            return False
        return True

    def cleanup(self):
        """Remove expired nonces."""
        now = time.time()
        expired = [n for n, t in self._nonces.items() if now - t > self.lifetime]
        for n in expired:
            del self._nonces[n]


class RelayProtocol(asyncio.DatagramProtocol):
    """Protocol for relayed UDP traffic."""

    def __init__(self, server: "StunTurnServer", allocation: Allocation):
        self.server = server
        self.allocation = allocation
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        if sock:
            addr = sock.getsockname()
            self.allocation.relayed_addr = addr
            logger.info(f"Relay created: {addr} for client {self.allocation.client_addr}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Forward data from peer to client via TURN Data Indication."""
        peer_ip = addr[0]
        
        # Check permission
        if peer_ip not in self.allocation.permissions:
            logger.debug(f"Dropped packet from {addr} - no permission")
            return
        
        if time.time() > self.allocation.permissions[peer_ip]:
            logger.debug(f"Dropped packet from {addr} - permission expired")
            return

        # Check for channel binding
        for channel, peer_addr in self.allocation.channels.items():
            if peer_addr == addr:
                # Send as ChannelData
                channel_data = struct.pack(">HH", channel, len(data)) + data
                # Pad to 4-byte boundary
                padding = (4 - len(data) % 4) % 4
                channel_data += b"\x00" * padding
                self.server.transport.sendto(channel_data, self.allocation.client_addr)
                return

        # Send as Data Indication
        self.server._send_data_indication(
            self.allocation.client_addr,
            addr,
            data
        )


class StunTurnServer:
    """STUN/TURN server implementation."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 3478,
        realm: str = "ezpeek.local",
        enable_turn: bool = False,
        credentials_file: Optional[str] = None,
        relay_ip: Optional[str] = None,
        relay_port_range: Tuple[int, int] = (49152, 65535),
    ):
        self.host = host
        self.port = port
        self.realm = realm
        self.enable_turn = enable_turn
        self.relay_ip = relay_ip
        self.relay_port_range = relay_port_range

        self.credentials = CredentialStore(credentials_file)
        self.nonces = NonceManager()
        self.allocations: Dict[Tuple[str, int], Allocation] = {}
        
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._next_relay_port = relay_port_range[0]

    def _get_next_relay_port(self) -> int:
        """Get next available relay port."""
        port = self._next_relay_port
        self._next_relay_port += 1
        if self._next_relay_port > self.relay_port_range[1]:
            self._next_relay_port = self.relay_port_range[0]
        return port

    async def start(self):
        """Start the STUN/TURN server."""
        loop = asyncio.get_event_loop()
        
        # Create UDP endpoint
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: StunServerProtocol(self),
            local_addr=(self.host, self.port)
        )
        
        self._running = True
        logger.info(f"STUN/TURN server started on {self.host}:{self.port}")
        logger.info(f"TURN enabled: {self.enable_turn}, Realm: {self.realm}")

        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop the server."""
        self._running = False
        if self.transport:
            self.transport.close()
        
        # Close all allocations
        for alloc in list(self.allocations.values()):
            if alloc.transport:
                alloc.transport.close()
        self.allocations.clear()
        
        logger.info("STUN/TURN server stopped")

    async def _cleanup_loop(self):
        """Periodically clean up expired allocations and nonces."""
        while self._running:
            await asyncio.sleep(60)
            self._cleanup_expired()

    def _cleanup_expired(self):
        """Remove expired allocations and permissions."""
        now = time.time()
        
        # Clean up nonces
        self.nonces.cleanup()
        
        # Clean up allocations
        expired = []
        for addr, alloc in self.allocations.items():
            if now > alloc.expires_at:
                expired.append(addr)
            else:
                # Clean up expired permissions
                expired_perms = [ip for ip, exp in alloc.permissions.items() if now > exp]
                for ip in expired_perms:
                    del alloc.permissions[ip]

        for addr in expired:
            alloc = self.allocations.pop(addr)
            if alloc.transport:
                alloc.transport.close()
            logger.info(f"Allocation expired for {addr}")

    def handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming STUN/TURN message."""
        # Check for ChannelData (first two bits are 01)
        if len(data) >= 4 and (data[0] & 0xC0) == 0x40:
            self._handle_channel_data(data, addr)
            return

        msg = StunMessage.decode(data)
        if not msg:
            logger.debug(f"Invalid STUN message from {addr}")
            return

        logger.debug(f"Received {hex(msg.message_type)} from {addr}")

        # Route by message type
        if msg.message_type == MSG_BINDING_REQUEST:
            self._handle_binding_request(msg, addr)
        elif msg.message_type == MSG_ALLOCATE_REQUEST:
            self._handle_allocate_request(msg, addr)
        elif msg.message_type == MSG_REFRESH_REQUEST:
            self._handle_refresh_request(msg, addr)
        elif msg.message_type == MSG_CREATE_PERMISSION_REQUEST:
            self._handle_create_permission_request(msg, addr)
        elif msg.message_type == MSG_CHANNEL_BIND_REQUEST:
            self._handle_channel_bind_request(msg, addr)
        elif msg.message_type == MSG_SEND_INDICATION:
            self._handle_send_indication(msg, addr)

    def _handle_binding_request(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle STUN Binding Request - return XOR-MAPPED-ADDRESS."""
        response = StunMessage(
            message_type=MSG_BINDING_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[]
        )

        # Add XOR-MAPPED-ADDRESS
        xor_addr = self._encode_xor_address(addr, msg.transaction_id)
        response.attributes.append(StunAttribute(ATTR_XOR_MAPPED_ADDRESS, xor_addr))
        response.attributes.append(StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME))

        self.transport.sendto(response.encode(), addr)
        logger.debug(f"Binding response sent to {addr}")

    def _handle_allocate_request(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle TURN Allocate Request."""
        if not self.enable_turn:
            self._send_error(msg, addr, ERR_FORBIDDEN, "TURN not enabled")
            return

        # Check for existing allocation
        if addr in self.allocations:
            self._send_error(msg, addr, ERR_ALLOCATION_MISMATCH, "Allocation exists")
            return

        # Check authentication
        username_attr = msg.get_attribute(ATTR_USERNAME)
        realm_attr = msg.get_attribute(ATTR_REALM)
        nonce_attr = msg.get_attribute(ATTR_NONCE)
        integrity_attr = msg.get_attribute(ATTR_MESSAGE_INTEGRITY)

        if not all([username_attr, realm_attr, nonce_attr, integrity_attr]):
            # Send 401 with nonce
            self._send_auth_challenge(msg, addr)
            return

        username = username_attr.value.decode()
        realm = realm_attr.value.decode()
        nonce = nonce_attr.value

        # Validate nonce
        if not self.nonces.validate(nonce):
            self._send_error(msg, addr, ERR_STALE_NONCE, "Stale nonce")
            return

        # Validate credentials
        key = self.credentials.compute_key(username, realm)
        if not key:
            self._send_error(msg, addr, ERR_UNAUTHORIZED, "Invalid credentials")
            return

        # TODO: Verify MESSAGE_INTEGRITY

        # Check requested transport (must be UDP = 17)
        transport_attr = msg.get_attribute(ATTR_REQUESTED_TRANSPORT)
        if not transport_attr or struct.unpack(">I", transport_attr.value[:4])[0] != 17:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Only UDP supported")
            return

        # Create allocation
        asyncio.create_task(self._create_allocation(msg, addr, username, key))

    async def _create_allocation(self, msg: StunMessage, addr: Tuple[str, int], 
                                  username: str, key: bytes):
        """Create a new TURN allocation."""
        loop = asyncio.get_event_loop()
        
        # Find available port for relay
        relay_port = self._get_next_relay_port()
        relay_ip = self.relay_ip or self.host
        if relay_ip == "0.0.0.0":
            relay_ip = self._get_public_ip()

        allocation = Allocation(
            client_addr=addr,
            relayed_addr=(relay_ip, relay_port),
            transport=None,
            username=username,
            realm=self.realm,
            created_at=time.time(),
            expires_at=time.time() + DEFAULT_ALLOCATION_LIFETIME,
        )

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: RelayProtocol(self, allocation),
                local_addr=("0.0.0.0", relay_port)
            )
            allocation.transport = transport
            
            # Update relayed address from actual socket
            sock = transport.get_extra_info("socket")
            if sock:
                allocation.relayed_addr = (relay_ip, sock.getsockname()[1])

        except OSError as e:
            logger.error(f"Failed to create relay: {e}")
            self._send_error(msg, addr, ERR_INSUFFICIENT_CAPACITY, "Cannot allocate relay")
            return

        self.allocations[addr] = allocation

        # Send success response
        response = StunMessage(
            message_type=MSG_ALLOCATE_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[]
        )

        # XOR-RELAYED-ADDRESS
        xor_relayed = self._encode_xor_address(allocation.relayed_addr, msg.transaction_id)
        response.attributes.append(StunAttribute(ATTR_XOR_RELAYED_ADDRESS, xor_relayed))

        # XOR-MAPPED-ADDRESS
        xor_mapped = self._encode_xor_address(addr, msg.transaction_id)
        response.attributes.append(StunAttribute(ATTR_XOR_MAPPED_ADDRESS, xor_mapped))

        # LIFETIME
        lifetime = int(allocation.expires_at - allocation.created_at)
        response.attributes.append(StunAttribute(ATTR_LIFETIME, struct.pack(">I", lifetime)))

        response.attributes.append(StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME))

        self.transport.sendto(response.encode(key), addr)
        logger.info(f"Allocation created for {addr} -> {allocation.relayed_addr}")

    def _handle_refresh_request(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle TURN Refresh Request."""
        alloc = self.allocations.get(addr)
        if not alloc:
            self._send_error(msg, addr, ERR_ALLOCATION_MISMATCH, "No allocation")
            return

        # Check authentication
        key = self.credentials.compute_key(alloc.username, self.realm)
        if not key:
            self._send_auth_challenge(msg, addr)
            return

        # Get requested lifetime
        lifetime_attr = msg.get_attribute(ATTR_LIFETIME)
        if lifetime_attr:
            requested_lifetime = struct.unpack(">I", lifetime_attr.value[:4])[0]
        else:
            requested_lifetime = DEFAULT_ALLOCATION_LIFETIME

        # Lifetime of 0 means delete
        if requested_lifetime == 0:
            if alloc.transport:
                alloc.transport.close()
            del self.allocations[addr]
            logger.info(f"Allocation deleted for {addr}")
            requested_lifetime = 0
        else:
            requested_lifetime = min(requested_lifetime, MAX_ALLOCATION_LIFETIME)
            alloc.expires_at = time.time() + requested_lifetime

        # Send response
        response = StunMessage(
            message_type=MSG_REFRESH_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[
                StunAttribute(ATTR_LIFETIME, struct.pack(">I", requested_lifetime)),
                StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME),
            ]
        )

        self.transport.sendto(response.encode(key), addr)

    def _handle_create_permission_request(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle TURN CreatePermission Request."""
        alloc = self.allocations.get(addr)
        if not alloc:
            self._send_error(msg, addr, ERR_ALLOCATION_MISMATCH, "No allocation")
            return

        key = self.credentials.compute_key(alloc.username, self.realm)
        if not key:
            self._send_auth_challenge(msg, addr)
            return

        # Get peer address
        peer_attr = msg.get_attribute(ATTR_XOR_PEER_ADDRESS)
        if not peer_attr:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Missing peer address")
            return

        peer_addr = self._decode_xor_address(peer_attr.value, msg.transaction_id)
        if not peer_addr:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Invalid peer address")
            return

        # Create permission (just IP, not port)
        peer_ip = peer_addr[0]
        alloc.permissions[peer_ip] = time.time() + PERMISSION_LIFETIME
        logger.info(f"Permission created for {addr} -> {peer_ip}")

        # Send response
        response = StunMessage(
            message_type=MSG_CREATE_PERMISSION_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME)]
        )

        self.transport.sendto(response.encode(key), addr)

    def _handle_channel_bind_request(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle TURN ChannelBind Request."""
        alloc = self.allocations.get(addr)
        if not alloc:
            self._send_error(msg, addr, ERR_ALLOCATION_MISMATCH, "No allocation")
            return

        key = self.credentials.compute_key(alloc.username, self.realm)
        if not key:
            self._send_auth_challenge(msg, addr)
            return

        # Get channel number
        channel_attr = msg.get_attribute(ATTR_CHANNEL_NUMBER)
        if not channel_attr or len(channel_attr.value) < 4:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Missing channel number")
            return

        channel = struct.unpack(">H", channel_attr.value[:2])[0]
        if channel < 0x4000 or channel > 0x7FFE:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Invalid channel number")
            return

        # Get peer address
        peer_attr = msg.get_attribute(ATTR_XOR_PEER_ADDRESS)
        if not peer_attr:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Missing peer address")
            return

        peer_addr = self._decode_xor_address(peer_attr.value, msg.transaction_id)
        if not peer_addr:
            self._send_error(msg, addr, ERR_BAD_REQUEST, "Invalid peer address")
            return

        # Bind channel
        alloc.channels[channel] = peer_addr
        # Also create permission
        alloc.permissions[peer_addr[0]] = time.time() + PERMISSION_LIFETIME
        
        logger.info(f"Channel {channel} bound for {addr} -> {peer_addr}")

        # Send response
        response = StunMessage(
            message_type=MSG_CHANNEL_BIND_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME)]
        )

        self.transport.sendto(response.encode(key), addr)

    def _handle_send_indication(self, msg: StunMessage, addr: Tuple[str, int]):
        """Handle TURN Send Indication - relay data to peer."""
        alloc = self.allocations.get(addr)
        if not alloc:
            return

        # Get peer address
        peer_attr = msg.get_attribute(ATTR_XOR_PEER_ADDRESS)
        data_attr = msg.get_attribute(ATTR_DATA)
        
        if not peer_attr or not data_attr:
            return

        peer_addr = self._decode_xor_address(peer_attr.value, msg.transaction_id)
        if not peer_addr:
            return

        # Check permission
        if peer_addr[0] not in alloc.permissions:
            return

        # Send data through relay
        if alloc.transport:
            alloc.transport.sendto(data_attr.value, peer_addr)

    def _handle_channel_data(self, data: bytes, addr: Tuple[str, int]):
        """Handle ChannelData message."""
        alloc = self.allocations.get(addr)
        if not alloc:
            return

        channel = struct.unpack(">H", data[:2])[0]
        length = struct.unpack(">H", data[2:4])[0]
        payload = data[4:4+length]

        # Find peer for channel
        peer_addr = alloc.channels.get(channel)
        if not peer_addr:
            return

        # Send to peer through relay
        if alloc.transport:
            alloc.transport.sendto(payload, peer_addr)

    def _send_data_indication(self, client_addr: Tuple[str, int], 
                               peer_addr: Tuple[str, int], data: bytes):
        """Send Data Indication to client."""
        msg = StunMessage(
            message_type=MSG_DATA_INDICATION,
            transaction_id=secrets.token_bytes(12),
            attributes=[]
        )

        # XOR-PEER-ADDRESS
        xor_peer = self._encode_xor_address(peer_addr, msg.transaction_id)
        msg.attributes.append(StunAttribute(ATTR_XOR_PEER_ADDRESS, xor_peer))

        # DATA
        msg.attributes.append(StunAttribute(ATTR_DATA, data))

        self.transport.sendto(msg.encode(), client_addr)

    def _send_auth_challenge(self, msg: StunMessage, addr: Tuple[str, int]):
        """Send 401 Unauthorized with realm and nonce."""
        nonce = self.nonces.generate()
        
        response = StunMessage(
            message_type=MSG_ALLOCATE_ERROR_RESPONSE,
            transaction_id=msg.transaction_id,
            attributes=[
                StunAttribute(ATTR_ERROR_CODE, self._encode_error(ERR_UNAUTHORIZED, "Unauthorized")),
                StunAttribute(ATTR_REALM, self.realm.encode()),
                StunAttribute(ATTR_NONCE, nonce),
                StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME),
            ]
        )

        self.transport.sendto(response.encode(), addr)

    def _send_error(self, msg: StunMessage, addr: Tuple[str, int], 
                    code: int, reason: str):
        """Send error response."""
        # Determine error response type based on request type
        response_type = msg.message_type | 0x0110  # Set error class bits
        
        response = StunMessage(
            message_type=response_type,
            transaction_id=msg.transaction_id,
            attributes=[
                StunAttribute(ATTR_ERROR_CODE, self._encode_error(code, reason)),
                StunAttribute(ATTR_SOFTWARE, SOFTWARE_NAME),
            ]
        )

        self.transport.sendto(response.encode(), addr)

    def _encode_error(self, code: int, reason: str) -> bytes:
        """Encode ERROR-CODE attribute value."""
        error_class = code // 100
        error_number = code % 100
        reason_bytes = reason.encode()[:127]  # Max 127 chars
        return struct.pack(">xxBB", error_class, error_number) + reason_bytes

    def _encode_xor_address(self, addr: Tuple[str, int], transaction_id: bytes) -> bytes:
        """Encode XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS."""
        ip, port = addr
        
        # XOR port with magic cookie high 16 bits
        xor_port = port ^ (STUN_MAGIC_COOKIE >> 16)
        
        # IPv4
        ip_bytes = socket.inet_aton(ip)
        ip_int = struct.unpack(">I", ip_bytes)[0]
        xor_ip = ip_int ^ STUN_MAGIC_COOKIE
        
        return struct.pack(">xBHI", 0x01, xor_port, xor_ip)

    def _decode_xor_address(self, data: bytes, transaction_id: bytes) -> Optional[Tuple[str, int]]:
        """Decode XOR address attribute."""
        if len(data) < 8:
            return None

        family = data[1]
        xor_port = struct.unpack(">H", data[2:4])[0]
        port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)

        if family == 0x01:  # IPv4
            xor_ip = struct.unpack(">I", data[4:8])[0]
            ip_int = xor_ip ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack(">I", ip_int))
            return (ip, port)

        return None

    def _get_public_ip(self) -> str:
        """Try to determine public IP."""
        # Try to get from environment
        public_ip = os.environ.get("PUBLIC_IP")
        if public_ip:
            return public_ip
        
        # Fallback to hostname resolution
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except:
            return "127.0.0.1"


class StunServerProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol for STUN/TURN server."""

    def __init__(self, server: StunTurnServer):
        self.server = server

    def connection_made(self, transport):
        self.server.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.server.handle_message(data, addr)


async def main():
    parser = argparse.ArgumentParser(description="EzPeek STUN/TURN Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=3478, help="Listen port")
    parser.add_argument("--realm", default="ezpeek.local", help="TURN realm")
    parser.add_argument("--turn", action="store_true", help="Enable TURN relay")
    parser.add_argument("--credentials", help="JSON file with username:password pairs")
    parser.add_argument("--relay-ip", help="Public IP for relay addresses")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    server = StunTurnServer(
        host=args.host,
        port=args.port,
        realm=args.realm,
        enable_turn=args.turn,
        credentials_file=args.credentials,
        relay_ip=args.relay_ip,
    )

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    
    def shutdown():
        logger.info("Shutting down...")
        asyncio.create_task(server.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    await server.start()

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
