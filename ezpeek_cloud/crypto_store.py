"""
At-rest encryption helpers for ezpeek cloud.

- Passwords: Argon2id hashes (not reversible — correct for auth)
- Email (and other secrets): AES-256-GCM
- Master AES key stored on disk (mode 0600); optional RSA wrap for key export

The SQLite file itself lives on disk; sensitive columns are ciphertext.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


class CryptoBox:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.aes_key_path = self.data_dir / "master.aes"
        self.rsa_priv_path = self.data_dir / "master_rsa.pem"
        self.rsa_pub_path = self.data_dir / "master_rsa.pub.pem"
        self._aes: Optional[bytes] = None
        self._ensure_keys()

    def _ensure_keys(self) -> None:
        if not self.aes_key_path.exists():
            key = AESGCM.generate_key(bit_length=256)
            self.aes_key_path.write_bytes(key)
            os.chmod(self.aes_key_path, 0o600)
        self._aes = self.aes_key_path.read_bytes()

        if not self.rsa_priv_path.exists():
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            priv_pem = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.rsa_priv_path.write_bytes(priv_pem)
            self.rsa_pub_path.write_bytes(pub_pem)
            os.chmod(self.rsa_priv_path, 0o600)
            os.chmod(self.rsa_pub_path, 0o644)

            # Wrap AES key with RSA for recovery/export
            wrapped = private.public_key().encrypt(
                self._aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            (self.data_dir / "master.aes.rsa").write_bytes(wrapped)
            os.chmod(self.data_dir / "master.aes.rsa", 0o600)

    def encrypt(self, plaintext: str) -> bytes:
        assert self._aes is not None
        aes = AESGCM(self._aes)
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ct

    def decrypt(self, blob: bytes) -> str:
        assert self._aes is not None
        aes = AESGCM(self._aes)
        nonce, ct = blob[:12], blob[12:]
        return aes.decrypt(nonce, ct, None).decode("utf-8")

    @staticmethod
    def hash_password(password: str) -> str:
        return ph.hash(password)

    @staticmethod
    def verify_password(password_hash: str, password: str) -> bool:
        try:
            return ph.verify(password_hash, password)
        except VerifyMismatchError:
            return False
