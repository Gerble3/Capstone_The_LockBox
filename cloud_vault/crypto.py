 
from __future__ import annotations
import os, json
from dataclasses import dataclass
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import Type, hash_secret_raw

# this file contains cryptographic functions and classes for the vault application

#  KDF (Argon2id) 
@dataclass
class KDFParams:
    time_cost: int = 2       # iterations
    memory_cost: int = 256 * 1024  # KiB (256 MiB)
    parallelism: int = 1
    salt_len: int = 16
    key_len: int = 32

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @staticmethod
    def from_json(s: str) -> 'KDFParams':
        d = json.loads(s); return KDFParams(**d)


def derive_master_key(password: str, salt: bytes, params: KDFParams) -> bytes:
    # Returns 32-byte key using Argon2id
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.key_len,
        type=Type.ID
    )

#  AEAD (AES-GCM) 
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

# Utility: hostname normalization for dedupe/indexing (optional here)
def normalize_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""
