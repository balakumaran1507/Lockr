#!/usr/bin/env python3
"""
crypto.py — Envelope encryption with post-quantum KEK.

Stack:
  DEK : AES-256-GCM  (per-secret data encryption key)
  KEK : FrodoKEM-1344-SHAKE via liboqs  (post-quantum key encapsulation)
        Falls back to X25519 + HKDF if liboqs not installed (dev only).

FrodoKEM-1344 is the most conservative PQ KEM:
  - Matrix LWE, no structured lattice assumptions
  - NIST security level 5 (≥ AES-256)
  - Larger keys/ciphertext than Kyber, but immune to algebraic attacks

Env vars:
  VAULT_MASTER_KEY   base64-encoded FrodoKEM secret key (from `lockr init`)
"""

import os
import secrets
import hashlib
import base64
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)

# ---------------------------------------------------------------------------
# PQ backend — FrodoKEM-1344-SHAKE via liboqs
# Falls back to X25519 in dev if liboqs C library not compiled in
# ---------------------------------------------------------------------------

_PQ_AVAILABLE = False
_KEM_ALG      = "FrodoKEM-1344-SHAKE"

try:
    import oqs  # type: ignore
    # Probe — will raise if liboqs .so not found
    with oqs.KeyEncapsulation(_KEM_ALG) as _probe:
        pass
    _PQ_AVAILABLE = True
except Exception:
    pass  # dev fallback active


@dataclass
class EncryptedBlob:
    """
    On-disk format for an encrypted secret.

    Fields:
      kem_ct   : KEM ciphertext (encapsulated shared secret)
      nonce    : AES-GCM nonce (12 bytes)
      ciphertext: AES-256-GCM encrypted secret value
      aad      : additional authenticated data (secret path, for binding)
    """
    kem_ct:     bytes
    nonce:      bytes
    ciphertext: bytes
    aad:        bytes

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed binary for storage."""
        def pack(b: bytes) -> bytes:
            return len(b).to_bytes(4, "big") + b

        return pack(self.kem_ct) + pack(self.nonce) + pack(self.ciphertext) + pack(self.aad)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedBlob":
        """Deserialize from length-prefixed binary."""
        offset = 0

        def unpack() -> bytes:
            nonlocal offset
            n = int.from_bytes(data[offset:offset + 4], "big")
            offset += 4
            chunk = data[offset:offset + n]
            offset += n
            return chunk

        return cls(
            kem_ct=unpack(),
            nonce=unpack(),
            ciphertext=unpack(),
            aad=unpack(),
        )


# ---------------------------------------------------------------------------
# KEK — FrodoKEM-1344 (PQ) or X25519 (dev fallback)
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new KEK keypair.

    Returns:
        (public_key_bytes, secret_key_bytes)
        Store secret_key in VAULT_MASTER_KEY env var (base64).
        public_key lives in .vault/vault.toml.
    """
    if _PQ_AVAILABLE:
        with oqs.KeyEncapsulation(_KEM_ALG) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk
    else:
        # Dev fallback — X25519
        sk_obj = X25519PrivateKey.generate()
        pk_obj = sk_obj.public_key()
        sk_bytes = sk_obj.private_bytes_raw()
        pk_bytes = pk_obj.public_bytes_raw()
        return pk_bytes, sk_bytes


def _encapsulate(pk_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    KEM encapsulate — produces (kem_ciphertext, shared_secret).
    shared_secret is used to derive the AES-256 DEK wrapper key.
    """
    if _PQ_AVAILABLE:
        with oqs.KeyEncapsulation(_KEM_ALG) as kem:
            kem_ct, shared_secret = kem.encap_secret(pk_bytes)
        return kem_ct, shared_secret
    else:
        # X25519 ephemeral DH
        ephemeral_sk = X25519PrivateKey.generate()
        ephemeral_pk = ephemeral_sk.public_key()
        peer_pk      = X25519PublicKey.from_public_bytes(pk_bytes)
        shared       = ephemeral_sk.exchange(peer_pk)
        kem_ct       = ephemeral_pk.public_bytes_raw()
        shared_secret = shared
        return kem_ct, shared_secret


def _decapsulate(sk_bytes: bytes, kem_ct: bytes) -> bytes:
    """
    KEM decapsulate — recovers shared_secret from kem_ciphertext + secret key.
    """
    if _PQ_AVAILABLE:
        with oqs.KeyEncapsulation(_KEM_ALG, sk_bytes) as kem:
            shared_secret = kem.decap_secret(kem_ct)
        return shared_secret
    else:
        sk_obj = X25519PrivateKey.from_private_bytes(sk_bytes)
        peer_pk = X25519PublicKey.from_public_bytes(kem_ct)
        return sk_obj.exchange(peer_pk)


def _derive_aes_key(shared_secret: bytes, aad: bytes) -> bytes:
    """HKDF-SHA256 — stretch shared secret into AES-256 key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"lockr-dek-wrap-v1" + aad,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _load_master_key() -> Tuple[bytes, bytes]:
    """Load KEK keypair from env. Raises if not set."""
    raw = os.environ.get("VAULT_MASTER_KEY")
    if not raw:
        raise RuntimeError(
            "VAULT_MASTER_KEY not set. Run `lockr init` to generate keys."
        )
    data = base64.b64decode(raw)
    # Format: 4-byte pk_len | pk | sk
    pk_len = int.from_bytes(data[:4], "big")
    pk = data[4:4 + pk_len]
    sk = data[4 + pk_len:]
    return pk, sk


def encrypt(plaintext: bytes, path: str) -> EncryptedBlob:
    """
    Encrypt a secret value.

    Args:
        plaintext : raw secret bytes
        path      : secret path e.g. "prod/db_password" (bound as AAD)

    Returns:
        EncryptedBlob ready for .vault/objects/ storage
    """
    pk, _ = _load_master_key()
    aad   = path.encode()

    # 1. KEM encapsulate → shared secret
    kem_ct, shared_secret = _encapsulate(pk)

    # 2. Derive per-secret AES key from shared secret
    aes_key = _derive_aes_key(shared_secret, aad)

    # 3. AES-256-GCM encrypt
    nonce      = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    return EncryptedBlob(
        kem_ct=kem_ct,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=aad,
    )


def decrypt(blob: EncryptedBlob) -> bytes:
    """
    Decrypt a secret blob.

    Args:
        blob: EncryptedBlob from .vault/objects/

    Returns:
        Raw plaintext bytes
    """
    _, sk = _load_master_key()

    # 1. KEM decapsulate → shared secret
    shared_secret = _decapsulate(sk, blob.kem_ct)

    # 2. Re-derive AES key
    aes_key = _derive_aes_key(shared_secret, blob.aad)

    # 3. AES-256-GCM decrypt (AAD binding verified here)
    return AESGCM(aes_key).decrypt(blob.nonce, blob.ciphertext, blob.aad)


def content_hash(data: bytes) -> str:
    """SHA-256 content hash — used as object filename (git-style)."""
    return hashlib.sha256(data).hexdigest()


def encode_master_key(pk: bytes, sk: bytes) -> str:
    """Serialize keypair to base64 for VAULT_MASTER_KEY env var."""
    packed = len(pk).to_bytes(4, "big") + pk + sk
    return base64.b64encode(packed).decode()


def is_pq_active() -> bool:
    """Returns True if FrodoKEM-1344 is active, False if using X25519 fallback."""
    return _PQ_AVAILABLE


def pq_status() -> str:
    if _PQ_AVAILABLE:
        return f"✅ Post-quantum: {_KEM_ALG} (NIST Level 5)"
    return "⚠️  PQ fallback: X25519 (dev mode — install liboqs for production)"
