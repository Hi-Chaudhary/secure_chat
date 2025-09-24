# src/crypto.py
"""
Secure RSA + AES-GCM hybrid helpers.

Usage:
- Server holds RSA keypair (private stays server-side).
- Client requests server public key, generates ephemeral AES key, encrypts AES key with server RSA public key.
- After handshake, symmetric AES-GCM used for confidentiality and authenticity.

This module only implements primitives and helper helpers; it does not perform network I/O.
"""

from __future__ import annotations
import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# ---- RSA key utilities ----

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Returns (private_pem, public_pem) as bytes.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def load_rsa_private_key(pem_data: bytes):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(pem_data, password=None)


def load_rsa_public_key(pem_data: bytes):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem_data)


def rsa_encrypt_with_public(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt_with_private(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ---- AES-GCM helpers ----

def generate_aes_key(length: int = 32) -> bytes:
    """Return a securely generated AES key (bytes). Default length=32 -> AES-256."""
    return secrets.token_bytes(length)


def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-GCM.
    Returns (nonce, ciphertext_with_tag) both bytes.
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce recommended for GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ct


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ---- helpers for safe encoding for JSON ----

def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64dec(data: str) -> bytes:
    return base64.b64decode(data.encode('ascii'))


# ---- higher-level hybrid flow helpers ----

def pack_handshake_payload(encrypted_key: bytes, server_pub_pem: bytes) -> dict:
    return {
        "enc_key": b64enc(encrypted_key),
        "server_pub": server_pub_pem.decode('utf-8')
    }


def unpack_handshake_payload(payload: dict) -> bytes:
    return b64dec(payload["enc_key"])
