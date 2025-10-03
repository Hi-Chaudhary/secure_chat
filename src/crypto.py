import os
from typing import Tuple, Dict, Any
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from .utils import b64e, b64d
from Crypto.Random import get_random_bytes

# AES-GCM helpers
def aes_encrypt(key: bytes, plaintext: bytes) -> Dict[str,str]:
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {"iv": b64e(iv), "ct": b64e(ct), "tag": b64e(tag)}

def aes_decrypt(key: bytes, iv_b64: str, ct_b64: str, tag_b64: str) -> bytes:
    iv = b64d(iv_b64); ct = b64d(ct_b64); tag = b64d(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

# RSA-OAEP wrap/unwrap AES key
def rsa_wrap_key(peer_pub_pem_b64: str, aes_key: bytes) -> str:
    pub = RSA.import_key(b64d(peer_pub_pem_b64))
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return b64e(cipher.encrypt(aes_key))

def rsa_unwrap_key(priv: RSA.RsaKey, wrapped_b64: str) -> bytes:
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(b64d(wrapped_b64))

# Sign/verify RSA-PSS over SHA256
def sign(priv: RSA.RsaKey, data: bytes) -> str:
    h = SHA256.new(data)
    signature = pss.new(priv).sign(h)
    return b64e(signature)

def verify(pub: RSA.RsaKey, data: bytes, sig_b64: str) -> bool:
    h = SHA256.new(data)
    try:
        pss.new(pub).verify(h, b64d(sig_b64))
        return True
    except (ValueError, TypeError):
        return False

# hybrid encrypt plaintext using AES key; RSA-wrap the key for the peer
def hybrid_encrypt(plaintext: bytes, aes_key: bytes) -> Dict[str,str]:
    enc = aes_encrypt(aes_key, plaintext)
    return enc

def gen_aes_key() -> bytes:
    return get_random_bytes(32)
