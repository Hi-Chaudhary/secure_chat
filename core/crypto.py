from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_rsa_keypair(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def rsa_wrap_key(pubkey, aes_key: bytes) -> bytes:
    return pubkey.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_unwrap_key(privkey, wrapped: bytes) -> bytes:
    return privkey.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def aes_encrypt(aes_key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(aes_key).encrypt(nonce, plaintext, aad)

def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(aes_key).decrypt(nonce, ciphertext, aad)

def fresh_aes_key() -> bytes:
    return os.urandom(32)  # AES-256
