# examples/generate_demo_keys.py
from src.crypto import generate_rsa_keypair, b64enc
from pathlib import Path
import os

KEY_DIR = Path("examples/demo_keys")
KEY_DIR.mkdir(parents=True, exist_ok=True)

priv_pem, pub_pem = generate_rsa_keypair()
(priv := KEY_DIR / "server_priv.pem").write_bytes(priv_pem)
(pub := KEY_DIR / "server_pub.pem").write_bytes(pub_pem)
print("Generated server RSA keypair in examples/demo_keys/")
print(f"Private: {priv}")
print(f"Public:  {pub}")
