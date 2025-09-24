# src/server.py
"""
Secure WebSocket server (public channel).
- Handshake: client receives server public key; client sends encrypted AES key (encrypted with RSA).
- After handshake, messages are AES-GCM encrypted and carried in the envelope.payload as base64 fields.
"""

from __future__ import annotations
import asyncio
import json
import argparse
import logging
import websockets
from websockets.server import WebSocketServerProtocol
from typing import Dict, Any
from src.crypto import (
    load_rsa_private_key, load_rsa_public_key, rsa_decrypt_with_private,
    b64dec, b64enc, aesgcm_decrypt, aesgcm_encrypt, generate_rsa_keypair
)
from src.protocol import make_envelope, parse_envelope
from src.utils import LOG, read_file_bytes, write_file_bytes, ensure_dir, safe_filename
import os

KEY_DIR = "examples/demo_keys"
RSA_PRIV_FILE = os.path.join(KEY_DIR, "server_priv.pem")
RSA_PUB_FILE = os.path.join(KEY_DIR, "server_pub.pem")


class ClientState:
    def __init__(self, username: str, ws: WebSocketServerProtocol):
        self.username = username
        self.ws = ws
        self.aes_key: bytes | None = None  # set after handshake


class ChatServer:
    def __init__(self):
        self.clients: Dict[str, ClientState] = {}  # username -> state
        self.lock = asyncio.Lock()
        self.priv_key = None
        self.pub_pem = None

    async def load_or_generate_keys(self):
        ensure_dir(KEY_DIR)
        if not (os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE)):
            LOG.info("Demo keys not found, generating RSA keypair...")
            priv_pem, pub_pem = generate_rsa_keypair()
            write_file_bytes(RSA_PRIV_FILE, priv_pem)
            write_file_bytes(RSA_PUB_FILE, pub_pem)
        else:
            pub_pem = read_file_bytes(RSA_PUB_FILE)
            priv_pem = read_file_bytes(RSA_PRIV_FILE)

        self.priv_key = load_rsa_private_key(priv_pem)
        self.pub_pem = pub_pem  # bytes

    async def handler(self, ws: WebSocketServerProtocol, path: str):
        # 1) send HANDSHAKE info (server pubkey)
        await ws.send(json.dumps({"type": "HANDSHAKE_INIT", "server_pub": self.pub_pem.decode("utf-8")}))

        # wait for client to send encrypted aes key inside a HANDSHAKE envelope
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
        except Exception:
            LOG.warning("Handshake timeout or error")
            await ws.close()
            return

        try:
            env = parse_envelope(raw)
            if env["type"] != "HANDSHAKE":
                raise ValueError("Expected HANDSHAKE")
            payload = env["payload"]
            enc_key_b64 = payload.get("enc_key")
            username = env.get("from", "")
            if not username:
                raise ValueError("Missing username in handshake")
            enc_key = b64dec(enc_key_b64)
            aes_key = rsa_decrypt_with_private(self.priv_key, enc_key)
        except Exception as e:
            LOG.exception("Handshake failed: %s", e)
            await ws.close()
            return

        # register client
        state = ClientState(username=username, ws=ws)
        state.aes_key = aes_key
        async with self.lock:
            if username in self.clients:
                # username collision: reject
                await ws.send(json.dumps({"type": "ACK", "meta": {"status": "ERROR", "reason": "username taken"}}))
                await ws.close()
                return
            self.clients[username] = state
            LOG.info("Client joined: %s", username)
            # announce to others
            await self.broadcast_system(f"{username} has joined the public channel", exclude=username)

        try:
            await self.client_loop(state)
        finally:
            async with self.lock:
                self.clients.pop(username, None)
                LOG.info("Client left: %s", username)
                await self.broadcast_system(f"{username} has left the public channel", exclude=None)

    async def client_loop(self, state: ClientState):
        ws = state.ws
        while True:
            raw = await ws.recv()
            try:
                env = parse_envelope(raw)
            except Exception:
                LOG.warning("Invalid envelope received; ignoring")
                continue

            # decrypt payload using client's AES key
            payload = env["payload"]
            if not state.aes_key:
                LOG.warning("No AES key for client %s", state.username)
                continue

            try:
                nonce = b64dec(payload["nonce"])
                ciphertext = b64dec(payload["ciphertext"])
                aad = payload.get("aad")
                aadb = aad.encode("utf-8") if isinstance(aad, str) else None
                plaintext = aesgcm_decrypt(state.aes_key, nonce, ciphertext, aadb)
                inner = json.loads(plaintext.decode("utf-8"))
            except Exception:
                LOG.exception("Decrypt/parse failed for message from %s", state.username)
                continue

            mtype = inner.get("type")
            if mtype == "PUBLIC_MSG":
                text = inner.get("text", "")
                LOG.info("PUBLIC from %s: %s", state.username, text)
                await self.broadcast_message(state.username, inner)
            elif mtype == "PRIVATE_MSG":
                to = inner.get("to")
                await self.forward_private(state.username, to, inner)
            else:
                LOG.debug("Unhandled inner message type: %s", mtype)

    async def broadcast_message(self, sender: str, inner_payload: Dict[str, Any]):
        async with self.lock:
            for uname, st in list(self.clients.items()):
                try:
                    if st.aes_key is None:
                        continue
                    await self._send_encrypted(st, inner_payload, sender)
                except Exception:
                    LOG.exception("Error sending to %s", uname)

    async def forward_private(self, sender: str, to: str, inner_payload: Dict[str, Any]):
        async with self.lock:
            st = self.clients.get(to)
            if not st:
                LOG.info("Private target not found: %s", to)
                return
            await self._send_encrypted(st, inner_payload, sender)

    async def _send_encrypted(self, st: ClientState, inner_payload: Dict[str, Any], sender: str):
        # inner_payload is a dict (type, text, to, etc). We'll serialize and AES-GCM encrypt with recipient's key.
        plaintext = json.dumps(inner_payload).encode("utf-8")
        nonce, ct = aesgcm_encrypt(st.aes_key, plaintext, associated_data=None)
        payload = {"nonce": b64enc(nonce), "ciphertext": b64enc(ct)}
        envelope = make_envelope("PUBLIC_MSG" if inner_payload.get("type") == "PUBLIC_MSG" else "PRIVATE_MSG", sender, st.username, payload)
        await st.ws.send(envelope)

    async def broadcast_system(self, text: str, exclude: str | None = None):
        inner = {"type": "PUBLIC_MSG", "text": f"[SYSTEM] {text}"}
        async with self.lock:
            for uname, st in list(self.clients.items()):
                if uname == exclude:
                    continue
                await self._send_encrypted(st, inner, "SYSTEM")


async def main(port: int):
    server = ChatServer()
    await server.load_or_generate_keys()
    LOG.info("Starting server on port %d", port)
    async with websockets.serve(server.handler, "0.0.0.0", port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000, help="WebSocket server port")
    args = parser.parse_args()
    logging.getLogger("websockets").setLevel(logging.WARNING)
    asyncio.run(main(args.port))
