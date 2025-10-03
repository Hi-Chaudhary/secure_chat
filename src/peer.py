# src/peer.py
import asyncio, json, websockets
from typing import List, Dict, Any, Optional
from .utils import to_json
from .keymgr import load_priv, load_pub, pub_pem_b64
from .storage import State
from .handlers import Handlers
from .protocol import MAX_WS_FRAME

async def _safe_send(ws, data: str):
    try:
        await ws.send(data)
    except Exception:
        pass

class Peer:
    def __init__(self, name: str, port: int, keys_dir: str, peers: List[str]):
        self.name = name
        self.port = port
        self.keys_dir = keys_dir
        self.peers_urls = peers

        self.priv = load_priv(keys_dir)
        self.pub  = load_pub(keys_dir)
        self.pub_b64 = pub_pem_b64(self.pub)

        self.state = State(self_id=name)

        # connection maps
        self.out_conns: Dict[str, websockets.WebSocketClientProtocol] = {}
        self.in_conns:  Dict[str, websockets.WebSocketServerProtocol] = {}

        # temp_label -> real_name ; real_name -> label
        self.alias: Dict[str, str] = {}
        self.reverse_alias: Dict[str, str] = {}

        self.handlers = Handlers(
            state=self.state,
            privkey=self.priv,
            self_pub_b64=self.pub_b64,
            send_json_func=self._send_json,
            register_alias_func=self._register_alias
        )

        self.server = None

    async def start(self):
        # Enforce per-frame size at protocol layer too
        self.server = await websockets.serve(self._server_handler, "0.0.0.0", self.port, max_size=MAX_WS_FRAME)
        print(f"[{self.name}] listening ws://0.0.0.0:{self.port}")
        asyncio.create_task(self._connect_to_peers())

    async def _server_handler(self, ws: websockets.WebSocketServerProtocol):
        temp_id = f"in-{id(ws)}"
        self.in_conns[temp_id] = ws
        try:
            await self.handlers.on_open_connection(temp_id)
            async for msg in ws:
                await self.handlers.on_message(msg, temp_id)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.in_conns.pop(temp_id, None)
            real = self.alias.pop(temp_id, None)
            if real:
                self.reverse_alias.pop(real, None)

    async def _connect_to_peers(self):
        await asyncio.sleep(0.2)
        for url in self.peers_urls:
            asyncio.create_task(self._dial_peer(url))

    async def _dial_peer(self, url: str):
        temp_id = url.split("//")[-1]  # e.g., localhost:9002
        while True:
            try:
                ws = await websockets.connect(url, max_size=MAX_WS_FRAME)
                self.out_conns[temp_id] = ws
                print(f"[{self.name}] connected -> {temp_id}")
                await self.handlers.on_open_connection(temp_id)
                async for msg in ws:
                    await self.handlers.on_message(msg, temp_id)
            except Exception as e:
                print(f"[{self.name}] connect error {url}: {e}; retrying in 2s")
                await asyncio.sleep(2)
            finally:
                self.out_conns.pop(temp_id, None)
                real = self.alias.pop(temp_id, None)
                if real:
                    self.reverse_alias.pop(real, None)

    def _register_alias(self, temp_label: str, real_name: str):
        self.alias[temp_label] = real_name
        if temp_label in self.out_conns or temp_label in self.in_conns:
            self.reverse_alias[real_name] = temp_label

    async def _send_json(self, to_id: Optional[str], obj: Dict[str, Any]):
        data = to_json(obj)

        if to_id is None or to_id == "*":
            for ws in list(self.out_conns.values()):
                await _safe_send(ws, data)
            for ws in list(self.in_conns.values()):
                await _safe_send(ws, data)
            return

        label = self.reverse_alias.get(to_id)
        if label:
            ws = self.out_conns.get(label) or self.in_conns.get(label)
            if ws:
                await _safe_send(ws, data)
                return

        # fallback broadcast (only intended peer will accept/decrypt)
        for ws in list(self.out_conns.values()):
            await _safe_send(ws, data)
        for ws in list(self.in_conns.values()):
            await _safe_send(ws, data)
