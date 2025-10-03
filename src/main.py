import argparse, asyncio, json, os, sys
from typing import List
from .peer import Peer

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', type=str, help='JSON config file')
    ap.add_argument('--name', type=str, help='peer id/name')
    ap.add_argument('--port', type=int, help='listen port')
    ap.add_argument('--keys', type=str, help='keys dir (with priv.pem/pub.pem)')
    ap.add_argument('--peers', type=str, help='comma-separated ws://host:port entries', default="")
    return ap.parse_args()

def load_config(path: str):
    with open(path,"r") as f:
        return json.load(f)

async def run_interactive(peer: Peer):
    await peer.start()
    # simple REPL
    print("Commands: /list | /msg --to <id> --text <msg> | /group --text <msg> | /quit")
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            await asyncio.sleep(0.1)
            continue
        line = line.strip()
        if line == "/quit":
            print("bye"); os._exit(0)
        elif line.startswith("/list"):
            payload = {"type":"LIST_REQUEST","ts":0}
            await peer.handlers.send_application("*", payload)
        elif line.startswith("/msg"):
            # format: /msg --to bob --text hello there
            to = None; text = ""
            parts = line.split()
            if "--to" in parts:
                to = parts[parts.index("--to")+1]
            if "--text" in parts:
                idx = parts.index("--text")+1
                text = " ".join(parts[idx:])
            payload = {"type":"MSG_PRIVATE","to":to,"text":text}
            await peer.handlers.send_application(to, payload)
        elif line.startswith("/group"):
            # /group --text hi all
            text = ""
            parts = line.split()
            if "--text" in parts:
                idx = parts.index("--text")+1
                text = " ".join(parts[idx:])
            payload = {"type":"MSG_GROUP","text":text}
            await peer.handlers.send_application("*", payload)
        elif line.startswith("/sendfile"):
        # /sendfile --to bob --path C:\file.bin
            parts = line.split()
            to = parts[parts.index("--to")+1] if "--to" in parts else None
            path = " ".join(parts[parts.index("--path")+1:]) if "--path" in parts else None
            if not (to and path):
                print("usage: /sendfile --to <peer> --path <file>")
            else:
                await peer.handlers.send_file(to, path)

def main():
    args = parse_args()
    cfg = {}
    if args.config:
        cfg = load_config(args.config)
    name = args.name or cfg.get("name")
    port = args.port or int(cfg.get("port", 0))
    keys = args.keys or cfg.get("keys_dir")
    peers = args.peers or ",".join(cfg.get("peers", []))
    peers_list = [p.strip() for p in peers.split(",") if p.strip()]
    if not (name and port and keys is not None):
        print("Missing required args: --name --port --keys (or --config)"); sys.exit(1)
    p = Peer(name=name, port=port, keys_dir=keys, peers=peers_list)
    asyncio.run(run_interactive(p))

if __name__ == "__main__":
    main()
