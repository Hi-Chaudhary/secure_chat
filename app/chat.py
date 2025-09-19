import asyncio, websockets
from core.codec import new_message, encode, decode

async def handler(ws, path):
    async for msg in ws:
        m = decode(msg.encode())
        print(f"[{m.ts}] {m.sender}: {m.payload}")

async def run_node(host="0.0.0.0", port=8765):
    async with websockets.serve(handler, host, port):
        print(f"Listening on ws://{host}:{port}")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(run_node())
