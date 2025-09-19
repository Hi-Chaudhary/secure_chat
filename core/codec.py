import msgspec, uuid, time

class Message(msgspec.Struct):
    ver: int
    type: str
    msg_id: str
    sender: str
    to: list[str] | None
    ts: int
    payload: dict

def new_message(msg_type: str, sender: str, payload: dict, to: list[str] | None = None):
    return Message(
        ver=1,
        type=msg_type,
        msg_id=str(uuid.uuid4()),
        sender=sender,
        to=to,
        ts=int(time.time()),
        payload=payload
    )

def encode(msg: Message) -> bytes:
    return msgspec.json.encode(msg)

def decode(data: bytes) -> Message:
    return msgspec.json.decode(data, type=Message)
