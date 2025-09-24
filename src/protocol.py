# src/protocol.py
"""
SOCP-style JSON protocol helpers.

Envelope format (JSON):
{
  "type": "JOIN" | "LEAVE" | "PUBLIC_MSG" | "PRIVATE_MSG" | "FILE_OFFER" | "FILE_CHUNK" | "HANDSHAKE",
  "from": "<username>",
  "to": "<username or '*'>",    # '*' means public channel
  "payload": "<base64 or dict depending on encryption>",
  "meta": { ... optional metadata ... }
}

This module focuses on creating and validating the envelope only.
"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional

VALID_TYPES = {
    "JOIN", "LEAVE", "PUBLIC_MSG", "PRIVATE_MSG",
    "FILE_OFFER", "FILE_CHUNK", "HANDSHAKE", "ACK"
}


def make_envelope(msg_type: str, sender: str, recipient: str, payload: Any, meta: Optional[Dict[str, Any]] = None) -> str:
    if msg_type not in VALID_TYPES:
        raise ValueError(f"Invalid message type: {msg_type}")
    envelope = {
        "type": msg_type,
        "from": sender,
        "to": recipient,
        "payload": payload,
        "meta": meta or {}
    }
    return json.dumps(envelope)


def parse_envelope(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON") from e

    if "type" not in data or data["type"] not in VALID_TYPES:
        raise ValueError("Invalid or missing message type")
    if "from" not in data or not isinstance(data["from"], str):
        raise ValueError("Missing or invalid 'from' field")
    if "to" not in data or not isinstance(data["to"], str):
        raise ValueError("Missing or invalid 'to' field")
    if "payload" not in data:
        raise ValueError("Missing payload")
    # meta optional
    data.setdefault("meta", {})
    return data
