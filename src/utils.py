# src/utils.py
from __future__ import annotations
import logging
import pathlib
import os

LOG = logging.getLogger("chat")
LOG.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(formatter)
LOG.addHandler(ch)


def ensure_dir(path: str):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def safe_filename(s: str) -> str:
    # very conservative sanitization for secure baseline
    return "".join(c for c in s if c.isalnum() or c in ("-", "_", "."))
