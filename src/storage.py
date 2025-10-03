from dataclasses import dataclass, field
from typing import Dict, Optional
from Crypto.PublicKey import RSA

@dataclass
class PeerInfo:
    peer_id: str
    pubkey_pem_b64: str
    fingerprint: str

@dataclass
class Session:
    aes_key: bytes

@dataclass
class State:
    self_id: str
    peers: Dict[str, PeerInfo] = field(default_factory=dict)
    sessions: Dict[str, Session] = field(default_factory=dict)

    def add_peer(self, info: PeerInfo):
        self.peers[info.peer_id] = info

    def get_peer(self, peer_id: str) -> Optional[PeerInfo]:
        return self.peers.get(peer_id)

    def add_session(self, peer_id: str, sess: Session):
        self.sessions[peer_id] = sess

    def get_session(self, peer_id: str) -> Optional[Session]:
        return self.sessions.get(peer_id)

    def list_peers(self):
        return list(self.peers.values())
