from .crypto import generate_rsa_keypair, rsa_wrap_key, rsa_unwrap_key, fresh_aes_key

class Session:
    def __init__(self, aes_key: bytes):
        self.key = aes_key
        self.send_counter = 0
        self.recv_counter = 0

def perform_handshake(initiator_priv, responder_pub):
    """Initiator generates AES key, wraps it for responder."""
    k_session = fresh_aes_key()
    wrapped = rsa_wrap_key(responder_pub, k_session)
    return Session(k_session), wrapped

def accept_handshake(responder_priv, wrapped: bytes):
    k_session = rsa_unwrap_key(responder_priv, wrapped)
    return Session(k_session)
