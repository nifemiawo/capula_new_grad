from __future__ import annotations

import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from shared.src.email_utils import normalise_email


def create_signing_key(seed: bytes) -> Ed25519PrivateKey:
    """Create an Ed25519 signing key from a 32-byte seed."""
    return Ed25519PrivateKey.from_private_bytes(seed)


def build_envelope(signing_key: Ed25519PrivateKey, email: str, payload: bytes, nonce: int) -> dict:
    """Build a signed envelope containing the email, payload, nonce, and signature."""
    payload_b64 = base64.b64encode(payload).decode("ascii")
    data = {
        "email": normalise_email(email),
        "payload": payload_b64,
        "nonce": nonce,
    }
    message = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signing_key.sign(message)
    data["signature"] = base64.b64encode(signature).decode("ascii")
    return data


def build_unsigned_envelope(email: str, payload: bytes, nonce: int = 0) -> dict:
    """Build an unsigned envelope used for registration (signature omitted)."""
    payload_b64 = base64.b64encode(payload).decode("ascii")
    return {"email": normalise_email(email), "payload": payload_b64, "nonce": nonce}


def public_key_bytes_from_private(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
