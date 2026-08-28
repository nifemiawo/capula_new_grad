"""Client-side API operations for the password vault backup service."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client.src.sign import build_envelope, build_unsigned_envelope
from client.src.http_client import post_json, get_json
from client.src.nonce_store import load_and_increment_nonce


def register(base_url: str, email: str, public_key_bytes: bytes) -> dict:
    """Register a user (unsigned). Returns server JSON, including the mocked verification code."""
    payload = {"type": "register", "public_key": base64.b64encode(public_key_bytes).decode("ascii")}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    envelope = build_unsigned_envelope(email, payload_bytes, nonce=0)
    return post_json(f"{base_url.rstrip('/')}/register", envelope)


def verify(base_url: str, email: str, code: str) -> dict:
    return get_json(f"{base_url.rstrip('/')}/verify", {"email": email, "code": code})


def store(base_url: str, email: str, signing_key: Ed25519PrivateKey, vault_blob: bytes) -> dict:
    payload = {"type": "store", "vault": base64.b64encode(vault_blob).decode("ascii")}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = load_and_increment_nonce(email)
    envelope = build_envelope(signing_key, email, payload_bytes, nonce)
    return post_json(f"{base_url.rstrip('/')}/store", envelope)


def retrieve(base_url: str, email: str, signing_key: Ed25519PrivateKey) -> dict:
    payload = {"type": "retrieve"}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = load_and_increment_nonce(email)
    envelope = build_envelope(signing_key, email, payload_bytes, nonce)
    return post_json(f"{base_url.rstrip('/')}/retrieve", envelope)