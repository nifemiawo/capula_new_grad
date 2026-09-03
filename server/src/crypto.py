"""Server-side signature verification.

Reconstructs the same {email, payload, nonce} JSON used by the
client's sign.py  and checks it against the caller's stored Ed25519 public key. Deliberately returns a plain bool rather
than raising, so callers can turn a failed check into whatever HTTP response
is appropriate without catching a cryptography-specific exception.
"""

import base64
import binascii
import json

import base64
import binascii
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from shared.src.email_utils import normalise_email


def verify_signature(public_key: bytes, email: str, payload: str, nonce:int, signature:str) -> bool:
    """
    Verify the signature of a signed envelope.
    """
    data = {
        "email": normalise_email(email),
        "payload": payload,
        "nonce": nonce,
    }
    message = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

    try:
        signature_bytes = base64.b64decode(signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False