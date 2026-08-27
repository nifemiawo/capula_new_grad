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
    signature_bytes = base64.b64decode(signature)
    data = {
        "email": normalise_email(email),
        "payload": payload,
        "nonce": nonce,
    }
    message = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False