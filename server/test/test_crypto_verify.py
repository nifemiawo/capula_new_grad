import base64
import json
import sys
import unittest
from pathlib import Path

# ensure package imports resolve
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from server.src.crypto import verify_signature


class CryptoVerifyTests(unittest.TestCase):
    def test_verify_signature_valid_and_invalid(self) -> None:
        # create keypair
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        email = "Alice@Example.com"
        payload = base64.b64encode(b"{}").decode("ascii")
        nonce = 7

        data = {"email": email.strip().lower(), "payload": payload, "nonce": nonce}
        message = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(private.sign(message)).decode("ascii")

        self.assertTrue(verify_signature(public, email, payload, nonce, signature))

        # tamper signature
        bad_sig = base64.b64encode(b"x" * 64).decode("ascii")
        self.assertFalse(verify_signature(public, email, payload, nonce, bad_sig))


if __name__ == "__main__":
    unittest.main()
