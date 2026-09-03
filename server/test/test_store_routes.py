import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ensure package imports resolve (project root on sys.path)
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlmodel import Session, SQLModel, create_engine

from client.src.vault_encrypt import decrypt_vault, encrypt_vault

import server.src.db as db_module
from server.src.routes.store import retrieve, store
from server.src.model.schemas import EnvelopeBase
from shared.src.email_utils import normalise_email


class StoreRetrieveRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "vault.db"
        self.engine = create_engine(f"sqlite:///{self.db_path}", connect_args={"check_same_thread": False})
        db_module.engine = self.engine
        SQLModel.metadata.create_all(self.engine)

    def tearDown(self) -> None:
        try:
            self.engine.dispose()
        except Exception:
            pass
        self.tempdir.cleanup()

    def _create_keypair(self) -> tuple[Ed25519PrivateKey, bytes]:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return private_key, public_key

    def _create_user(self, session: Session, email: str, public_key: bytes, verified: bool = True, last_nonce: int = 0):
        user = db_module.User(
            email=normalise_email(email),
            public_key=public_key,
            verified=verified,
            last_nonce=last_nonce,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    def _signed_envelope(self, private_key: Ed25519PrivateKey, email: str, inner: dict, nonce: int) -> EnvelopeBase:
        payload_json = json.dumps(inner, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.b64encode(payload_json).decode("ascii")
        message = json.dumps(
            {"email": normalise_email(email), "payload": payload_b64, "nonce": nonce},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = base64.b64encode(private_key.sign(message)).decode("ascii")
        return EnvelopeBase(email=email, payload=payload_b64, nonce=nonce, signature=signature)

    def test_store_and_retrieve_happy_path(self) -> None:
        email = "alice@example.com"
        private_key, public_key = self._create_keypair()
        plaintext = b"demo vault contents"
        encryption_seed = bytes(range(32))
        vault_blob = encrypt_vault(plaintext, encryption_seed)

        with Session(self.engine) as session:
            user = self._create_user(session, email, public_key, verified=True, last_nonce=0)

            store_envelope = self._signed_envelope(
                private_key,
                email,
                {"type": "store", "vault": base64.b64encode(vault_blob).decode("ascii")},
                nonce=1,
            )
            self.assertEqual(store(store_envelope, session), {"status": "stored"})

            stored_vault = session.get(db_module.Vault, user.id)
            self.assertIsNotNone(stored_vault)
            self.assertEqual(user.last_nonce, 1)

            retrieve_envelope = self._signed_envelope(private_key, email, {"type": "retrieve"}, nonce=2)
            response = retrieve(retrieve_envelope, session)

            retrieved_blob = base64.b64decode(response["vault"])
            self.assertEqual(retrieved_blob, vault_blob)
            self.assertEqual(decrypt_vault(retrieved_blob, encryption_seed), plaintext)
            self.assertEqual(session.get(db_module.User, user.id).last_nonce, 2)

    def test_store_rejects_missing_signature(self) -> None:
        private_key, public_key = self._create_keypair()
        email = "alice@example.com"

        with Session(self.engine) as session:
            self._create_user(session, email, public_key)
            envelope = EnvelopeBase(
                email=email,
                payload=base64.b64encode(json.dumps({"type": "store", "vault": "Zm9v"}).encode("utf-8")).decode("ascii"),
                nonce=1,
            )

            with self.assertRaises(HTTPException) as context:
                store(envelope, session)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "signature required")

    def test_store_rejects_invalid_signature_and_unknown_user(self) -> None:
        email = "alice@example.com"
        private_key, public_key = self._create_keypair()
        wrong_private_key, _ = self._create_keypair()

        with Session(self.engine) as session:
            self._create_user(session, email, public_key)

            bad_signature_envelope = self._signed_envelope(
                wrong_private_key,
                email,
                {"type": "store", "vault": "Zm9v"},
                nonce=1,
            )
            with self.assertRaises(HTTPException) as invalid_signature_context:
                store(bad_signature_envelope, session)

        self.assertEqual(invalid_signature_context.exception.status_code, 401)
        self.assertEqual(invalid_signature_context.exception.detail, "invalid credentials")

        with Session(self.engine) as session:
            malformed_signature_envelope = self._signed_envelope(
                private_key,
                email,
                {"type": "store", "vault": "Zm9v"},
                nonce=1,
            )
            malformed_signature_envelope.signature = "!!!"

            with self.assertRaises(HTTPException) as malformed_signature_context:
                store(malformed_signature_envelope, session)

        self.assertEqual(malformed_signature_context.exception.status_code, 401)
        self.assertEqual(malformed_signature_context.exception.detail, "invalid credentials")

        with Session(self.engine) as session:
            missing_user_envelope = self._signed_envelope(
                private_key,
                "missing@example.com",
                {"type": "store", "vault": "Zm9v"},
                nonce=1,
            )

            with self.assertRaises(HTTPException) as missing_user_context:
                store(missing_user_envelope, session)

        self.assertEqual(missing_user_context.exception.status_code, 401)
        self.assertEqual(missing_user_context.exception.detail, "Invalid credentials")

    def test_store_rejects_unverified_user_and_stale_nonce(self) -> None:
        unverified_email = "alice-unverified@example.com"
        stale_email = "alice-stale@example.com"
        private_key, public_key = self._create_keypair()

        with Session(self.engine) as session:
            self._create_user(session, unverified_email, public_key, verified=False)
            unverified_envelope = self._signed_envelope(
                private_key,
                unverified_email,
                {"type": "store", "vault": "Zm9v"},
                nonce=1,
            )

            with self.assertRaises(HTTPException) as unverified_context:
                store(unverified_envelope, session)

        self.assertEqual(unverified_context.exception.status_code, 401)
        self.assertEqual(unverified_context.exception.detail, "Invalid credentials")

        with Session(self.engine) as session:
            self._create_user(session, stale_email, public_key, verified=True, last_nonce=1)
            stale_envelope = self._signed_envelope(
                private_key,
                stale_email,
                {"type": "store", "vault": "Zm9v"},
                nonce=1,
            )

            with self.assertRaises(HTTPException) as stale_context:
                store(stale_envelope, session)

        self.assertEqual(stale_context.exception.status_code, 409)
        self.assertEqual(stale_context.exception.detail, "nonce already used or stale")

    def test_store_rejects_malformed_and_invalid_inner_payloads(self) -> None:
        malformed_email = "alice-malformed@example.com"
        mismatch_email = "alice-mismatch@example.com"
        private_key, public_key = self._create_keypair()

        with Session(self.engine) as session:
            self._create_user(session, malformed_email, public_key)

            malformed_envelope = self._signed_envelope(private_key, malformed_email, {"type": "store", "vault": "Zm9v"}, nonce=1)
            malformed_envelope.payload = base64.b64encode(b"not-json").decode("ascii")
            malformed_message = json.dumps(
                {"email": normalise_email(malformed_email), "payload": malformed_envelope.payload, "nonce": 1},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            malformed_envelope.signature = base64.b64encode(private_key.sign(malformed_message)).decode("ascii")

            with self.assertRaises(HTTPException) as malformed_context:
                store(malformed_envelope, session)

        self.assertEqual(malformed_context.exception.status_code, 400)
        self.assertEqual(malformed_context.exception.detail, "malformed payload")

        with Session(self.engine) as session:
            self._create_user(session, mismatch_email, public_key)
            type_mismatch_envelope = self._signed_envelope(private_key, mismatch_email, {"type": "retrieve"}, nonce=1)

            with self.assertRaises(HTTPException) as mismatch_context:
                store(type_mismatch_envelope, session)

        self.assertEqual(mismatch_context.exception.status_code, 400)
        self.assertEqual(mismatch_context.exception.detail, "type mismatch for this endpoint")

    def test_store_rejects_bad_vault_payloads(self) -> None:
        bad_base64_email = "alice-bad-base64@example.com"
        short_blob_email = "alice-short-vault@example.com"
        private_key, public_key = self._create_keypair()

        with Session(self.engine) as session:
            self._create_user(session, bad_base64_email, public_key)

            bad_base64_envelope = self._signed_envelope(
                private_key,
                bad_base64_email,
                {"type": "store", "vault": "%%%"},
                nonce=1,
            )
            with self.assertRaises(HTTPException) as invalid_vault_context:
                store(bad_base64_envelope, session)

        self.assertEqual(invalid_vault_context.exception.status_code, 400)
        self.assertEqual(invalid_vault_context.exception.detail, "malformed vault payload")

        with Session(self.engine) as session:
            self._create_user(session, short_blob_email, public_key)
            short_blob = base64.b64encode(b"short-vault").decode("ascii")
            short_envelope = self._signed_envelope(
                private_key,
                short_blob_email,
                {"type": "store", "vault": short_blob},
                nonce=1,
            )

            with self.assertRaises(HTTPException) as short_context:
                store(short_envelope, session)

        self.assertEqual(short_context.exception.status_code, 400)
        self.assertEqual(short_context.exception.detail, "vault ciphertext too short")

    def test_retrieve_rejects_missing_vault(self) -> None:
        email = "alice@example.com"
        private_key, public_key = self._create_keypair()

        with Session(self.engine) as session:
            self._create_user(session, email, public_key)
            envelope = self._signed_envelope(private_key, email, {"type": "retrieve"}, nonce=1)

            with self.assertRaises(HTTPException) as context:
                retrieve(envelope, session)

        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "no vault stored for this user")


if __name__ == "__main__":
    unittest.main()