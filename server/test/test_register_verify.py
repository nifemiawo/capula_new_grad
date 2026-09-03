import base64
import sys
import tempfile
import unittest
from pathlib import Path


from fastapi import HTTPException
from sqlmodel import Session, SQLModel, create_engine,select

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server.src.db as db_module
from server.src.routes.register import register_user, verify_user
from server.src.model.schemas import EnvelopeBase, RegisterPayload


class RegisterVerifyTests(unittest.TestCase):
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

    def test_register_returns_code_and_verify_succeeds(self) -> None:
        payload = RegisterPayload(public_key=base64.b64encode(b"\x02" * 32).decode("ascii"))
        payload_json = payload.model_dump_json().encode("utf-8")
        envelope = EnvelopeBase(email=" Test@Example.Com ", payload=base64.b64encode(payload_json).decode("ascii"), nonce=0)

        with Session(self.engine) as session:
            result = register_user(envelope, session)
            self.assertIn("verification_code", result)
            code = result["verification_code"]

            # user should exist but not verified yet
            user = session.exec(select(db_module.User).where(db_module.User.email == "test@example.com")).first()
            self.assertIsNotNone(user)
            self.assertFalse(user.verified)

            # now call verify_user 
            verify_user("test@example.com", code, session)
            session.refresh(user)
            self.assertTrue(user.verified)

    def test_register_rejects_malformed_payload(self) -> None:
        envelope = EnvelopeBase(email="test@example.com", payload="not-base64", nonce=0)

        with Session(self.engine) as session:
            with self.assertRaises(HTTPException) as context:
                register_user(envelope, session)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "malformed payload")

    def test_register_rejects_malformed_inner_payload(self) -> None:
        payload = base64.b64encode(b"not-json").decode("ascii")
        envelope = EnvelopeBase(email="test@example.com", payload=payload, nonce=0)

        with Session(self.engine) as session:
            with self.assertRaises(HTTPException) as context:
                register_user(envelope, session)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "malformed payload")

    def test_register_existing_user_returns_generic_message(self) -> None:
        payload = RegisterPayload(public_key=base64.b64encode(b"\x03" * 32).decode("ascii"))
        payload_json = payload.model_dump_json().encode("utf-8")
        envelope = EnvelopeBase(email="test@example.com", payload=base64.b64encode(payload_json).decode("ascii"), nonce=0)

        with Session(self.engine) as session:
            first = register_user(envelope, session)
            existing_code = first["verification_code"]

            second = register_user(envelope, session)

            self.assertEqual(second, {"message": "If this user exists, a verification code has been created."})

          
            users = session.exec(select(db_module.User).where(db_module.User.email == "test@example.com")).all()
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0].verification_code, existing_code)

    def test_verify_rejects_unknown_or_wrong_code(self) -> None:
        with Session(self.engine) as session:
            with self.assertRaises(HTTPException) as unknown_context:
                verify_user("missing@example.com", "deadbeef", session)

            payload = RegisterPayload(public_key=base64.b64encode(b"\x04" * 32).decode("ascii"))
            payload_json = payload.model_dump_json().encode("utf-8")
            envelope = EnvelopeBase(email="test@example.com", payload=base64.b64encode(payload_json).decode("ascii"), nonce=0)
            register_user(envelope, session)

            with self.assertRaises(HTTPException) as wrong_code_context:
                verify_user("test@example.com", "wrong-code", session)

        self.assertEqual(unknown_context.exception.status_code, 400)
        self.assertEqual(unknown_context.exception.detail, "Invalid or expired verification code")
        self.assertEqual(wrong_code_context.exception.status_code, 400)
        self.assertEqual(wrong_code_context.exception.detail, "Invalid or expired verification code")


if __name__ == "__main__":
    unittest.main()
