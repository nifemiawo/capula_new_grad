import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# ensure package imports resolve (project root on sys.path)
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server.src.db as db_module
from server.src.routes.register import register_user, verify_user
from server.src.schemas import EnvelopeBase, RegisterPayload


class RegisterVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "vault.db"
        self.engine = create_engine(f"sqlite:///{self.db_path}", connect_args={"check_same_thread": False})
        # point the module engine at the temp engine
        db_module.engine = self.engine
        SQLModel.metadata.create_all(self.engine)

    def tearDown(self) -> None:
        # ensure engine disposes connections so the temp file can be removed
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
            from sqlmodel import select
            user = session.exec(select(db_module.User).where(db_module.User.email == "test@example.com")).first()
            self.assertIsNotNone(user)
            self.assertFalse(user.verified)

            # now call verify_user (simulating GET parameters)
            verify_user("test@example.com", code, session)
            session.refresh(user)
            self.assertTrue(user.verified)


if __name__ == "__main__":
    unittest.main()
