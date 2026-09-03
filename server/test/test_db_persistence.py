from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


class TestUserPersistence(unittest.TestCase):
    def test_user_persists_across_process_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "vault.db"
            public_key_b64 = base64.b64encode(b"\x01" * 32).decode("ascii")

            writer_code = f"""
from sqlmodel import SQLModel, Session, create_engine
from db import User
import base64

engine = create_engine(r"sqlite:///{database_path}", connect_args={{"check_same_thread": False}})
SQLModel.metadata.create_all(engine)

with Session(engine) as session:
    user = User(
        email="alice@example.com",
        public_key=base64.b64decode("{public_key_b64}"),
        verified=True,
        last_nonce=3,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    print(user.id)
"""

            writer_result = subprocess.run(
                [sys.executable, "-c", writer_code],
                cwd=SERVER_DIR,
                check=True,
                capture_output=True,
                text=True,
            )
            user_id = int(writer_result.stdout.strip())

            reader_code = f"""
from sqlmodel import Session, create_engine, select
from db import User
import base64

engine = create_engine(r"sqlite:///{database_path}", connect_args={{"check_same_thread": False}})
with Session(engine) as session:
    user = session.exec(select(User).where(User.email == "alice@example.com")).one()
    print(user.id)
    print(user.email)
    print(base64.b64encode(user.public_key).decode("ascii"))
    print(user.verified)
    print(user.last_nonce)
"""

            reader_result = subprocess.run(
                [sys.executable, "-c", reader_code],
                cwd=SERVER_DIR,
                check=True,
                capture_output=True,
                text=True,
            )

            reader_lines = [line.strip() for line in reader_result.stdout.splitlines() if line.strip()]
            self.assertEqual(
                reader_lines,
                [str(user_id), "alice@example.com", public_key_b64, "True", "3"],
            )


if __name__ == "__main__":
    unittest.main()
