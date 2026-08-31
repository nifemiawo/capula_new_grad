"""Local per-email nonce tracking.

the client tracks its own nonce in a
local file, since it re-derives keys fresh each run with no other
persistent state. A production client would need to handle the
local-state-lost-and-out-of-sync-with-server case explicitly; this does not.
"""

from __future__ import annotations

import os

from shared.src.email_utils import normalise_email


def _nonce_path(email: str) -> str:
    safe = normalise_email(email).replace("@", "%40")
    return os.path.join(os.getcwd(), f".nonce-{safe}")


def load_and_increment_nonce(email: str) -> int:
    path = _nonce_path(email)
    last = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            contents = f.read().strip()
            last = int(contents) if contents else 0
    except (FileNotFoundError, ValueError):
        last = 0

    next_nonce = last + 1
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(next_nonce))
    return next_nonce