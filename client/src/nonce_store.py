"""Local per-email nonce tracking.

The client tracks its own nonce in a local file, since it re-derives keys
fresh from the master password each run rather than keeping any other
persistent state. A drawback of this approach is that if the local nonce
falls out of sync with the server (e.g. the file is lost, or a request
is sent but the response never arrives), the client has no way to recover;
a production implementation would need to handle that explicitly, for
example by letting the client query the server for its last-known nonce.
"""

from __future__ import annotations
import os
from shared.src.email_utils import normalise_email


def _nonce_path(email: str) -> str:
    address = normalise_email(email)
    return os.path.join(os.getcwd(), f".nonce-{address}")


def load_and_increment_nonce(email: str) -> int:
    path = _nonce_path(email)
    last = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            contents = f.read().strip()
            last = int(contents) if contents else 0 # get last nonce, default to 0 if file is empty
    except (FileNotFoundError, ValueError):
        last = 0 # default to 0 if file doesn't exist or contents are invalid

    next_nonce = last + 1 
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(next_nonce))
    return next_nonce