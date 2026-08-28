"""
Authenticated routes: /store and /retrieve.

Both share identical auth checks (user exists, verified, nonce fresh,
signature valid), factored into authenticate_request so neither route
duplicates that logic. The server only ever handles ciphertext bytes,
it never imports or calls decrypt_vault.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from server.src.crypto import verify_signature
from server.src.db import User, Vault, get_session
from server.src.schemas import EnvelopeBase, StorePayload
from shared.src.email_utils import normalise_email

router = APIRouter()


def authenticate_request(envelope: EnvelopeBase, session: Session) -> tuple[User, dict]:
    """
    Run all shared checks for an authenticated request.
    Returns the matched User and the decoded inner payload dict.
    Raises HTTPException on any failure.
    """
    email = normalise_email(envelope.email)

    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    if not user.verified:
        raise HTTPException(status_code=403, detail="account not verified")

    if envelope.signature is None:
            raise HTTPException(status_code=400, detail="signature required")
    
    
    if not verify_signature(
        public_key=user.public_key,
        email=envelope.email,
        payload=envelope.payload,
        nonce=envelope.nonce,
        signature=envelope.signature,
    ):
        raise HTTPException(status_code=401, detail="invalid signature")


    if envelope.nonce <= user.last_nonce:
        raise HTTPException(status_code=409, detail="nonce already used or stale")

    
    try:
        payload_bytes = base64.b64decode(envelope.payload, validate=True)
        inner = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="malformed payload")

    return user, inner


def _advance_nonce(session: Session, user: User, nonce: int) -> None:
    user.last_nonce = nonce
    session.add(user)
    session.commit()


@router.post("/store")
def store(envelope: EnvelopeBase, session: Session = Depends(get_session)):
    user, inner = authenticate_request(envelope, session)

    if inner.get("type") != "store":
        raise HTTPException(status_code=400, detail="type mismatch for this endpoint")

    payload = StorePayload(**inner)

    try:
        vault_blob = base64.b64decode(payload.vault, validate=True)
    except ValueError:
        raise HTTPException(status_code=400, detail="malformed vault payload")

    if len(vault_blob) < 12:
        raise HTTPException(status_code=400, detail="vault ciphertext too short")

    encryption_nonce = vault_blob[:12]
    ciphertext = vault_blob[12:]

    existing = session.get(Vault, user.id)
    if existing is not None:
        existing.encryption_nonce = encryption_nonce
        existing.ciphertext = ciphertext
        existing.created_at = datetime.now(timezone.utc)
        session.add(existing)
    else:
        session.add(
            Vault(
                user_id=user.id,
                encryption_nonce=encryption_nonce,
                ciphertext=ciphertext,
                created_at=datetime.now(timezone.utc),
            )
        )

    _advance_nonce(session, user, envelope.nonce)
    return {"status": "stored"}


@router.post("/retrieve")
def retrieve(envelope: EnvelopeBase, session: Session = Depends(get_session)):
    user, inner = authenticate_request(envelope, session)

    if inner.get("type") != "retrieve":
        raise HTTPException(status_code=400, detail="type mismatch for this endpoint")

    vault = session.get(Vault, user.id)
    if vault is None:
        raise HTTPException(status_code=404, detail="no vault stored for this user")

    vault_blob = vault.encryption_nonce + vault.ciphertext

    _advance_nonce(session, user, envelope.nonce)
    return {"vault": base64.b64encode(vault_blob).decode("ascii")}