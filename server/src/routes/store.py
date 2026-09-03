"""
Authenticated routes: /store and /retrieve.
Design notes:
- User lookup and verification-status failures are collapsed into a single
  generic 401 ("invalid credentials") rather than distinct 404/403 responses,
  so an unauthenticated caller can't use these endpoints to enumerate which
  emails are registered. This is a deliberate trade-off: a legitimate user
  who forgot to verify their account gets a less specific error in exchange
  for that information not being exposed to anyone else.
- Nonce freshness is enforced with a single atomic conditional UPDATE
  (last_nonce < envelope.nonce) rather than a separate read-then-write, so
  two concurrent requests for the same user can't both pass a freshness
  check against the same stale value.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy import update as sa_update
from sqlmodel import Session, select

from server.src.crypto import verify_signature
from server.src.db import User, Vault, get_session
from server.src.model.schemas import EnvelopeBase, RetrievePayload, StorePayload
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
    if user is None or not user.verified:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if envelope.signature is None:
        raise HTTPException(status_code=400, detail="signature required")

    if not verify_signature(
        public_key=user.public_key,
        email=envelope.email,
        payload=envelope.payload,
        nonce=envelope.nonce,
        signature=envelope.signature,
    ):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Prevent race conditions by atomically updating the last_nonce in the database if the provided nonce is greater than the stored last_nonce
    result = session.exec(
        sa_update(User)
        .where(User.id == user.id, User.last_nonce < envelope.nonce)
        .values(last_nonce=envelope.nonce)
    )
    session.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=409, detail="nonce already used or stale")
    session.refresh(user)

    try:
        payload_bytes = base64.b64decode(envelope.payload, validate=True)
        inner = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="malformed payload")

    return user, inner


@router.post("/store")
def store(envelope: EnvelopeBase, session: Session = Depends(get_session)) -> dict:
    """Store the provided vault for the authenticated user"""
    user, inner = authenticate_request(envelope, session)

    if inner.get("type") != "store":
        raise HTTPException(status_code=400, detail="type mismatch for this endpoint")

    try:
        payload = StorePayload(**inner)
    except ValidationError:
        raise HTTPException(status_code=400, detail="malformed payload")

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
    session.commit()
    return {"status": "stored"}

@router.post("/retrieve")
def retrieve(envelope: EnvelopeBase, session: Session = Depends(get_session)) -> dict:
    """Retrieve the stored vault for the authenticated user"""
    user, inner = authenticate_request(envelope, session)

    if inner.get("type") != "retrieve":
        raise HTTPException(status_code=400, detail="type mismatch for this endpoint")

    try:
        RetrievePayload(**inner)
    except ValidationError:
        raise HTTPException(status_code=400, detail="malformed payload")

    vault = session.get(Vault, user.id)
    if vault is None:
        raise HTTPException(status_code=404, detail="no vault stored for this user")

    vault_blob = vault.encryption_nonce + vault.ciphertext
    return {"vault": base64.b64encode(vault_blob).decode("ascii")}