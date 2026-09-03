""" Registration routes for the API. 
"""

import base64
import binascii
import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from pydantic import ValidationError

from server.src.db import User, get_session
from server.src.model.schemas import EnvelopeBase, RegisterPayload
from shared.src.email_utils import normalise_email

router = APIRouter()


@router.post("/register")
def register_user(envelope: EnvelopeBase, session: Session = Depends(get_session)) -> dict:
    """
    Register a new user with the provided envelope.
    Registration is unsigned; the email is verified separately
    via the mock verification step before the account can be used.
    """
    email = normalise_email(envelope.email)

    try:
        payload_bytes = base64.b64decode(envelope.payload, validate=True)
        payload = RegisterPayload.model_validate_json(payload_bytes)
        public_key_bytes = base64.b64decode(payload.public_key, validate=True)
    except (ValueError, binascii.Error, ValidationError):
        raise HTTPException(status_code=400, detail="malformed payload")

    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        # Don't reveal whether the user exists or not, to avoid leaking information to potential attackers
        return {"message": "If this user exists, a verification code has been created."} 
    verification_code = secrets.token_hex(4) 

    new_user = User(
        email=email,
        public_key=public_key_bytes,
        verified=False,
        verification_code=verification_code,
        last_nonce=0,
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {
        "message": "If this user exists, a verification code has been created.",
        "verification_code": verification_code,
    }


@router.get("/verify")
def verify_user(email: str, code: str, session: Session = Depends(get_session)) -> dict:
    """ Verify a user's email address using the provided verification code"""
    user = session.exec(select(User).where(User.email == normalise_email(email))).first()
    if user is None or user.verification_code != code:
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")
    
    user.verified = True
    user.verification_code = None
    session.add(user)
    session.commit()
    return {"message": "Email verified"}
