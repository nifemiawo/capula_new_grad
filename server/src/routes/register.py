import base64
import json

from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session, select

from server.src.db import User, get_session
from server.src.schemas import EnvelopeBase, RegisterPayload
from shared.src.email_utils import normalise_email

app = FastAPI()


@app.post("/register")
def register_user(envelope: EnvelopeBase, session: Session = Depends(get_session)) -> dict:
    """
    Register a new user with the provided envelope.
    Registration is unsigned per spec; the email is verified separately
    via the mock verification step before the account can be used.
    """
    email = normalise_email(envelope.email)

    payload_bytes = base64.b64decode(envelope.payload)
    payload = RegisterPayload.model_validate_json(payload_bytes)
    public_key_bytes = base64.b64decode(payload.public_key)

    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")

    new_user = User(
        email=email,
        public_key=public_key_bytes,
        verified=False,
        last_nonce=0,
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": "User registered, verification required", "user_id": new_user.id}
