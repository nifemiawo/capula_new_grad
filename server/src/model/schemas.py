"""Pydantic schemas for the password vault API."""
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class EnvelopeBase(BaseModel):
    email: EmailStr
    payload: str
    nonce: int = Field(ge=0)
    signature: str | None = None

class RegisterPayload(BaseModel):
    type: Literal["register"] = "register"
    public_key: str

class StorePayload(BaseModel):
    type: Literal["store"] = "store"
    vault: str

class RetrievePayload(BaseModel):
    type: Literal["retrieve"] = "retrieve"