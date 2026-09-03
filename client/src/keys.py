"""Key derivation for the password vault client.

The client derives two independent 32-byte seeds from the email address and
master password using a split-KDF pattern:

- the first 32 bytes are used as the Ed25519 signing seed
- the second 32 bytes are used as the vault encryption seed
"""

from __future__ import annotations
from hashlib import scrypt
from shared.src.email_utils import normalise_email

_DERIVED_KEY_LENGTH = 64
_SEED_LENGTH = 32
_SCRYPT_COST = 2**17
_SCRYPT_BLOCK_SIZE = 8
_SCRYPT_PARALLELISM = 1
_SCRYPT_MAX_MEM = 256 * 1024 * 1024 

def derive_keys(email: str, master_password: str) -> tuple[bytes, bytes]:
	"""Derive signing and encryption seeds from an email and master password.
	The returned tuple contains two 32-byte values:

	1. Ed25519 signing seed
	2. Vault encryption seed
	"""

	if not isinstance(email, str):
		raise TypeError("email must be a string")
	if not isinstance(master_password, str):
		raise TypeError("master_password must be a string")
	if not master_password:
		raise ValueError("master_password must not be empty")

	salt = normalise_email(email).encode("utf-8")
	derived = scrypt(
		password=master_password.encode("utf-8"),
		salt=salt,
		n=_SCRYPT_COST,
		r=_SCRYPT_BLOCK_SIZE,
		p=_SCRYPT_PARALLELISM,
		dklen=_DERIVED_KEY_LENGTH,
		maxmem=_SCRYPT_MAX_MEM,

	)

	signing_seed = derived[:_SEED_LENGTH] # First 32 bytes for signing
	encryption_seed = derived[_SEED_LENGTH:] # Last 32 bytes for encryption
	return signing_seed, encryption_seed
