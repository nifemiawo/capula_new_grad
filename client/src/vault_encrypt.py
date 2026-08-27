
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_vault(plaintext: bytes, encryption_seed: bytes) -> bytes:
	"""Encrypt a vault using the provided encryption seed.

	The encryption seed must be 32 bytes long. The returned ciphertext includes
	a 12-byte nonce prefix so it can be decrypted without an extra parameter.
	"""
	if not isinstance(plaintext, bytes):
		raise TypeError("plaintext must be bytes")
	if not isinstance(encryption_seed, bytes):
		raise TypeError("encryption_seed must be bytes")
	if len(encryption_seed) != 32:
		raise ValueError("encryption_seed must be 32 bytes long")

	nonce = os.urandom(12)
	ciphertext = AESGCM(encryption_seed).encrypt(nonce, plaintext, None)
	return nonce + ciphertext


def decrypt_vault(ciphertext: bytes, encryption_seed: bytes) -> bytes:
	"""Decrypt a vault ciphertext created by encrypt_vault."""
	if not isinstance(ciphertext, bytes):
		raise TypeError("ciphertext must be bytes")
	if not isinstance(encryption_seed, bytes):
		raise TypeError("encryption_seed must be bytes")
	if len(encryption_seed) != 32:
		raise ValueError("encryption_seed must be 32 bytes long")

	if len(ciphertext) < 28:
		raise ValueError("ciphertext is too short to contain a nonce and tag")

	nonce = ciphertext[:12]
	payload = ciphertext[12:]
	return AESGCM(encryption_seed).decrypt(nonce, payload, None)
    