from __future__ import annotations


def normalise_email(email: str) -> str:
	"""Return a normalised email address for shared account handling.

	We trim surrounding whitespace and convert to lowercase so the same logical
	account maps to the same derived values and signed payloads.
	"""
	if not isinstance(email, str):
		raise TypeError("email must be a string")

	normalised = email.strip()
	if not normalised:
		raise ValueError("email must not be empty")
	return normalised.lower()