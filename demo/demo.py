"""
End-to-end demo of the password vault backup flow.

Runs all 7 steps from the spec:
1. Generate a key pair from the master password
2. Register an email address and public key
3. Complete the mocked email-verification process
4. Encrypt a sample password vault
5. Store the encrypted vault
6. Retrieve it
7. Confirm that the retrieved data matches what was stored

Requires the server running locally first, e.g.:
    uvicorn server.src.main:app --reload
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys

from client.src.keys import derive_keys
from client.src.sign import create_signing_key, public_key_bytes_from_private
from client.src.vault_encrypt import encrypt_vault, decrypt_vault
from client.src import api_client
from client.src.http_client import ApiError

BASE_URL = os.environ.get("CAPULA_BASE_URL", "http://localhost:8000")


def run_demo(email: str, master_password: str) -> None:
    print(f"Running demo for {email}\n")

    # Step 1: generate a key pair from the master password
    print("[1] Deriving keys from master password...")
    signing_seed, encryption_seed = derive_keys(email, master_password)
    signing_key = create_signing_key(signing_seed)
    public_key_bytes = public_key_bytes_from_private(signing_key)
    print("    done.\n")

    # Step 2: register an email address and public key
    print("[2] Registering...")
    register_response = api_client.register(BASE_URL, email, public_key_bytes)
    print(f"    server response: {register_response}\n")

    # Step 3: complete the mocked email-verification process
    print("[3] Verifying (mocked)...")
    verification_code = register_response["verification_code"]
    verify_response = api_client.verify(BASE_URL, email, verification_code)
    print(f"    server response: {verify_response}\n")

    # Step 4: encrypt a sample password vault
    print("[4] Encrypting sample vault...")
    sample_vault = {
        "entries": [
            {"site": "github.com", "username": "n!f3M1", "password": "hi1243"},
            {"site": "email.com", "username": "oluwan1femi", "password": "demo1234"},
        ]
    }
    plaintext = json.dumps(sample_vault).encode("utf-8")
    vault_blob = encrypt_vault(plaintext, encryption_seed)
    print(f"    ciphertext length: {len(vault_blob)} bytes\n")

    # Step 5: store the encrypted vault
    print("[5] Storing vault...")
    store_response = api_client.store(BASE_URL, email, signing_key, vault_blob)
    print(f"    server response: {store_response}\n")

    # Step 6: retrieve it
    print("[6] Retrieving vault...")
    retrieve_response = api_client.retrieve(BASE_URL, email, signing_key)
    retrieved_blob = base64.b64decode(retrieve_response["vault"])
    print("    retrieved.\n")

    # Step 7: confirm the retrieved data matches what was stored.
    # Two separate checks, at two different layers:
    #   - ciphertext equality confirms the round trip through the server
    #     didn't corrupt or substitute anything (transport/storage layer)
    #   - decrypted equality confirms the encryption/decryption itself is
    #     sound end to end (crypto layer)
    print("[7] Verifying round trip...")
    decrypted = decrypt_vault(retrieved_blob, encryption_seed)
    decrypted_vault = json.loads(decrypted)

    assert retrieved_blob == vault_blob, "retrieved ciphertext does not match stored ciphertext"
    assert decrypted_vault == sample_vault, "decrypted vault does not match original"
    print("    success: retrieved vault matches original.\n") 
    print("Demo complete.")


if __name__ == "__main__":
    default_email = f"demo-{secrets.token_hex(4)}@example.com"
    demo_email = sys.argv[1] if len(sys.argv) > 1 else default_email
    demo_password = sys.argv[2] if len(sys.argv) > 2 else "correct-horse-battery-staple"

    try:
        run_demo(demo_email, demo_password)
    except ApiError as e:
        print(f"\nDemo failed: server rejected a request ({e.status_code}): {e.detail}")
        sys.exit(1)
    except Exception as e:
        print(f"\nDemo failed unexpectedly: {e!r}")
        sys.exit(1)