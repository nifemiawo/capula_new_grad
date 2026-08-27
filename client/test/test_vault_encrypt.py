import os
import sys
import unittest

TEST_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(os.path.dirname(TEST_DIR))
SRC_DIR = os.path.join(os.path.dirname(TEST_DIR), "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from vault_encrypt import decrypt_vault, encrypt_vault


class VaultEncryptTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self) -> None:
        seed = bytes(range(32))
        plaintext = b"vault contents"

        ciphertext = encrypt_vault(plaintext, seed)

        self.assertIsInstance(ciphertext, bytes)
        self.assertGreater(len(ciphertext), len(plaintext))
        self.assertEqual(decrypt_vault(ciphertext, seed), plaintext)

    def test_encrypt_rejects_invalid_seed_length(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_vault(b"payload", b"short-seed")

    def test_encrypt_rejects_non_bytes_plaintext(self) -> None:
        with self.assertRaises(TypeError):
            encrypt_vault("payload", bytes(range(32)))

    def test_decrypt_rejects_invalid_seed_length(self) -> None:
        with self.assertRaises(ValueError):
            decrypt_vault(b"ciphertext", b"short-seed")


if __name__ == "__main__":
    unittest.main()
