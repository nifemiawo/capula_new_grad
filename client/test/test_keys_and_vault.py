import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.src.keys import derive_keys
from client.src.vault_encrypt import encrypt_vault, decrypt_vault


class ClientKeysVaultTests(unittest.TestCase):
    @patch("client.src.keys.scrypt")
    def test_derive_keys_properties(self, mock_scrypt) -> None:
        mock_scrypt.return_value = bytes(range(64))

        signing, encryption = derive_keys("Test@Example.com", "hunter2")
        self.assertEqual(len(signing), 32)
        self.assertEqual(len(encryption), 32)

    def test_vault_round_trip_and_invalid_seed(self) -> None:
        seed = bytes(range(32))
        plaintext = b"hello secret"
        ciphertext = encrypt_vault(plaintext, seed)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(decrypt_vault(ciphertext, seed), plaintext)

        with self.assertRaises(ValueError):
            encrypt_vault(b"x", b"short")

  


if __name__ == "__main__":
    unittest.main()
