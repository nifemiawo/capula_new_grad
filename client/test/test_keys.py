import unittest
import os
import sys
from unittest.mock import patch

TEST_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(os.path.dirname(TEST_DIR))
SRC_DIR = os.path.join(os.path.dirname(TEST_DIR), "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from client.src.keys import derive_keys


class DeriveKeysTests(unittest.TestCase):
    @patch("client.src.keys.scrypt")
    def test_same_inputs_produce_same_keys(self, mock_scrypt) -> None:
        mock_scrypt.return_value = b"a" * 64

        first = derive_keys("test@example.com", "correct horse battery staple")
        second = derive_keys(" test@example.com ", "correct horse battery staple")

        self.assertEqual(first, second)
        self.assertEqual(len(first[0]), 32)
        self.assertEqual(len(first[1]), 32)

    @patch("client.src.keys.scrypt")
    def test_different_passwords_produce_different_keys(self, mock_scrypt) -> None:
        mock_scrypt.side_effect = [b"a" * 64, b"b" * 64]

        first = derive_keys("test@example.com", "password-one")
        second = derive_keys("test@example.com", "password-two")

        self.assertNotEqual(first, second)

    def test_input_validation(self) -> None:
        with self.assertRaises(TypeError):
            derive_keys(123, "password")
        with self.assertRaises(TypeError):
            derive_keys("test@example.com", 123)
        with self.assertRaises(ValueError):
            derive_keys("", "password")
        with self.assertRaises(ValueError):
            derive_keys("test@example.com", "")
        

    


if __name__ == "__main__":
    unittest.main()