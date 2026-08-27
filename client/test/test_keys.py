import unittest
import os
import sys

TEST_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(os.path.dirname(TEST_DIR))
SRC_DIR = os.path.join(os.path.dirname(TEST_DIR), "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from keys import derive_keys


class DeriveKeysTests(unittest.TestCase):
    def test_same_inputs_produce_same_keys(self) -> None:
        first = derive_keys("test@example.com", "correct horse battery staple")
        second = derive_keys(" test@example.com ", "correct horse battery staple")

        self.assertEqual(first, second)
        self.assertEqual(len(first[0]), 32)
        self.assertEqual(len(first[1]), 32)

    def test_different_passwords_produce_different_keys(self) -> None:
        first = derive_keys("test@example.com", "password-one")
        second = derive_keys("test@example.com", "password-two")

        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()