
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt_vault(plaintext: bytes, encryption_seed: bytes) -> bytes:
    """Encrypt a vault using the provided encryption seed.

    The encryption seed must be 32 bytes long. The returned ciphertext is
    the encrypted vault data.
    """ 

    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    if not isinstance(encryption_seed, bytes):
        raise TypeError("Encryption seed must be bytes")
    if len(encryption_seed) != 32:
        raise ValueError("Encryption seed must be 32 bytes long")
    nonce = os.urandom(12)  
    aesgcm = AESGCM(encryption_seed)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  

def decrypt_vault(ciphertext: bytes, encryption_seed: bytes) -> bytes:
    """Decrypt a vault using the provided encryption seed.

    The encryption seed must be 32 bytes long. The returned plaintext is
    the decrypted vault data.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(encryption_seed, bytes):
        raise TypeError("Encryption seed must be bytes")
    if len(encryption_seed) != 32:
        raise ValueError("Encryption seed must be 32 bytes long")
    nonce = ciphertext[:12]  
    aesgcm = AESGCM(encryption_seed)
    plaintext = aesgcm.decrypt(nonce, ciphertext[12:], None)
    return plaintext
    