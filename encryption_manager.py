import os
from base64 import urlsafe_b64encode  # <--- NEW IMPORT
from cryptography.fernet import Fernet
from typing import Optional


class EncryptionManager:
    

    def __init__(self, derived_key: bytes):
        
        raw_key = derived_key[:32]

        
        fernet_key = urlsafe_b64encode(raw_key)

        self.fernet = Fernet(fernet_key)

    def encrypt_data(self, plaintext: str) -> str:
        """
        Encrypts a plaintext string (e.g., a password or username).
        Returns the ciphertext as a URL-safe Base64 string.
        """
        try:
            ciphertext_bytes = self.fernet.encrypt(plaintext.encode('utf-8'))
            return ciphertext_bytes.decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return ""

    def decrypt_data(self, ciphertext: str) -> Optional[str]:
        
        try:
            plaintext_bytes = self.fernet.decrypt(ciphertext.encode('utf-8'))
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


if __name__ == '__main__':
    from key_utils import derive_key, generate_salt

    test_salt = generate_salt()
    test_password = "MySecureMasterPassword123"
    derived_key = derive_key(test_password, test_salt)

    manager = EncryptionManager(derived_key)

    test_username = "user@example.com"

    encrypted_username = manager.encrypt_data(test_username)

    print("--- Encryption Test ---")
    print(f"Original Username: {test_username}")
    print(
        f"Derived Fernet Key: {urlsafe_b64encode(derived_key[:32]).decode('utf-8')}")
    print(f"Encrypted Username: {encrypted_username}")

    decrypted_username = manager.decrypt_data(encrypted_username)

    print("\n--- Decryption Test ---")
    print(f"Decrypted Username: {decrypted_username}")

    corrupted_cipher = encrypted_username[:-5] + 'XXXXX'
    print("\n--- Corruption Test ---")
    manager.decrypt_data(corrupted_cipher)