import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

KDF_ITERATIONS = 480000  
SALT_SIZE = 16          
KEY_SIZE = 32           

def generate_salt(size=SALT_SIZE):
    
    return os.urandom(size)

def derive_key(master_password: str, salt: bytes) -> bytes:
    
    password_bytes = master_password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def hash_password(password: str, salt: bytes) -> bytes:
    
    return derive_key(password, salt)

def encode_bytes(data: bytes) -> str:
    
    return urlsafe_b64encode(data).decode('utf-8')

def decode_bytes(data: str) -> bytes:
    
    return urlsafe_b64decode(data.encode('utf-8'))

if __name__ == '__main__':
    test_salt = generate_salt()
    test_password = "MySecureMasterPassword123"

    derived_key = derive_key(test_password, test_salt)
    password_hash = hash_password(test_password, test_salt)

    print(f"Generated Salt (B64): {encode_bytes(test_salt)}")
    print(f"Derived Key (Hex): {derived_key.hex()}")
    print(f"Password Hash (Hex): {password_hash.hex()}")
    
    verification_hash = hash_password(test_password, test_salt)
    print(f"\nVerification Check Successful: {verification_hash == password_hash}")