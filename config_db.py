import sqlite3
import os
from typing import Optional

from key_utils import generate_salt, hash_password, encode_bytes, decode_bytes

DATABASE_FILE = "password_manager.db"


class ConfigDB:

    def __init__(self):
        
        self.conn = sqlite3.connect(DATABASE_FILE)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                salt TEXT NOT NULL,
                master_hash TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def is_initialized(self) -> bool:
        
        self.cursor.execute("SELECT COUNT(*) FROM config")
        return self.cursor.fetchone()[0] > 0

    def initialize_master_password(self, master_password: str) -> None:
        
        if self.is_initialized():
            raise Exception("Master password has already been set.")

        salt = generate_salt()
        master_hash = hash_password(master_password, salt)

        self.cursor.execute(
            "INSERT INTO config (id, salt, master_hash) VALUES (?, ?, ?)",
            (1, encode_bytes(salt), encode_bytes(master_hash))
        )
        self.conn.commit()
        print("Master password set successfully!")

    def get_config(self) -> Optional[tuple[bytes, bytes]]:
        self.cursor.execute(
            "SELECT salt, master_hash FROM config WHERE id = 1")
        row = self.cursor.fetchone()
        if row:
            return decode_bytes(row[0]), decode_bytes(row[1])
        return None

    def verify_master_password(self, input_password: str) -> Optional[bytes]:
        config = self.get_config()
        if not config:
            return None

        salt, stored_hash = config

        input_hash = hash_password(input_password, salt)

        if input_hash == stored_hash:
            return hash_password(input_password, salt)
        else:
            return None

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    db = ConfigDB()

    if not db.is_initialized():
        print("Database not initialized. Setting Master Password...")
        db.initialize_master_password("SuperSecretMP123")

    print("\n--- Testing Verification ---")
    correct_key = db.verify_master_password("SuperSecretMP123")
    if correct_key:
        print("Master Password Verified! Derived Key (first 10 chars):",
              correct_key.hex()[:10] + "...")
    else:
        print("Verification Failed.")

    incorrect_key = db.verify_master_password("WrongPassword")
    if incorrect_key is None:
        print("Incorrect Password Rejected successfully.")

    db.close()
