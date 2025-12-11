import sqlite3
from typing import List, Dict, Optional

from config_db import DATABASE_FILE, ConfigDB
from encryption_manager import EncryptionManager


class CredentialManager:

    def __init__(self, encryption_key: bytes):
        self.conn = sqlite3.connect(DATABASE_FILE)
        self.cursor = self.conn.cursor()
        self.enc_manager = EncryptionManager(encryption_key)
        self._create_credentials_table()

    def _create_credentials_table(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name TEXT NOT NULL,
                encrypted_username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                UNIQUE(site_name)
            )
        """)
        self.conn.commit()

    def add_credential(self, site_name: str, username: str, password: str) -> bool:
        try:
            encrypted_user = self.enc_manager.encrypt_data(username)
            encrypted_pass = self.enc_manager.encrypt_data(password)

            self.cursor.execute(
                """
                INSERT INTO credentials (site_name, encrypted_username, encrypted_password)
                VALUES (?, ?, ?)
                """,
                (site_name, encrypted_user, encrypted_pass)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            print(f"Error: A credential for '{site_name}' already exists.")
            return False
        except Exception as e:
            print(f"Failed to add credential: {e}")
            return False

    def get_credential(self, site_name: str) -> Optional[Dict[str, str]]:
        self.cursor.execute(
            """
            SELECT encrypted_username, encrypted_password 
            FROM credentials WHERE site_name = ?
            """,
            (site_name,)
        )
        row = self.cursor.fetchone()

        if row:
            encrypted_user, encrypted_pass = row

            decrypted_user = self.enc_manager.decrypt_data(encrypted_user)
            decrypted_pass = self.enc_manager.decrypt_data(encrypted_pass)

            if decrypted_user and decrypted_pass:
                return {
                    "site_name": site_name,
                    "username": decrypted_user,
                    "password": decrypted_pass
                }
            else:
                print("Decryption failed! Data might be corrupted or key is wrong.")
                return None
        return None

    def update_credential(self, site_name: str, new_username: str, new_password: str) -> bool:
        try:
            encrypted_user = self.enc_manager.encrypt_data(new_username)
            encrypted_pass = self.enc_manager.encrypt_data(new_password)

            self.cursor.execute(
                """
                UPDATE credentials 
                SET encrypted_username = ?, encrypted_password = ?
                WHERE site_name = ?
                """,
                (encrypted_user, encrypted_pass, site_name)
            )
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            print(f"Failed to update credential: {e}")
            return False

    def list_sites(self) -> List[str]:
        self.cursor.execute(
            "SELECT site_name FROM credentials ORDER BY site_name")
        return [row[0] for row in self.cursor.fetchall()]

    def delete_credential(self, site_name: str) -> bool:
        try:
            self.cursor.execute(
                """
                DELETE FROM credentials WHERE site_name = ?
                """,
                (site_name,)
            )
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            print(f"Failed to delete credential: {e}")
            return False

    def close(self):
        self.conn.close()
