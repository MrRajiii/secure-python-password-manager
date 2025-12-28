# Secure Password Manager (PyQt5)
<p align="left">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PyQt5-41CD52?style=for-the-badge&logo=qt&logoColor=white" alt="PyQt5">
  <img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Cryptography-0769AD?style=for-the-badge&logo=gnuprivacyguard&logoColor=white" alt="Cryptography">
</p>
A robust, cross-platform desktop application for securely managing user credentials. Built with Python and PyQt5, emphasizing cryptographic best practices.

## Features

* **Full CRUD Functionality:** Easily Create, Read, Update, and Delete credentials.
* **Secure Authentication:** Uses a single Master Password to unlock the vault.
* **Encrypted Storage:** All credentials are encrypted before being stored in an SQLite database.
* **Professional GUI:** Built using PyQt5 for a clean, native desktop look and feel.

## Security Architecture

This project is designed with a strong focus on data security, using industry-standard primitives from the `cryptography` library.

1.  **Key Derivation:** The Master Password is never stored directly. It is stretched using **PBKDF2 with SHA-256** and a high iteration count (**480,000+ iterations**) and a unique salt to generate a strong, 32-byte encryption key. This process makes brute-force attacks computationally infeasible.
2.  **Authenticated Encryption:** All sensitive data (usernames, passwords) is encrypted using **AES-256 GCM** (via the Fernet specification). This method not only encrypts the data but also ensures its **integrity** (guaranteeing that the stored data has not been tampered with).

## 🛠️ Technologies Used

* **Language:** Python 3.x
* **GUI Framework:** PyQt5
* **Database:** SQLite3
* **Cryptography:** `cryptography` library (PBKDF2, Fernet/AES-256 GCM)

## Installation and Setup

1.  **Clone the Repository:**
    ```bash
    git clone [YOUR_REPO_URL]
    cd [YOUR_REPO_NAME]
    ```

2.  **Install Dependencies:**
    ```bash
    pip install PyQt5 cryptography
    ```

3.  **Run the Application:**
    ```bash
    python password_gui.py
    ```

### First Run: Initialization
On the first run, the application will detect the missing configuration and prompt you to set your new, secure Master Password.

***

Now you can run the following commands to add these two new critical files and push everything cleanly:

1.  **Stage the new files:**
    ```bash
    git add .
    ```
2.  **Commit the final project:**
    ```bash
    git commit -m "feat: Final project completion with PyQt5 GUI, full CRUD, and crucial documentation/git setup"
    ```
3.  **Push to your remote repository:**
    ```bash
    git push
    ```
