Secure CLI Password Manager
A secure command-line password manager built with Python that stores website credentials in an encrypted vault using modern cryptographic techniques like AES-GCM encryption and PBKDF2 key derivation.
This tool allows users to securely store, retrieve, list, and delete passwords while protecting them with a master password.
🚀 Features
🔐 AES-GCM Encryption for secure password storage
🔑 PBKDF2-HMAC (SHA-256) key derivation
🧂 Random salt generation for stronger security
📦 Encrypted JSON vault storage
🖥️ Simple Command Line Interface (CLI)
🔒 Brute-force protection with login attempt limit
⚡ Atomic file writing to prevent vault corruption
🔄 Ability to change master password
⚙️ How It Works
When the program runs for the first time, it creates a secure vault file (vault.json).
The user sets a master password to protect the vault.
The password is converted into a cryptographic key using PBKDF2-HMAC with SHA-256.
All stored credentials are encrypted using AES-GCM encryption.
When commands are executed (add, get, list, delete), the vault is temporarily decrypted using the master password.
After operations are completed, the vault is re-encrypted and saved securely.
📦 Installation

Install dependencies:

pip install cryptography
💻 Usage
Run the script using:

python vault.py <command>
Add a Password

python vault.py add google.com username
Get Stored Credentials

python vault.py get google.com
List All Stored Websites

python vault.py list
Delete an Entry

python vault.py delete google.com
Change Master Password

 Security Features
AES-256 GCM encryption
PBKDF2 key derivation with 200,000 iterations
Secure random nonce and salt generation
Protection against multiple failed login attempts
Atomic file operations to prevent data corruption.



