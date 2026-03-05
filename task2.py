import os
import sys
import json
import base64
import argparse
import getpass
import secrets
import tempfile
import shutil
import re
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.json"
PBKDF2_ITERATIONS = 200_000
LOCKOUT_THRESHOLD = 5

# =============================
# Utility Functions
# =============================

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode())

def validate_site(site: str) -> bool:
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, site) is not None

def atomic_write(filename: str, data: Dict[str, Any]):
    fd, temp_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as tmp:
        json.dump(data, tmp, indent=4)
    shutil.move(temp_path, filename)

# =============================
# Cryptographic Functions
# =============================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(key: bytes, plaintext: bytes):
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# =============================
# Vault Management
# =============================

def initialize_vault():
    print("Initializing new vault.")
    master_password = getpass.getpass("Create master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if master_password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    salt = secrets.token_bytes(16)
    key = derive_key(master_password, salt)

    vault_data = {
        "salt": b64encode(salt),
        "failed_attempts": 0,
        "data": None
    }

    nonce, ciphertext = encrypt_data(key, json.dumps({}).encode())
    vault_data["data"] = {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext)
    }

    atomic_write(VAULT_FILE, vault_data)
    print("Vault created successfully.")

def load_vault():
    if not os.path.exists(VAULT_FILE):
        initialize_vault()

    with open(VAULT_FILE, "r") as f:
        vault = json.load(f)

    if vault.get("failed_attempts", 0) >= LOCKOUT_THRESHOLD:
        print("Vault locked due to too many failed attempts.")
        sys.exit(1)

    master_password = getpass.getpass("Enter master password: ")
    salt = b64decode(vault["salt"])

    try:
        key = derive_key(master_password, salt)
        nonce = b64decode(vault["data"]["nonce"])
        ciphertext = b64decode(vault["data"]["ciphertext"])

        decrypted = decrypt_data(key, nonce, ciphertext)
        vault_data = json.loads(decrypted.decode())

        vault["failed_attempts"] = 0
        atomic_write(VAULT_FILE, vault)

        return key, vault, vault_data

    except Exception:
        vault["failed_attempts"] += 1
        atomic_write(VAULT_FILE, vault)
        print("Incorrect master password or corrupted vault.")
        sys.exit(1)

def save_vault(key: bytes, vault: Dict, vault_data: Dict):
    nonce, ciphertext = encrypt_data(key, json.dumps(vault_data).encode())
    vault["data"] = {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext)
    }
    atomic_write(VAULT_FILE, vault)

# =============================
# CLI Operations
# =============================

def add_entry(args):
    if not validate_site(args.site):
        print("Invalid website format.")
        return

    key, vault, data = load_vault()

    password = getpass.getpass("Enter password: ")

    data[args.site] = {
        "username": args.username,
        "password": password
    }

    save_vault(key, vault, data)
    print("Entry added.")

def get_entry(args):
    key, vault, data = load_vault()

    entry = data.get(args.site)
    if not entry:
        print("Site not found.")
        return

    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")

def list_entries(args):
    key, vault, data = load_vault()

    if not data:
        print("Vault is empty.")
        return

    for site in data:
        print(site)

def delete_entry(args):
    key, vault, data = load_vault()

    if args.site not in data:
        print("Site not found.")
        return

    del data[args.site]
    save_vault(key, vault, data)
    print("Entry deleted.")

def change_master_password(args):
    key, vault, data = load_vault()

    new_password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new password: ")

    if new_password != confirm:
        print("Passwords do not match.")
        return

    new_salt = secrets.token_bytes(16)
    new_key = derive_key(new_password, new_salt)

    vault["salt"] = b64encode(new_salt)
    save_vault(new_key, vault, data)

    print("Master password changed successfully.")

# =============================
# Main CLI Setup
# =============================

def main():
    parser = argparse.ArgumentParser(description="Secure CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("site")
    add_parser.add_argument("username")

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("site")

    subparsers.add_parser("list")

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("site")

    
    change_parser = subparsers.add_parser(
        "change-master",
        aliases=["changepw"],
        help="Change master password"
    )

    args = parser.parse_args()

    if args.command == "add":
        add_entry(args)
    elif args.command == "get":
        get_entry(args)
    elif args.command == "list":
        list_entries(args)
    elif args.command == "delete":
        delete_entry(args)
    elif args.command in ("change-master", "changepw"):
        change_master_password(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
