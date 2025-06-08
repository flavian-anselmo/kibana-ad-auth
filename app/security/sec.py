import os
from cryptography.fernet import Fernet
import logging

ENCRYPTION_KEY = os.getenv("AD_SYNC_ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    
    logging.error(f"No ecryption key generated {ENCRYPTION_KEY}")

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_text(plain_text: str) -> str:
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_text(encrypted_text: str) -> str:
    return fernet.decrypt(encrypted_text.encode()).decode()
