from cryptography.fernet import Fernet
import os

def generate_and_print_key():
    # Check if key already exists in env
    existing_key = os.getenv("AD_SYNC_ENCRYPTION_KEY")
    if existing_key:
        print(f"Encryption key already set in environment: {existing_key}")
        return existing_key

    # Fernet key
    new_key = Fernet.generate_key().decode()
    print("===== IMPORTANT =====")
    print("Generated new encryption key. Save this securely!")
    print(f"AD_SYNC_ENCRYPTION_KEY={new_key}")
    print(f'RUN: export AD_SYNC_ENCRYPTION_KEY={new_key}')
    print("=====================")
    return new_key

if __name__ == "__main__":
    generate_and_print_key()