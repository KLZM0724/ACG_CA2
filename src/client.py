# client.py
import os
import socket
import json
from crypto_utils import (
    load_rsa_private_key,
    load_rsa_public_key,
    generate_aes_key_iv,
    encrypt_file_aes,
    sha256_digest,
    sign_digest,
    encrypt_with_rsa,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

CLIENT_PRIV_KEY_PATH = "keys/client_private.pem"
SERVER_PUB_KEY_PATH = "keys/server_public.pem"

BUFFER_SIZE = 4096


def send_secure_file(filepath: str):
    # Load keys
    client_private_key = load_rsa_private_key(CLIENT_PRIV_KEY_PATH)
    server_public_key = load_rsa_public_key(SERVER_PUB_KEY_PATH)

    # Read file
    with open(filepath, "rb") as f:
        file_data = f.read()

    # Generate AES key & IV
    aes_key, iv = generate_aes_key_iv()

    # Encrypt file
    encrypted_data = encrypt_file_aes(file_data, aes_key, iv)

    # Hash and sign
    digest = sha256_digest(file_data)
    signature = sign_digest(client_private_key, digest)

    # Encrypt AES key with server's public key
    encrypted_aes_key = encrypt_with_rsa(server_public_key, aes_key)

    # Prepare metadata
    metadata = {
        "filename": os.path.basename(filepath),
        "iv": iv.hex(),
        "encrypted_key_len": len(encrypted_aes_key),
        "signature_len": len(signature),
        "file_len": len(encrypted_data),
    }
    metadata_bytes = json.dumps(metadata).encode()

    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((SERVER_HOST, SERVER_PORT))
        print("[+] Connected to server.")

        # Send metadata length first
        s.sendall(len(metadata_bytes).to_bytes(4, "big"))
        s.sendall(metadata_bytes)

        # Send encrypted AES key
        s.sendall(encrypted_aes_key)

        # Send signature
        s.sendall(signature)

        # Send encrypted file in chunks
        sent = 0
        while sent < len(encrypted_data):
            chunk = encrypted_data[sent : sent + BUFFER_SIZE]
            s.sendall(chunk)
            sent += len(chunk)

        print("[+] File sent securely.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    # Example usage
    file_to_send = "test_file.txt"  # ensure this exists
    if os.path.exists(file_to_send):
        send_secure_file(file_to_send)
    else:
        print("[!] File not found.")
