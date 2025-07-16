# server.py
import socket
import json
import os
from crypto_utils import (
    load_rsa_private_key,
    load_rsa_public_key,
    decrypt_with_rsa,
    decrypt_file_aes,
    sha256_digest,
    verify_signature,
)

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000

SERVER_PRIV_KEY_PATH = "keys/server_private.pem"
CLIENT_PUB_KEY_PATH = "keys/client_public.pem"

BUFFER_SIZE = 4096
SAVE_DIR = "received_files"

os.makedirs(SAVE_DIR, exist_ok=True)


def handle_client(conn: socket.socket):
    try:
        # 1. Read metadata length
        meta_len_bytes = conn.recv(4)
        if not meta_len_bytes:
            print("[!] No metadata length received.")
            return
        meta_len = int.from_bytes(meta_len_bytes, "big")

        # 2. Read metadata JSON
        metadata_json = conn.recv(meta_len)
        metadata = json.loads(metadata_json.decode())
        filename = metadata["filename"]
        iv = bytes.fromhex(metadata["iv"])
        encrypted_key_len = metadata["encrypted_key_len"]
        signature_len = metadata["signature_len"]
        file_len = metadata["file_len"]

        print(f"[+] Receiving file: {filename}")
        print(f"[i] Encrypted file size: {file_len} bytes")

        # 3. Read encrypted AES key
        encrypted_aes_key = b""
        while len(encrypted_aes_key) < encrypted_key_len:
            chunk = conn.recv(encrypted_key_len - len(encrypted_aes_key))
            if not chunk:
                raise Exception("Connection closed while receiving AES key.")
            encrypted_aes_key += chunk

        # 4. Read signature
        signature = b""
        while len(signature) < signature_len:
            chunk = conn.recv(signature_len - len(signature))
            if not chunk:
                raise Exception("Connection closed while receiving signature.")
            signature += chunk

        # 5. Read encrypted file data
        encrypted_data = b""
        while len(encrypted_data) < file_len:
            chunk = conn.recv(min(BUFFER_SIZE, file_len - len(encrypted_data)))
            if not chunk:
                raise Exception("Connection closed while receiving file.")
            encrypted_data += chunk

        # 6. Decrypt AES key with server private key
        server_private_key = load_rsa_private_key(SERVER_PRIV_KEY_PATH)
        aes_key = decrypt_with_rsa(server_private_key, encrypted_aes_key)

        # 7. Decrypt file with AES key
        decrypted_data = decrypt_file_aes(encrypted_data, aes_key, iv)

        # 8. Verify signature using client public key
        client_public_key = load_rsa_public_key(CLIENT_PUB_KEY_PATH)
        digest = sha256_digest(decrypted_data)
        if verify_signature(client_public_key, digest, signature):
            print("[+] Signature verified. Integrity intact.")
            # Save file
            save_path = os.path.join(SAVE_DIR, filename)
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            print(f"[+] File saved to {save_path}")
        else:
            print("[!] Signature verification failed. File rejected.")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(5)
    print(f"[+] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        conn, addr = s.accept()
        print(f"[+] Connection from {addr}")
        handle_client(conn)


if __name__ == "__main__":
    start_server()
