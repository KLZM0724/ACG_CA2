# generate_keys.py
import os
from Crypto.PublicKey import RSA

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_rsa_keypair(name: str, key_size: int = 2048):
    """Generate RSA private and public keys and save them to files."""
    key = RSA.generate(key_size)

    private_key_path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    public_key_path = os.path.join(KEYS_DIR, f"{name}_public.pem")

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(key.export_key())
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    print(f"[+] Generated {name} key pair:")
    print(f"    Private: {private_key_path}")
    print(f"    Public : {public_key_path}")

if __name__ == "__main__":
    print("[*] Generating RSA key pairs...")
    generate_rsa_keypair("server")
    generate_rsa_keypair("client")
    print("[✓] All keys generated in 'keys/' directory.")
