# crypto_utils.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# RSA
def load_rsa_private_key(path: str):
    try:
        with open(path, 'rb') as f:
            return RSA.import_key(f.read())
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def load_rsa_public_key(path: str):
    try:
        with open(path, 'rb') as f:
            return RSA.import_key(f.read())
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None

def encrypt_with_rsa(public_key: RSA.RsaKey, data: bytes) -> bytes:
    try:
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)
    except Exception as e:
        print(f"RSA encryption error: {e}")
        return None

def decrypt_with_rsa(private_key: RSA.RsaKey, data: bytes) -> bytes:
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(data)
    except Exception as e:
        print(f"RSA decryption error: {e}")
        return None

# AES
def generate_aes_key_iv() -> tuple[bytes, bytes]:
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)
    return key, iv

def encrypt_file_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        return cipher.encrypt(padded_data)
    except Exception as e:
        print(f"AES encryption error: {e}")
        return None

def decrypt_file_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, AES.block_size)
    except Exception as e:
        print(f"AES decryption error: {e}")
        return None

# AES-GCM Authenticated Encryption (Recommended)
def encrypt_file_aes_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag
    except Exception as e:
        print(f"AES-GCM encryption error: {e}")
        return None, None, None

def decrypt_file_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print(f"AES-GCM decryption error: {e}")
        return None

# SHA-256 Hash
def sha256_digest(data: bytes) -> bytes:
    h = SHA256.new(data)
    return h

# Digital Signature
def sign_digest(private_key: RSA.RsaKey, digest: SHA256.SHA256Hash) -> bytes:
    try:
        return pkcs1_15.new(private_key).sign(digest)
    except Exception as e:
        print(f"Signing error: {e}")
        return None

def verify_signature(public_key: RSA.RsaKey, digest: SHA256.SHA256Hash, signature: bytes) -> bool:
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError) as e:
        print(f"Signature verification failed: {e}")
        return False
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False
