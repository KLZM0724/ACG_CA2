# ACG_CA2
Secure File Transfer Application

A cryptographically secure file transfer system implementing RSA-AES hybrid encryption with digital signatures for authentication and integrity verification.

## 🔐 How It Works

### Security Architecture

This application uses **hybrid cryptography** combining the strengths of both symmetric and asymmetric encryption:

1. **RSA (Asymmetric) Encryption**: Used for secure key exchange
2. **AES-256-CBC (Symmetric) Encryption**: Used for efficient file encryption
3. **Digital Signatures (RSA-PKCS#1 v1.5)**: Ensures file integrity and authenticity
4. **SHA-256 Hashing**: Creates message digests for signature verification

### Transfer Process Flow

```
CLIENT SIDE:                           SERVER SIDE:
┌─────────────────┐                   ┌─────────────────┐
│ 1. Read File    │                   │ 7. Receive Data │
│ 2. Generate AES │                   │ 8. Decrypt AES  │
│ 3. Encrypt File │ ── Encrypted ──> │ 9. Decrypt File │
│ 4. Sign Hash    │    Data Stream    │ 10. Verify Sig  │
│ 5. Encrypt AES  │                   │ 11. Save File   │
│ 6. Send All     │                   │                 │
└─────────────────┘                   └─────────────────┘
```

### Step-by-Step Security Process

**Client (Sender):**
1. **File Reading**: Loads the file to be transferred
2. **AES Key Generation**: Creates random 256-bit AES key and 128-bit IV
3. **File Encryption**: Encrypts file using AES-256-CBC with PKCS#7 padding
4. **Digital Signing**: 
   - Creates SHA-256 hash of original file
   - Signs hash with client's RSA private key
5. **Key Protection**: Encrypts AES key with server's RSA public key
6. **Secure Transmission**: Sends metadata, encrypted key, signature, and encrypted file

**Server (Receiver):**
1. **Data Reception**: Receives all components in sequence
2. **Key Decryption**: Decrypts AES key using server's RSA private key
3. **File Decryption**: Decrypts file data using recovered AES key and IV
4. **Integrity Verification**:
   - Computes SHA-256 hash of decrypted file
   - Verifies signature using client's RSA public key
5. **File Storage**: Saves file only if signature verification passes

### Security Guarantees

- **Confidentiality**: AES-256 encryption ensures data cannot be read by unauthorized parties
- **Integrity**: Digital signatures detect any tampering or corruption
- **Authentication**: RSA signatures prove the file came from the legitimate sender
- **Non-repudiation**: Sender cannot deny sending the file due to digital signatures
- **Forward Secrecy**: Each transfer uses a unique AES key

## 🚀 How to Run the Program

1. **Install Dependencies**
   - Make sure you have Python 3 installed.
   - Install required packages using pip:
     ```
     pip install pycryptodome
     ```

2. **Generate RSA Keys**
   - Use the provided `generate_keys.py` script to generate RSA key pairs for the client and server:
     ```
     python src/generate_keys.py
     ```

3. **Start the Server**
   - Run the server script:
     ```
     python src/server.py
     ```
   - You should see: `[+] Server listening on 0.0.0.0:5000`

4. **Run the Client**
   - In a separate terminal, run the client script:
     ```
     python src/client.py
     ```

5. **File Transfer**
   - Place your file in the root directory and name it `test_text.txt` (or modify the client code in `src/client.py` to use a different filename)
   - The client will automatically transfer the file securely to the server

## ✅ Verifying Security

### Success Indicators

**Server Output Should Show:**
```
[+] Connection from ('127.0.0.1', [port])
[+] Receiving file: test_file.txt
[i] Encrypted file size: [size] bytes
[+] Signature verified. Integrity intact.
[+] File saved to received_files/test_file.txt
```

**Client Output Should Show:**
```
[+] Connected to server.
[+] File sent securely.
```

### Security Verification

- **Signature Verification**: If you see `[+] Signature verified. Integrity intact.`, the file is authentic and unmodified
- **File Integrity**: Compare original and received files - they should be identical
- **Encryption in Transit**: All data sent over the network is encrypted

## 📁 Directory Structure


```
ACG_CA2-1/
├── contributions.txt            # Contributors and their roles
├── README.md                    # This documentation
├── test_text.txt                # Example file to transfer (default)
├── src/
│   ├── client.py                # Client implementation
│   ├── server.py                # Server implementation
│   ├── crypto_utils.py          # Cryptographic functions
│   └── generate_keys.py         # Key generation utility
└── (keys/ and received_files/ will be created at runtime)
```

**Notes:**
- The `keys/` directory and key files are generated by running `src/generate_keys.py`.
- The `received_files/` directory is created automatically by the server to store received files.
- The default file to transfer is `test_text.txt` in the project root. You can change this in `src/client.py`.
- Only files that pass signature verification are saved by the server.
# 🧑‍💻 Contributions

See `contributions.txt` for a detailed breakdown of each team member's contributions.
