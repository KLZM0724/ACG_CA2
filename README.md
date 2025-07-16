# ACG_CA2
secure file transfer application

## How to Run the Program

1. **Install Dependencies**
   - Make sure you have Python 3 installed.
   - Install required packages using pip:
     ```
     pip install pycryptodome
     ```

2. **Generate RSA Keys**
   - Use the provided `generate_keys.py` script to generate RSA key pairs for the client and server.

3. **Start the Server**
   - Run the server script:
     ```
     python src/server.py
     ```

4. **Run the Client**
   - In a separate terminal, run the client script:
     ```
     python src/client.py
     ```

5. **File Transfer**
   - Follow the prompts in the client and server terminals to securely transfer files.

**Note:**  
- Ensure the `keys/` directory contains the correct public/private key files for both client and server.
- Encrypted files and received files will be stored in the `received_files/` directory.
