from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
import json

private_key = None  # Replace with actual private key in PEM format

class Decryptor:
    def __init__(self):
        self.home = Path.home()
        self.locations = ("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", "Public")
        self.files = []

    def load_private_key(self):
        self.private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
    
    def decrypt_file(self, path):
        encrypted_path = Path(path)
        output_path = encrypted_path.with_suffix("")

        with open(encrypted_path, "rb") as infile:
            metadat_len = int.from_bytes(infile.read(4), "big")
            metadata_json = infile.read(metadat_len)
            metadata = json.loads(metadata_json.decode())

            encrypted_aes_key = bytes.fromhex(metadata["encrypted_key"])
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            iv = bytes.fromhex(metadata["iv"])

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            with open(output_path, "wb") as outfile:
                decrypted_data = b""
                
                while True:
                    chunk = infile.read(8192)
                    if not chunk:
                        break
                    decrypted_data += decryptor.update(chunk)
                
                decrypted_data += decryptor.finalize()
                unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
                outfile.write(unpadded_data)
        
        return output_path
    
    def find_files(self):
        for location in self.locations:
            folder = self.home / location
            
            if folder.exists() and folder.is_dir():
                for file in folder.rglob("*"):
                    if file.is_file() and file.suffix == ".enc":
                        self.files.append(file)
    
    def decrypt_files(self):
        for file in self.files:
            try:
                decrypted_file = self.decrypt_file(file)
            except:
                pass