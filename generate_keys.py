from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
           backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def save_rsa_keypair(private_key, public_key, private_key_path, public_key_path):
    encryption = serialization.NoEncryption()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print(f"RSA key pair generated and saved to {private_key_path} and {public_key_path}")