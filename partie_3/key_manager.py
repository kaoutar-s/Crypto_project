from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = "keys"

def generate_keys():
    """Génère une paire de clés ECDSA et les sauvegarde en PEM."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Sauvegarde clé privée
    with open(f"{KEYS_DIR}/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sauvegarde clé publique
    with open(f"{KEYS_DIR}/public_key.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[OK] Cles ECDSA generees.")

def load_private_key():
    with open(f"{KEYS_DIR}/private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    with open(f"{KEYS_DIR}/public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())
