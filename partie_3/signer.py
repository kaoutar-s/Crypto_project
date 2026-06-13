import json, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from partie_3.key_manager import load_private_key

def sign_alert(alert: dict) -> dict:
    private_key = load_private_key()

    # Signer les données originales directement
    alert_json = json.dumps(alert, sort_keys=True, ensure_ascii=False).encode("utf-8")
    signature = private_key.sign(alert_json, ec.ECDSA(hashes.SHA256()))

    return {
        **alert,
        "signature": base64.b64encode(signature).decode()
        # signed_data supprimé — on recanonicalise à la vérification
    }