import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from partie_3.key_manager import load_public_key

def verify_alert(signed_alert: dict) -> bool:
    try:
        public_key = load_public_key()

        # Reconstruire les données SANS signature et signed_data
        original_alert = {k: v for k, v in signed_alert.items() 
                         if k not in ("signature", "signed_data")}
        
        # Recanonicalize comme dans signer.py
        alert_json = json.dumps(original_alert, sort_keys=True, ensure_ascii=False).encode("utf-8")
        
        signature = base64.b64decode(signed_alert["signature"])
        public_key.verify(signature, alert_json, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"[!] Erreur de vérification : {e}")
        return False