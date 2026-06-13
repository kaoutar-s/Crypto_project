from partie_3.key_manager import generate_keys
from partie_3.signer import sign_alert
from partie_3.verifier import verify_alert

def test_sign_and_verify():
    generate_keys()

    alert = {
        "timestamp": "2025-01-01T00:00:00",
        "severity": "critical",
        "alert_type": "weak_cipher",
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "details": {"cipher": "TLS_RSA_WITH_RC4_128_MD5"}
    }

    signed = sign_alert(alert)
    assert verify_alert(signed) == True, "La vérification doit réussir"

    # Test de falsification
    signed["severity"] = "info"  # Modification après signature
    assert verify_alert(signed) == False, "Alerte falsifiée doit échouer"

    print("[✓] Tous les tests passent.")

if __name__ == "__main__":
    test_sign_and_verify()