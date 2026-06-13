import json, base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from partie_3.key_manager import load_private_key
from partie_3.database import get_all_alerts

def export_signed_report(output_path: str = "report.json"):
    """
    Exporte toutes les alertes dans un fichier JSON
    avec une signature globale du rapport.
    """
    alerts = get_all_alerts()
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    report_bytes = json.dumps(report, sort_keys=True, ensure_ascii=False).encode()
    private_key  = load_private_key()
    signature    = private_key.sign(report_bytes, ec.ECDSA(hashes.SHA256()))

    final = {
        "report": report,
        "report_signature": base64.b64encode(signature).decode()
    }

    with open(output_path, "w") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)

    print(f"[OK] Rapport exporte : {output_path}")
    return final
