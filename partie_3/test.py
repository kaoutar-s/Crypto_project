# partie_3/test_complet.py

from partie_3.key_manager import generate_keys
from partie_3.signer import sign_alert
from partie_3.verifier import verify_alert
from partie_3.database import init_db, insert_alert, get_all_alerts
from partie_3.exporter import export_signed_report

print("\n=== ÉTAPE 6 : Création de report.json ===")
export_signed_report("report.json")
print("report.json créé ! Donne ce fichier au Membre D")

# ============================================
# SIMULATION : alerte envoyée par le Membre B
# ============================================
alerte_du_membre_B = {
    "timestamp": "2025-05-30T10:45:00",
    "severity": "critical",
    "alert_type": "weak_cipher",
    "source_ip": "192.168.1.10",
    "dest_ip": "8.8.8.8",
    "details": {
        "tls_version": "TLS 1.0",
        "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
        "message": "Cipher suite très faible détectée"
    }
}

# ============================================
# ÉTAPE 1 : Générer les clés (une seule fois)
# ============================================
print("=== ÉTAPE 1 : Génération des clés ===")
generate_keys()

# ============================================
# ÉTAPE 2 : Signer l'alerte
# ============================================
print("\n=== ÉTAPE 2 : Signature de l'alerte ===")
alerte_signee = sign_alert(alerte_du_membre_B)
print("Alerte signée avec succès !")
print(f"Signature : {alerte_signee['signature'][:40]}...")

# ============================================
# ÉTAPE 3 : Vérifier la signature
# ============================================
print("\n=== ÉTAPE 3 : Vérification ===")
resultat = verify_alert(alerte_signee)
print(f"Signature valide ? {resultat}")  # doit afficher True

# ============================================
# ÉTAPE 4 : Stocker dans la base de données
# ============================================
print("\n=== ÉTAPE 4 : Stockage dans SQLite ===")
init_db()
id_alerte = insert_alert(alerte_signee)
print(f"Alerte sauvegardée avec l'ID : {id_alerte}")

# ============================================
# ÉTAPE 5 : Relire depuis la base de données
# ============================================
print("\n=== ÉTAPE 5 : Lecture depuis la BD ===")
toutes_les_alertes = get_all_alerts()
print(f"Nombre d'alertes dans la BD : {len(toutes_les_alertes)}")
print(f"Première alerte : {toutes_les_alertes[0]['alert_type']} - {toutes_les_alertes[0]['severity']}")

# ============================================
# BONUS : Test de falsification
# ============================================
print("\n=== BONUS : Test de falsification ===")
alerte_falsifiee = alerte_signee.copy()
alerte_falsifiee["severity"] = "info"  # quelqu'un essaie de changer le niveau
resultat_falsifie = verify_alert(alerte_falsifiee)
print(f"Alerte falsifiée acceptée ? {resultat_falsifie}")  # doit afficher False

print("\n✓ Tout fonctionne correctement !")