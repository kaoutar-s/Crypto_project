# cert_parser.py
# Rôle : extraire et analyser le certificat X509 du serveur
# (reçu dans le message Certificate du handshake TLS)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import struct


def extraire_certificat_depuis_paquet(data):
    """
    Extrait les octets bruts du certificat depuis un paquet TLS.
    Le message Certificate a le type 11 dans le handshake.
    """
    try:
        # Vérifier TLS Handshake
        if not data or data[0] != 22:
            return None
        # Type 11 = Certificate
        if data[5] != 11:
            return None
        
        # Naviguer jusqu'aux données du certificat
        # Structure : [TLS Record 5 octets][Handshake header 4 octets]
        # [Certificates list length 3 octets][Cert length 3 octets][Cert DER]
        pos = 9 + 3   # après en-têtes + longueur liste
        
        if pos + 3 > len(data):
            return None
        
        # Longueur du premier certificat (3 octets big-endian)
        cert_len = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2]
        pos += 3
        
        if pos + cert_len > len(data):
            return None
        
        # Retourner les octets DER du certificat
        return data[pos:pos+cert_len]
    
    except Exception as e:
        print(f"[!] Erreur extraction certificat : {e}")
        return None


def analyser_certificat(cert_bytes):
    """
    Analyse un certificat X509 en format DER.
    Retourne toutes les informations importantes.
    cert_bytes : octets bruts du certificat
    """
    try:
        # Charger le certificat
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        maintenant = datetime.datetime.utcnow()
        
        # Extraire les Subject Alternative Names (SAN)
        san_liste = []
        try:
            ext_san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_liste = [str(nom) for nom in ext_san.value]
        except x509.ExtensionNotFound:
            pass
        
        # Construire le résultat
        resultat = {
            "subject":       cert.subject.rfc4514_string(),
            "issuer":        cert.issuer.rfc4514_string(),
            "numero_serie":  str(cert.serial_number),
            "valide_depuis": cert.not_valid_before.isoformat(),
            "valide_jusqu":  cert.not_valid_after.isoformat(),
            "est_expire":    maintenant > cert.not_valid_after,
            "est_auto_signe": cert.issuer == cert.subject,
            "san":           san_liste,
            "version":       cert.version.name,
        }
        
        # Calculer jours restants avant expiration
        if not resultat["est_expire"]:
            delta = cert.not_valid_after - maintenant
            resultat["jours_restants"] = delta.days
        else:
            delta = maintenant - cert.not_valid_after
            resultat["jours_restants"] = -delta.days  # négatif = expiré depuis X jours
        
        return resultat
    
    except Exception as e:
        print(f"[!] Erreur analyse certificat : {e}")
        return None


def afficher_certificat(info_cert):
    """
    Affiche les infos du certificat de manière lisible.
    """
    if not info_cert:
        print("[!] Pas d'info certificat à afficher")
        return
    
    print("\n" + "="*50)
    print("  CERTIFICAT X509")
    print("="*50)
    print(f"  Subject      : {info_cert['subject']}")
    print(f"  Issuer       : {info_cert['issuer']}")
    print(f"  Valide du    : {info_cert['valide_depuis']}")
    print(f"  Valide jusqu : {info_cert['valide_jusqu']}")
    print(f"  Expire       : {'OUI !' if info_cert['est_expire'] else 'NON OK'}")
    print(f"  Auto-signe   : {'OUI !' if info_cert['est_auto_signe'] else 'NON OK'}")
    print(f"  Jours restants: {info_cert['jours_restants']}")
    if info_cert['san']:
        print(f"  SAN          : {', '.join(info_cert['san'])}")
    print("="*50)


# ─── TEST ───────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] cert_parser.py - s'utilise importe depuis session.py")
