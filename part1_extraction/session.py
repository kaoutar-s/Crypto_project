# session.py
# Rôle : orchestrer tous les modules et produire
# un objet JSON complet par session TLS capturée

import uuid
import time
import json

# Importer nos modules
from part1_extraction.capture    import extraire_payload, est_client_hello, est_server_hello
from part1_extraction.tls_parser import parser_client_hello, parser_server_hello
from part1_extraction.cert_parser import extraire_certificat_depuis_paquet, analyser_certificat
from part1_extraction.ja3        import calculer_ja3, calculer_ja3s

import scapy.all as scapy


def construire_session(paquet_client, paquet_serveur=None):
    """
    Construit un enregistrement de session TLS complet.
    
    paquet_client : paquet scapy contenant le ClientHello
    paquet_serveur : paquet scapy contenant le ServerHello (optionnel)
    
    Retourne : dictionnaire Python prêt à être sérialisé en JSON
    """
    session = {
        "session_id":   str(uuid.uuid4()),
        "timestamp":    time.time(),
        "src_ip":       None,
        "dst_ip":       None,
        "src_port":     None,
        "dst_port":     None,
        "client_hello": None,
        "server_hello": None,
        "certificat":   None,
        "empreintes": {
            "ja3":        None,
            "ja3_brut":   None,
            "ja3s":       None,
            "ja3s_brut":  None,
        }
    }
    
    # ── Extraire les IPs et ports ──
    if paquet_client and paquet_client.haslayer(scapy.IP):
        session["src_ip"]   = paquet_client[scapy.IP].src
        session["dst_ip"]   = paquet_client[scapy.IP].dst
        session["src_port"] = paquet_client[scapy.TCP].sport
        session["dst_port"] = paquet_client[scapy.TCP].dport
    
    # ── Parser le ClientHello ──
    data_client = extraire_payload(paquet_client)
    if data_client and est_client_hello(data_client):
        session["client_hello"] = parser_client_hello(data_client)
        
        # Calculer JA3
        chaine, hash_md5 = calculer_ja3(session["client_hello"])
        session["empreintes"]["ja3"]      = hash_md5
        session["empreintes"]["ja3_brut"] = chaine
    
    # ── Parser le ServerHello ──
    if paquet_serveur:
        data_serveur = extraire_payload(paquet_serveur)
        
        if data_serveur and est_server_hello(data_serveur):
            session["server_hello"] = parser_server_hello(data_serveur)
            
            # Calculer JA3S
            chaine_s, hash_s = calculer_ja3s(session["server_hello"])
            session["empreintes"]["ja3s"]      = hash_s
            session["empreintes"]["ja3s_brut"] = chaine_s
        
        # Chercher le certificat dans ce paquet ou les suivants
        cert_bytes = extraire_certificat_depuis_paquet(data_serveur) if data_serveur else None
        if cert_bytes:
            session["certificat"] = analyser_certificat(cert_bytes)
    
    return session


def sessions_depuis_pcap(chemin_pcap):
    """
    Analyse un fichier PCAP complet et retourne
    la liste de toutes les sessions TLS trouvées.
    """
    from part1_extraction.capture import capture_depuis_pcap
    
    paquets = capture_depuis_pcap(chemin_pcap)
    sessions = []
    
    print(f"\n[*] Analyse de {len(paquets)} paquets TLS...")
    
    for i, paquet in enumerate(paquets):
        data = extraire_payload(paquet)
        if not data:
            continue
        
        # Si c'est un ClientHello → créer une nouvelle session
        if est_client_hello(data):
            # Chercher le ServerHello dans les paquets suivants
            paquet_serveur = None
            for j in range(i+1, min(i+20, len(paquets))):
                data_suiv = extraire_payload(paquets[j])
                if data_suiv and est_server_hello(data_suiv):
                    paquet_serveur = paquets[j]
                    break
            
            session = construire_session(paquet, paquet_serveur)
            sessions.append(session)
            print(f"  [+] Session trouvee : {session['src_ip']} -> {session['dst_ip']} "
                  f"| JA3: {session['empreintes']['ja3']}")
    
    print(f"\n[+] Total : {len(sessions)} sessions TLS extraites")
    return sessions


def sauvegarder_sessions(sessions, fichier_sortie="sessions_tls.json"):
    """
    Sauvegarde toutes les sessions dans un fichier JSON.
    """
    with open(fichier_sortie, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2, ensure_ascii=False, default=str)
    print(f"[+] Sessions sauvegardées dans : {fichier_sortie}")


def afficher_session(session):
    """
    Affiche une session de manière lisible dans le terminal.
    """
    print("\n" + "="*60)
    print(f"  SESSION TLS")
    print("="*60)
    print(f"  ID          : {session['session_id'][:8]}...")
    print(f"  Source      : {session['src_ip']}:{session['src_port']}")
    print(f"  Destination : {session['dst_ip']}:{session['dst_port']}")
    
    if session.get("client_hello"):
        ch = session["client_hello"]
        print(f"  TLS version : {ch.get('version_nom')}")
        print(f"  SNI         : {ch.get('sni', 'N/A')}")
        print(f"  Cipher suites: {len(ch.get('cipher_suites', []))} proposées")
    
    print(f"  JA3         : {session['empreintes']['ja3']}")
    print(f"  JA3S        : {session['empreintes']['ja3s']}")
    
    if session.get("certificat"):
        cert = session["certificat"]
        print(f"  Certificat  : {cert.get('subject', 'N/A')}")
        print(f"  Expire      : {'OUI !' if cert.get('est_expire') else 'NON OK'}")
        print(f"  Auto-signe  : {'OUI !' if cert.get('est_auto_signe') else 'NON OK'}")
    
    print("="*60)


# ─── PROGRAMME PRINCIPAL ─────────────────────────────────
if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("  PARTIE 1 - EXTRACTION TLS")
    print("="*60)
    
    if len(sys.argv) > 1:
        # Mode fichier PCAP : python session.py mon_fichier.pcap
        chemin_pcap = sys.argv[1]
        sessions = sessions_depuis_pcap(chemin_pcap)
        
        for s in sessions:
            afficher_session(s)
        
        sauvegarder_sessions(sessions, "sessions_tls.json")
    
    else:
        print("\n[!] Usage : python session.py <fichier.pcap>")
        print("[!] Exemple : python session.py test.pcap")
        print("\n[*] Pour obtenir un fichier PCAP de test :")
        print("    https://wiki.wireshark.org/SampleCaptures")
        print("    Cherche 'ssl' ou 'tls' dans la liste")
