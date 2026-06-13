import ipaddress
import re

try:
    from .alert_engine import create_alert
    from .rules import (
        BLACKLISTED_JA3,
        BLACKLISTED_JA3S,
        CERT_EXPIRY_WARNING_DAYS,
        MAX_REASONABLE_CIPHER_SUITES,
        SUSPICIOUS_SNI_KEYWORDS,
        WEAK_CIPHER_IDS,
        WEAK_CIPHER_KEYWORDS,
        WEAK_TLS_VERSIONS,
    )
except ImportError:
    from alert_engine import create_alert
    from rules import (
        BLACKLISTED_JA3,
        BLACKLISTED_JA3S,
        CERT_EXPIRY_WARNING_DAYS,
        MAX_REASONABLE_CIPHER_SUITES,
        SUSPICIOUS_SNI_KEYWORDS,
        WEAK_CIPHER_IDS,
        WEAK_CIPHER_KEYWORDS,
        WEAK_TLS_VERSIONS,
    )


SNI_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")


def _clean_sni(value):
    if not value:
        return None
    return str(value).strip().strip("\x00").lower()


def _ip_is_public(ip_value):
    if not ip_value:
        return False
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)


def normalize_tls_session(tls_data):
    """
    Accept either the old flat sample used by part 2 or a full TLS session
    produced by part1_extraction.session.
    """
    client_hello = tls_data.get("client_hello") or {}
    server_hello = tls_data.get("server_hello") or {}
    cert = tls_data.get("certificat") or {}
    fingerprints = tls_data.get("empreintes") or {}

    tls_version = (
        tls_data.get("tls_version")
        or server_hello.get("version_nom")
        or client_hello.get("version_nom")
    )

    cipher_suite = (
        tls_data.get("cipher_suite")
        or server_hello.get("cipher_suite_choisie")
    )

    cipher_suites = tls_data.get("cipher_suites")
    if cipher_suites is None:
        cipher_suites = client_hello.get("cipher_suites", [])

    return {
        "session_id": tls_data.get("session_id"),
        "src_ip": tls_data.get("src_ip"),
        "dst_ip": tls_data.get("dst_ip"),
        "src_port": tls_data.get("src_port"),
        "dst_port": tls_data.get("dst_port"),
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "cipher_suites": cipher_suites or [],
        "certificate_expired": bool(
            tls_data.get("certificate_expired", cert.get("est_expire", False))
        ),
        "self_signed": bool(
            tls_data.get("self_signed", cert.get("est_auto_signe", False))
        ),
        "certificate_days_remaining": tls_data.get(
            "certificate_days_remaining", cert.get("jours_restants")
        ),
        "has_certificate": bool(cert) or tls_data.get("has_certificate", False),
        "sni": _clean_sni(tls_data.get("sni") or client_hello.get("sni")),
        "ja3": tls_data.get("ja3") or fingerprints.get("ja3"),
        "ja3s": tls_data.get("ja3s") or fingerprints.get("ja3s"),
        "raw": tls_data,
    }


def _cipher_is_weak(cipher):
    if cipher is None:
        return False
    if isinstance(cipher, int):
        return cipher in WEAK_CIPHER_IDS
    if isinstance(cipher, str):
        upper = cipher.upper()
        return any(keyword in upper for keyword in WEAK_CIPHER_KEYWORDS)
    return False


class TLSDetector:
    def analyze(self, tls_data):
        tls_data = normalize_tls_session(tls_data)
        alerts = []

        src_ip = tls_data.get("src_ip")
        dst_ip = tls_data.get("dst_ip")
        ja3 = tls_data.get("ja3")
        session_id = tls_data.get("session_id")

        def add(severity, rule, description, **details):
            alerts.append(
                create_alert(
                    severity,
                    rule,
                    description,
                    src_ip,
                    dst_ip,
                    ja3,
                    session_id=session_id,
                    details={
                        "session_id": session_id,
                        "src_port": tls_data.get("src_port"),
                        "dst_port": tls_data.get("dst_port"),
                        "sni": tls_data.get("sni"),
                        **details,
                    },
                )
            )

        if tls_data.get("tls_version") in WEAK_TLS_VERSIONS:
            add(
                "warning",
                "Weak TLS Version",
                f"{tls_data['tls_version']} detected",
                tls_version=tls_data.get("tls_version"),
            )

        if tls_data.get("certificate_expired"):
            add(
                "critical",
                "Expired Certificate",
                "Server certificate expired",
                certificate_days_remaining=tls_data.get("certificate_days_remaining"),
            )
        elif tls_data.get("certificate_days_remaining") is not None:
            if tls_data["certificate_days_remaining"] <= CERT_EXPIRY_WARNING_DAYS:
                add(
                    "warning",
                    "Certificate Near Expiry",
                    "Server certificate expires soon",
                    certificate_days_remaining=tls_data.get("certificate_days_remaining"),
                )

        if tls_data.get("self_signed"):
            add(
                "warning",
                "Self-Signed Certificate",
                "Self-signed certificate detected",
            )

        if not tls_data.get("has_certificate") and tls_data.get("dst_port") == 443:
            add(
                "info",
                "Missing Certificate",
                "No server certificate was extracted for this TLS session",
            )

        cipher = tls_data.get("cipher_suite")
        if _cipher_is_weak(cipher):
            add(
                "warning",
                "Weak Cipher Suite",
                f"Weak cipher detected: {cipher}",
                cipher_suite=cipher,
            )

        weak_offered = [c for c in tls_data.get("cipher_suites", []) if _cipher_is_weak(c)]
        if weak_offered:
            add(
                "warning",
                "Weak Offered Cipher",
                f"Client offered {len(weak_offered)} weak cipher suite(s)",
                weak_cipher_suites=weak_offered,
            )

        if len(tls_data.get("cipher_suites", [])) > MAX_REASONABLE_CIPHER_SUITES:
            add(
                "info",
                "Unusual Cipher Suite Count",
                "Client offered an unusually large cipher suite list",
                cipher_suite_count=len(tls_data.get("cipher_suites", [])),
            )

        sni = tls_data.get("sni")
        if not sni:
            add(
                "info",
                "Missing SNI",
                "ClientHello did not include a server name",
            )
        else:
            if not SNI_PATTERN.match(sni):
                add(
                    "warning",
                    "Malformed SNI",
                    f"Suspicious SNI value: {sni}",
                    sni=sni,
                )
            if any(keyword in sni for keyword in SUSPICIOUS_SNI_KEYWORDS):
                add(
                    "warning",
                    "Suspicious SNI",
                    f"Suspicious domain indicator in SNI: {sni}",
                    sni=sni,
                )

        if tls_data.get("ja3") in BLACKLISTED_JA3:
            add(
                "critical",
                "Suspicious JA3",
                "Known malicious fingerprint",
                ja3=tls_data.get("ja3"),
            )

        if tls_data.get("ja3s") in BLACKLISTED_JA3S:
            add(
                "critical",
                "Suspicious JA3S",
                "Known malicious server fingerprint",
                ja3s=tls_data.get("ja3s"),
            )

        if _ip_is_public(src_ip) and _ip_is_public(dst_ip):
            add(
                "info",
                "External TLS Flow",
                "Both endpoints are public IP addresses",
            )

        return alerts
