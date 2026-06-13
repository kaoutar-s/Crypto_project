try:
    from .detector import TLSDetector
except ImportError:
    from detector import TLSDetector


sample = {
    "src_ip": "192.168.1.15",
    "dst_ip": "8.8.8.8",
    "tls_version": "TLS 1.0",
    "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "certificate_expired": True,
    "self_signed": False,
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
}

detector = TLSDetector()

alerts = detector.analyze(sample)

for alert in alerts:
    print(alert)
