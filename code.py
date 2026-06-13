import argparse
import importlib.util
import json
import sys
import sysconfig
from pathlib import Path

from partie2_moteursoc.detector import TLSDetector


def preload_stdlib_code_module():
    """
    This entrypoint is named code.py. Scapy imports Python's standard library
    code module, so preload it to prevent this file from shadowing it.
    """
    if "code" in sys.modules and hasattr(sys.modules["code"], "InteractiveInterpreter"):
        return

    stdlib_code = Path(sysconfig.get_path("stdlib")) / "code.py"
    spec = importlib.util.spec_from_file_location("code", stdlib_code)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["code"] = module


def load_sessions_from_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def detect_alerts(sessions):
    detector = TLSDetector()
    alerts = []
    for session in sessions:
        alerts.extend(detector.analyze(session))
    return alerts


def sign_and_store_alerts(alerts, export_report_path=None):
    try:
        from partie_3.database import init_db, insert_alert
        from partie_3.exporter import export_signed_report
        from partie_3.key_manager import generate_keys
        from partie_3.signer import sign_alert
    except ModuleNotFoundError as exc:
        missing = exc.name
        raise RuntimeError(
            f"Missing dependency '{missing}'. Install project dependencies with "
            "'python -m pip install -r requirements.txt' before using --store."
        ) from exc

    keys_dir = Path("keys")
    if not (keys_dir / "private_key.pem").exists() or not (keys_dir / "public_key.pem").exists():
        generate_keys()

    init_db()
    stored = []
    for alert in alerts:
        signed = sign_alert(alert)
        alert_id = insert_alert(signed)
        stored.append({**signed, "database_id": alert_id})

    if export_report_path:
        export_signed_report(export_report_path)

    return stored


def main():
    parser = argparse.ArgumentParser(
        description="Run the complete TLS IDS pipeline: extraction, detection, signing, and export."
    )
    parser.add_argument("--pcap", help="PCAP file to analyze with part 1 extraction.")
    parser.add_argument("--sessions", help="Existing sessions_tls.json file to analyze.")
    parser.add_argument("--sessions-out", default="sessions_tls.json")
    parser.add_argument("--alerts-out", default="alerts.json")
    parser.add_argument("--store", action="store_true", help="Sign alerts and store them in SQLite.")
    parser.add_argument("--report-out", help="Export a signed report after storing alerts.")
    args = parser.parse_args()

    if not args.pcap and not args.sessions:
        parser.error("Choose either --pcap <file.pcap> or --sessions <sessions_tls.json>.")

    if args.pcap:
        preload_stdlib_code_module()
        from part1_extraction.session import sauvegarder_sessions, sessions_depuis_pcap

        sessions = sessions_depuis_pcap(args.pcap)
        sauvegarder_sessions(sessions, args.sessions_out)
    else:
        sessions = load_sessions_from_json(args.sessions)

    alerts = detect_alerts(sessions)
    write_json(args.alerts_out, alerts)

    print(f"[+] Sessions analyzed: {len(sessions)}")
    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Alerts saved to: {args.alerts_out}")

    if args.store:
        try:
            stored_alerts = sign_and_store_alerts(alerts, args.report_out)
        except RuntimeError as exc:
            print(f"[!] {exc}")
            return 1
        print(f"[+] Signed and stored alerts: {len(stored_alerts)}")
        if args.report_out:
            print(f"[+] Signed report saved to: {args.report_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
