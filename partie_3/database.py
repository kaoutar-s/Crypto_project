import sqlite3
import json
from datetime import datetime

DB_PATH = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            source_ip   TEXT,
            dest_ip     TEXT,
            details     TEXT,
            signed_data TEXT NOT NULL,
            signature   TEXT NOT NULL,
            verified    INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()
    print("[OK] Base de donnees initialisee.")

def insert_alert(signed_alert: dict) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        INSERT INTO alerts
            (timestamp, severity, alert_type, source_ip, dest_ip,
             details, signed_data, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        signed_alert.get("timestamp", datetime.utcnow().isoformat()),
        signed_alert.get("severity"),
        signed_alert.get("alert_type"),
        signed_alert.get("source_ip"),
        signed_alert.get("dest_ip"),
        json.dumps(signed_alert.get("details", {})),
        json.dumps({k: v for k, v in signed_alert.items()
                    if k != "signature"}, sort_keys=True),
        signed_alert["signature"]
    ))
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id

def get_all_alerts() -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_alerts_by_severity(severity: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC",
        (severity,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
