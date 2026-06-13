from datetime import datetime


def create_alert(
    severity,
    rule,
    description,
    src_ip,
    dst_ip,
    ja3=None,
    session_id=None,
    details=None,
):
    details = details or {}
    details.setdefault("message", description)
    if ja3:
        details.setdefault("ja3", ja3)
    if session_id:
        details.setdefault("session_id", session_id)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "alert_type": rule.lower().replace(" ", "_"),
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "details": details,
        # Backward-compatible names used by the first part 2 prototype.
        "rule": rule,
        "description": description,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ja3": ja3,
    }
