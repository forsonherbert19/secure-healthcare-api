import json
from datetime import UTC, datetime
from pathlib import Path


LOG_DIRECTORY = Path("logs")
LOG_DIRECTORY.mkdir(exist_ok=True)

AUDIT_LOG_FILE = LOG_DIRECTORY / "audit.log"


def sanitize_log_value(value):
    if not isinstance(value, str):
        return value

    return (
        value.replace("\r", "\\r")
        .replace("\n", "\\n")[:200]
    )


def log_security_event(
    event_type: str,
    username: str,
    role: str,
    outcome: str,
    patient_id: int | None = None,
    reason: str | None = None,
):
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": sanitize_log_value(event_type),
        "username": sanitize_log_value(username),
        "role": sanitize_log_value(role),
        "outcome": sanitize_log_value(outcome),
        "patient_id": patient_id,
    }

    if reason:
        event["reason"] = sanitize_log_value(reason)

    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event) + "\n")
    try:
        from app.alerting import process_security_alerts

        process_security_alerts()

    except Exception as exc:
        print(
            f"[WARNING] Security alert processing failed: {exc}"
        )
