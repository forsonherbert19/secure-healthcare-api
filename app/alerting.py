import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.detector import (
    generate_security_alerts,
    load_audit_events,
)


ALERT_LOG_FILE = Path("logs/security_alerts.jsonl")
ALERT_COOLDOWN_MINUTES = 5


def load_existing_alerts():
    alerts = []

    if not ALERT_LOG_FILE.exists():
        return alerts

    with ALERT_LOG_FILE.open("r", encoding="utf-8") as alert_file:
        for line in alert_file:
            line = line.strip()

            if not line:
                continue

            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return alerts


def alert_recently_sent(alert, existing_alerts):
    now = datetime.now(UTC)
    cooldown = timedelta(minutes=ALERT_COOLDOWN_MINUTES)

    for existing in reversed(existing_alerts):
        if (
            existing.get("rule_id") == alert.get("rule_id")
            and existing.get("username") == alert.get("username")
        ):
            created_at = existing.get("created_at")

            if not created_at:
                continue

            previous_time = datetime.fromisoformat(created_at)

            if now - previous_time <= cooldown:
                return True

    return False


def process_security_alerts():
    events = load_audit_events()
    alerts = generate_security_alerts(events)

    if not alerts:
        return

    existing_alerts = load_existing_alerts()

    now = datetime.now(UTC)
    detection_window = timedelta(minutes=5)

    for alert in alerts:
        last_seen = datetime.fromisoformat(alert["last_seen"])

        # Ignore old detections.
        if now - last_seen > detection_window:
            continue

        # Avoid repeatedly alerting on the same activity.
        if alert_recently_sent(
            alert,
            existing_alerts,
        ):
            continue

        alert_record = {
            "created_at": now.isoformat(),
            **alert,
        }

        ALERT_LOG_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with ALERT_LOG_FILE.open(
            "a",
            encoding="utf-8",
        ) as alert_file:
            alert_file.write(
                json.dumps(alert_record) + "\n"
            )

        existing_alerts.append(alert_record)

        print(
            f"[SECURITY ALERT] "
            f"{alert['severity']} "
            f"{alert['rule_id']} - "
            f"{alert['event']} "
            f"for user {alert['username']}"
        )

