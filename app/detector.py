import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path


AUDIT_LOG_FILE = Path("logs/audit.log")
SECURITY_ALERT_FILE = Path("logs/security_alerts.json")

FAILED_ACCESS_THRESHOLD = 3
FAILED_LOGIN_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 5


def load_audit_events():
    events = []

    if not AUDIT_LOG_FILE.exists():
        return events

    with AUDIT_LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print("[WARNING] Skipping malformed audit log entry")

    return events


def parse_timestamp(timestamp):
    return datetime.fromisoformat(timestamp)


def detect_repeated_denied_record_access(events):
    denied_access = defaultdict(list)
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "patient_record_access"
            and event.get("outcome") == "denied"
        ):
            denied_access[event["username"]].append(event)

    window = timedelta(minutes=DETECTION_WINDOW_MINUTES)

    for username, user_events in denied_access.items():
        user_events.sort(
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        for index in range(len(user_events)):
            start_time = parse_timestamp(
                user_events[index]["timestamp"]
            )

            matching_events = []

            for candidate in user_events[index:]:
                candidate_time = parse_timestamp(
                    candidate["timestamp"]
                )

                if candidate_time - start_time <= window:
                    matching_events.append(candidate)

            if len(matching_events) >= FAILED_ACCESS_THRESHOLD:
                patient_ids = sorted(
                    {
                        event.get("patient_id")
                        for event in matching_events
                        if event.get("patient_id") is not None
                    }
                )

                alerts.append(
                    {
                        "rule_id": "SEC-001",
                        "severity": "HIGH",
                        "event": "RepeatedUnauthorizedRecordAccess",
                        "username": username,
                        "failed_attempts": len(matching_events),
                        "patient_ids": patient_ids,
                        "first_seen": matching_events[0]["timestamp"],
                        "last_seen": matching_events[-1]["timestamp"],
                        "description": (
                            "Repeated unauthorized patient-record "
                            "access attempts detected."
                        ),
                    }
                )

                break

    return alerts


def detect_repeated_failed_logins(events):
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:
        if (
            event.get("event_type") == "login_attempt"
            and event.get("outcome") == "denied"
        ):
            failed_logins[event["username"]].append(event)

    window = timedelta(minutes=DETECTION_WINDOW_MINUTES)

    for username, user_events in failed_logins.items():
        user_events.sort(
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        for index in range(len(user_events)):
            start_time = parse_timestamp(
                user_events[index]["timestamp"]
            )

            matching_events = []

            for candidate in user_events[index:]:
                candidate_time = parse_timestamp(
                    candidate["timestamp"]
                )

                if candidate_time - start_time <= window:
                    matching_events.append(candidate)

            if len(matching_events) >= FAILED_LOGIN_THRESHOLD:
                alerts.append(
                    {
                        "rule_id": "SEC-002",
                        "severity": "HIGH",
                        "event": "RepeatedFailedLogins",
                        "username": username,
                        "failed_attempts": len(matching_events),
                        "first_seen": matching_events[0]["timestamp"],
                        "last_seen": matching_events[-1]["timestamp"],
                        "description": (
                            "Repeated failed login attempts detected."
                        ),
                    }
                )

                break

    return alerts


def generate_security_alerts(events):
    alerts = []

    alerts.extend(
        detect_repeated_denied_record_access(events)
    )

    alerts.extend(
        detect_repeated_failed_logins(events)
    )

    return alerts


def save_security_report(events, alerts):
    report = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "audit_events_analyzed": len(events),
        "security_findings": len(alerts),
        "alerts": alerts,
    }

    SECURITY_ALERT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with SECURITY_ALERT_FILE.open(
        "w",
        encoding="utf-8",
    ) as report_file:
        json.dump(
            report,
            report_file,
            indent=2,
        )


def main():
    print("Healthcare API Security Detector")
    print("--------------------------------")

    events = load_audit_events()

    print(f"Audit events analyzed: {len(events)}")

    alerts = generate_security_alerts(events)

    print(f"Security findings: {len(alerts)}")
    print("--------------------------------")

    if not alerts:
        print("No suspicious activity detected.")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['rule_id']} - "
            f"{alert['event']}"
        )

        print(f"User: {alert['username']}")
        print(f"Attempts: {alert['failed_attempts']}")

        if alert.get("patient_ids"):
            print(
                "Target patient IDs: "
                f"{alert['patient_ids']}"
            )

        print(alert["description"])
        print("--------------------------------")

    save_security_report(events, alerts)

    print("Security Report Generated")
    print("--------------------------------")
    print(f"Security findings: {len(alerts)}")
    print(f"Report saved: {SECURITY_ALERT_FILE}")


if __name__ == "__main__":
    main()
