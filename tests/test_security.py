from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.detector import (
    detect_repeated_denied_record_access,
    detect_repeated_failed_logins,
)
from app.main import app


client = TestClient(app)


def login(username, password):
    return client.post(
        "/auth/login",
        data={
            "username": username,
            "password": password,
        },
    )


def auth_headers(username, password):
    response = login(username, password)

    assert response.status_code == 200

    token = response.json()["access_token"]

    return {
        "Authorization": f"Bearer {token}"
    }


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_invalid_login_is_rejected():
    response = login(
        "patient.alex",
        "WrongPassword123!",
    )

    assert response.status_code == 401


def test_valid_login_returns_token():
    response = login(
        "patient.alex",
        "AlexDemo123!",
    )

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_patient_record_requires_authentication():
    response = client.get("/patients/101")

    assert response.status_code == 401


def test_patient_can_access_own_record():
    headers = auth_headers(
        "patient.alex",
        "AlexDemo123!",
    )

    response = client.get(
        "/patients/101",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == 101


def test_patient_cannot_access_another_patient():
    headers = auth_headers(
        "patient.alex",
        "AlexDemo123!",
    )

    response = client.get(
        "/patients/102",
        headers=headers,
    )

    assert response.status_code == 403


def test_doctor_can_access_assigned_patient():
    headers = auth_headers(
        "dr.morgan",
        "DoctorDemo123!",
    )

    response = client.get(
        "/patients/102",
        headers=headers,
    )

    assert response.status_code == 200


def test_admin_can_view_patient_list():
    headers = auth_headers(
        "admin.security",
        "AdminDemo123!",
    )

    response = client.get(
        "/patients",
        headers=headers,
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_repeated_unauthorized_access_detection():
    now = datetime.now(UTC)

    events = []

    for attempt in range(3):
        events.append(
            {
                "timestamp": (
                    now + timedelta(seconds=attempt * 30)
                ).isoformat(),
                "event_type": "patient_record_access",
                "username": "patient.alex",
                "role": "patient",
                "outcome": "denied",
                "patient_id": 102,
            }
        )

    alerts = detect_repeated_denied_record_access(
        events
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SEC-001"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["failed_attempts"] == 3


def test_repeated_failed_login_detection():
    now = datetime.now(UTC)

    events = []

    for attempt in range(3):
        events.append(
            {
                "timestamp": (
                    now + timedelta(seconds=attempt * 30)
                ).isoformat(),
                "event_type": "login_attempt",
                "username": "patient.alex",
                "role": "unknown",
                "outcome": "denied",
                "patient_id": None,
            }
        )

    alerts = detect_repeated_failed_logins(
        events
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SEC-002"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["failed_attempts"] == 3
