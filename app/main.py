from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app.audit import log_security_event
from app.authorization import can_access_patient
from app.data import patient_records
from app.models import PatientRecord
from app.security import (
    authenticate_user,
    create_access_token,
    get_current_user,
)


app = FastAPI(
    title="Secure Healthcare Records API",
    description="A security-focused healthcare records API using synthetic data.",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Secure Healthcare Records API",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "secure-healthcare-api",
    }


@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(
        form_data.username,
        form_data.password,
    )

    if not user:
        log_security_event(
            event_type="login_attempt",
            username=form_data.username,
            role="unknown",
            outcome="denied",
            reason="invalid_credentials",
        )

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    log_security_event(
        event_type="login_attempt",
        username=user["username"],
        role=user["role"],
        outcome="allowed",
    )

    token = create_access_token(user["username"])

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/users/me")
def read_current_user(
    current_user: dict = Depends(get_current_user),
):
    return {
        "id": current_user["user_id"],
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
    }


@app.get("/patients", response_model=list[PatientRecord])
def get_patients(
    current_user: dict = Depends(get_current_user),
):
    role = current_user["role"]

    log_security_event(
        event_type="patient_list_access",
        username=current_user["username"],
        role=role,
        outcome="allowed",
    )

    if role == "admin":
        return patient_records

    if role == "doctor":
        return [
            patient
            for patient in patient_records
            if patient.assigned_doctor_id == current_user["user_id"]
        ]

    if role == "patient":
        return [
            patient
            for patient in patient_records
            if patient.id == current_user["patient_id"]
        ]

    raise HTTPException(
        status_code=403,
        detail="Access denied",
    )


@app.get("/patients/{patient_id}", response_model=PatientRecord)
def get_patient(
    patient_id: int,
    current_user: dict = Depends(get_current_user),
):
    for patient in patient_records:
        if patient.id == patient_id:

            if not can_access_patient(
                current_user,
                patient,
            ):
                log_security_event(
                    event_type="patient_record_access",
                    username=current_user["username"],
                    role=current_user["role"],
                    outcome="denied",
                    patient_id=patient_id,
                    reason="authorization_failure",
                )

                raise HTTPException(
                    status_code=403,
                    detail="You are not authorized to access this patient record",
                )

            log_security_event(
                event_type="patient_record_access",
                username=current_user["username"],
                role=current_user["role"],
                outcome="allowed",
                patient_id=patient_id,
            )

            return patient

    log_security_event(
        event_type="patient_record_access",
        username=current_user["username"],
        role=current_user["role"],
        outcome="not_found",
        patient_id=patient_id,
    )

    raise HTTPException(
        status_code=404,
        detail="Patient record not found",
    )
