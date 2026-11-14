from fastapi import HTTPException, status


def can_access_patient(current_user: dict, patient_record) -> bool:
    role = current_user["role"]

    # Patient can only access their own record
    if role == "patient":
        return current_user["patient_id"] == patient_record.id

    # Doctor can access only patients assigned to them
    if role == "doctor":
        return patient_record.assigned_doctor_id == current_user["user_id"]

    # Admin can access all records for this demo system
    if role == "admin":
        return True

    return False


def enforce_patient_access(current_user: dict, patient_record):
    if not can_access_patient(current_user, patient_record):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this patient record",
        )

