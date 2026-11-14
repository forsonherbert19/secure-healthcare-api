from app.models import PatientRecord, User, UserRole


users = [
    User(
        id=1,
        username="patient.alex",
        full_name="Alex Carter",
        role=UserRole.patient,
        patient_id=101,
    ),
    User(
        id=2,
        username="patient.jordan",
        full_name="Jordan Lee",
        role=UserRole.patient,
        patient_id=102,
    ),
    User(
        id=3,
        username="dr.morgan",
        full_name="Dr. Morgan Reed",
        role=UserRole.doctor,
    ),
    User(
        id=4,
        username="admin.security",
        full_name="Security Administrator",
        role=UserRole.admin,
    ),
]


patient_records = [
    PatientRecord(
        id=101,
        full_name="Alex Carter",
        date_of_birth="1998-04-12",
        assigned_doctor_id=3,
        diagnosis="Synthetic seasonal allergy record",
        medications=["Synthetic Antihistamine"],
        notes="Synthetic demonstration record. No real patient data.",
    ),
    PatientRecord(
        id=102,
        full_name="Jordan Lee",
        date_of_birth="2001-09-08",
        assigned_doctor_id=3,
        diagnosis="Synthetic migraine record",
        medications=["Synthetic Migraine Medication"],
        notes="Synthetic demonstration record. No real patient data.",
    ),
]
