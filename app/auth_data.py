from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


auth_users = {
    "patient.alex": {
        "user_id": 1,
        "username": "patient.alex",
        "full_name": "Alex Carter",
        "role": "patient",
        "patient_id": 101,
        "hashed_password": password_hash.hash("AlexDemo123!"),
    },
    "patient.jordan": {
        "user_id": 2,
        "username": "patient.jordan",
        "full_name": "Jordan Lee",
        "role": "patient",
        "patient_id": 102,
        "hashed_password": password_hash.hash("JordanDemo123!"),
    },
    "dr.morgan": {
        "user_id": 3,
        "username": "dr.morgan",
        "full_name": "Dr. Morgan Reed",
        "role": "doctor",
        "patient_id": None,
        "hashed_password": password_hash.hash("DoctorDemo123!"),
    },
    "admin.security": {
        "user_id": 4,
        "username": "admin.security",
        "full_name": "Security Administrator",
        "role": "admin",
        "patient_id": None,
        "hashed_password": password_hash.hash("AdminDemo123!"),
    },
}
