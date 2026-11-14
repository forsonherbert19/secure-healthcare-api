from datetime import date
from enum import Enum

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    patient = "patient"
    doctor = "doctor"
    admin = "admin"


class User(BaseModel):
    id: int
    username: str
    full_name: str
    role: UserRole
    patient_id: int | None = None


class PatientRecord(BaseModel):
    id: int
    full_name: str
    date_of_birth: date
    assigned_doctor_id: int
    diagnosis: str
    medications: list[str] = Field(default_factory=list)
    notes: str

