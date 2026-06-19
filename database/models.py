from pydantic import BaseModel
from datetime import datetime
from typing import List


class User(BaseModel):
    email: str
    role: str
    company: str


class Detection(BaseModel):
    type: str
    count: int
    status: str


class SecurityIncident(BaseModel):
    incident_id: int
    timestamp: datetime
    user_id: str
    company: str
    risk_level: str
    action: str
    detections: List[Detection]
    prompt_preview: str


class Alert(BaseModel):
    alert_id: int
    timestamp: datetime
    severity: str
    reasons: List[str]
    action_taken: str


class UserActivity(BaseModel):
    user_id: str
    total_events: int
    critical_events: int
    last_risk_level: str
    anomaly_detected: bool
