from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator
import re
import ipaddress

class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventStatusEnum(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"

class AlertStatusEnum(str, Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"

class EventBase(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 timestamp e.g. 2026-10-21T10:00:00Z")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    username: str = Field(..., min_length=1, max_length=100)
    event_type: str = Field(..., min_length=2, max_length=100)
    severity: SeverityEnum = SeverityEnum.LOW
    status: EventStatusEnum = EventStatusEnum.FAILURE
    message: str = Field(..., min_length=1, max_length=1000)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

class EventCreate(EventBase):
    pass

class EventResponse(EventBase):
    id: int
    created_at: str

class AlertResponse(BaseModel):
    id: int
    rule_name: str
    severity: str
    source_ip: str
    target_username: Optional[str] = None
    reason: str
    event_count: int
    first_event_time: str
    last_event_time: str
    status: AlertStatusEnum
    notes: Optional[str] = ""
    created_at: str
    updated_at: str

class AlertStatusUpdate(BaseModel):
    status: AlertStatusEnum
    notes: Optional[str] = None

class DetectionRuleConfig(BaseModel):
    window_minutes: int = Field(10, ge=1, le=1440, description="Sliding time window in minutes")
    threshold: int = Field(5, ge=2, le=100, description="Failed attempts required to alert")

class LogUploadSummary(BaseModel):
    total_rows: int
    imported_rows: int
    failed_rows: int
    alerts_created: int
    errors: List[Dict[str, Any]] = []

class StatsSummary(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    resolved_alerts: int
    critical_alerts: int
    high_alerts: int
    severity_breakdown: Dict[str, int]
    event_type_breakdown: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_target_users: List[Dict[str, Any]]
    recent_events_timeline: List[Dict[str, Any]]
