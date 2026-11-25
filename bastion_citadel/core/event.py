"""Security event handling for Bastion-Citadel."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid


class EventType(Enum):
    """Types of security events."""
    VULNERABILITY_DETECTED = "vulnerability_detected"
    THREAT_DETECTED = "threat_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    REMEDIATION_APPLIED = "remediation_applied"
    ALERT = "alert"
    INFO = "info"


class Severity(Enum):
    """Severity levels for security events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityEvent:
    """Represents a security event detected by the agent."""
    event_type: EventType
    severity: Severity
    title: str
    description: str
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "remediation": self.remediation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create event from dictionary."""
        return cls(
            event_type=EventType(data["event_type"]),
            severity=Severity(data["severity"]),
            title=data["title"],
            description=data["description"],
            source=data["source"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            event_id=data.get("event_id", str(uuid.uuid4())),
            metadata=data.get("metadata", {}),
            remediation=data.get("remediation")
        )
