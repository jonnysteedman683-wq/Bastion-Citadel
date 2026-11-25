"""Helper utilities for Bastion-Citadel."""

import datetime
import json
import platform
import re
import socket
from typing import Any, Dict, List, Optional

from bastion_citadel.core.event import SecurityEvent


def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_timestamp(timestamp: Optional[datetime.datetime] = None) -> str:
    """Format timestamp to readable string."""
    if timestamp is None:
        timestamp = datetime.datetime.utcnow()
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def validate_email(email: str) -> bool:
    """Validate an email address."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_ip(ip: str) -> bool:
    """Validate an IP address (IPv4 or IPv6)."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def validate_url(url: str) -> bool:
    """Validate a URL."""
    pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w._~:/?#[\]@!$&\(\)\*\+,;=]*'
    return bool(re.match(pattern, url))


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "node_name": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "hostname": socket.gethostname()
    }


def generate_report(events: List[SecurityEvent], title: str = "Security Report") -> Dict[str, Any]:
    """Generate a security report from events."""
    
    # Group by severity
    by_severity: Dict[str, List[Dict]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    
    for event in events:
        severity = event.severity.value
        if severity in by_severity:
            by_severity[severity].append(event.to_dict())
    
    # Count by type
    by_type: Dict[str, int] = {}
    for event in events:
        event_type = event.event_type.value
        by_type[event_type] = by_type.get(event_type, 0) + 1
    
    # Count by source
    by_source: Dict[str, int] = {}
    for event in events:
        source = event.source
        by_source[source] = by_source.get(source, 0) + 1
    
    report = {
        "title": title,
        "generated_at": format_timestamp(),
        "summary": {
            "total_events": len(events),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_type": by_type,
            "by_source": by_source
        },
        "events": {
            "critical": by_severity["critical"],
            "high": by_severity["high"],
            "medium": by_severity["medium"],
            "low": by_severity["low"],
            "info": by_severity["info"]
        },
        "system_info": get_system_info()
    }
    
    return report


def export_report(report: Dict[str, Any], output_path: str, format: str = "json") -> bool:
    """Export report to file."""
    try:
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        else:
            # Simple text format
            with open(output_path, 'w') as f:
                f.write(f"{report['title']}\n")
                f.write(f"Generated: {report['generated_at']}\n\n")
                f.write("SUMMARY:\n")
                f.write(f"  Total Events: {report['summary']['total_events']}\n")
                for severity, count in report['summary']['by_severity'].items():
                    f.write(f"  {severity.upper()}: {count}\n")
                f.write("\n")
                
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    if report['events'][severity]:
                        f.write(f"\n{severity.upper()} EVENTS:\n")
                        for event in report['events'][severity]:
                            f.write(f"  - {event['title']}: {event['description']}\n")
        return True
    except Exception as e:
        print(f"Error exporting report: {e}")
        return False
