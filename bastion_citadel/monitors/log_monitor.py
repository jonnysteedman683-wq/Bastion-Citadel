"""Log file monitoring for Bastion-Citadel."""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.plugin import SecurityPlugin, PluginType


@dataclass
class LogPattern:
    """Pattern for detecting security events in logs."""
    name: str
    pattern: str
    severity: Severity
    description: str
    remediation: str


class LogMonitor(SecurityPlugin):
    """
    Monitors log files for security-relevant events.
    
    Features:
    - Real-time log monitoring
    - Pattern-based threat detection
    - Failed login detection
    - Suspicious activity detection
    """
    
    name = "log_monitor"
    plugin_type = PluginType.MONITOR
    description = "Monitors log files for security events and threats"
    
    # Security patterns to detect in logs
    SECURITY_PATTERNS = [
        LogPattern(
            name="failed_login",
            pattern=r'(?:Failed|Invalid|Wrong)\s+(?:password|login|authentication|credential)',
            severity=Severity.MEDIUM,
            description="Multiple failed login attempts detected",
            remediation="Investigate the source of failed login attempts"
        ),
        LogPattern(
            name="brute_force",
            pattern=r'(?:Brute force|Multiple failed attempts|Too many attempts)',
            severity=Severity.HIGH,
            description="Brute force attack detected",
            remediation="Block the attacking IP and investigate"
        ),
        LogPattern(
            name="root_login",
            pattern=r'root\s+LOGIN|su:\s+root|sudo:\s+root',
            severity=Severity.HIGH,
            description="Root login detected",
            remediation="Verify if root login was authorized"
        ),
        LogPattern(
            name="permission_denied",
            pattern=r'(?:Permission denied|Access denied|Unauthorized)',
            severity=Severity.LOW,
            description="Access denied event detected",
            remediation="Review access controls"
        ),
        LogPattern(
            name="sql_injection",
            pattern=r'(?:SQL injection|sqli|union\s+select|\'\s*or\s*1=1)',
            severity=Severity.CRITICAL,
            description="Possible SQL injection attack detected",
            remediation="Investigate immediately and patch vulnerabilities"
        ),
        LogPattern(
            name="xss_attack",
            pattern=r'(?:XSS|Cross-site scripting|<script>|javascript:)',
            severity=Severity.HIGH,
            description="Possible XSS attack detected",
            remediation="Review input validation and sanitization"
        ),
        LogPattern(
            name="directory_traversal",
            pattern=r'(?:\.\./|\.\.\\|path\s+traversal)',
            severity=Severity.HIGH,
            description="Directory traversal attempt detected",
            remediation="Block the request and patch the vulnerability"
        ),
        LogPattern(
            name="malware_detected",
            pattern=r'(?:Malware|Virus|Trojan|Ransomware|Exploit)',
            severity=Severity.CRITICAL,
            description="Malware detected",
            remediation="Isolate the affected system and run antivirus"
        ),
        LogPattern(
            name="port_scan",
            pattern=r'(?:Port scan|Nmap|Masscan|Port\s+scanning)',
            severity=Severity.MEDIUM,
            description="Port scanning activity detected",
            remediation="Block the scanning IP and investigate"
        ),
    ]
    
    def __init__(self):
        self.log_files: List[str] = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
        ]
        self.file_positions: Dict[str, int] = {}
        self.initialized = False
    
    async def initialize(self) -> bool:
        """Initialize the monitor and set up file positions."""
        for log_file in self.log_files:
            path = Path(log_file)
            if path.exists():
                self.file_positions[log_file] = 0
        self.initialized = True
        return True
    
    async def execute(self, **kwargs) -> List[SecurityEvent]:
        """
        Execute the log monitoring check.
        
        Args:
            **kwargs: Additional options
                - log_files: List of log files to monitor
                - since: Only check lines since this timestamp
        
        Returns:
            List of SecurityEvent objects
        """
        events: List[SecurityEvent] = []
        
        if not self.initialized:
            events.append(SecurityEvent(
                event_type=EventType.ALERT,
                severity=Severity.MEDIUM,
                title="Monitor Not Initialized",
                description="Log monitor has not been initialized",
                source=self.name
            ))
            return events
        
        log_files = kwargs.get("log_files", self.log_files)
        
        for log_file in log_files:
            path = Path(log_file)
            if not path.exists():
                continue
            
            try:
                # Get current position
                position = self.file_positions.get(log_file, 0)
                
                # Read new lines
                with open(path, 'r') as f:
                    f.seek(position)
                    new_lines = f.readlines()
                    
                    # Update position
                    self.file_positions[log_file] = f.tell()
                
                # Analyze lines
                file_events = self.analyze_lines(log_file, new_lines)
                events.extend(file_events)
                
            except Exception as e:
                events.append(SecurityEvent(
                    event_type=EventType.ALERT,
                    severity=Severity.MEDIUM,
                    title="Log Read Error",
                    description=f"Error reading log file {log_file}: {e}",
                    source=self.name,
                    metadata={"log_file": log_file, "error": str(e)}
                ))
        
        return events
    
    def analyze_lines(self, log_file: str, lines: List[str]) -> List[SecurityEvent]:
        """Analyze log lines for security events."""
        events: List[SecurityEvent] = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            for pattern in self.SECURITY_PATTERNS:
                if re.search(pattern.pattern, line, re.IGNORECASE):
                    event = SecurityEvent(
                        event_type=EventType.THREAT_DETECTED,
                        severity=pattern.severity,
                        title=pattern.name.replace('_', ' ').title(),
                        description=f"{pattern.description} in {log_file}",
                        source=self.name,
                        remediation=pattern.remediation,
                        metadata={
                            "log_file": log_file,
                            "line_number": line_num,
                            "line": line,
                            "pattern": pattern.name
                        }
                    )
                    events.append(event)
                    break  # Only report first match per line
        
        return events
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        self.file_positions = {}
        self.initialized = False
