"""File-based vulnerability scanner."""

import asyncio
import hashlib
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.plugin import SecurityPlugin, PluginType


class FileVulnerabilityScanner(SecurityPlugin):
    """
    Scanner for detecting vulnerabilities in files.
    
    Detects:
    - Hardcoded secrets (API keys, passwords, tokens)
    - Sensitive data exposure
    - Insecure file permissions
    - Common misconfigurations
    """
    
    name = "file_vulnerability_scanner"
    plugin_type = PluginType.SCANNER
    description = "Scans files for hardcoded secrets and vulnerabilities"
    
    # Patterns for detecting secrets
    SECRET_PATTERNS = {
        "api_key": r'(?:api[_-]?key|apikey)[=:"]?\s*["\']?([a-zA-Z0-9_\-]{32,})["\']?',
        "password": r'(?:password|passwd|pwd)[=:"]?\s*["\']?([^\s"\']+)["\']?',
        "secret": r'(?:secret|private[_-]?key)[=:"]?\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "token": r'(?:access[_-]?token|auth[_-]?token|bearer)[=:"]?\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        "aws_key": r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16,}',
        "github_token": r'ghp_[a-zA-Z0-9]{36,}',
        "slack_token": r'xox[baprs]-[0-9a-zA-Z\-]+',
    }
    
    # Insecure patterns
    INSECURE_PATTERNS = {
        "eval": r'eval\s*\(.*\)',
        "exec": r'exec\s*\(.*\)',
        "pickle_load": r'pickle\.load\s*\(.*\)',
        "shell_true": r'shell\s*=\s*True',
        "debug_true": r'DEBUG\s*=\s*True',
    }
    
    def __init__(self):
        self.exclude_patterns = ['.git', '__pycache__', '.venv', 'node_modules', '.env']
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    async def initialize(self) -> bool:
        """Initialize the scanner."""
        return True
    
    async def execute(self, target: Optional[str] = None, **kwargs) -> List[SecurityEvent]:
        """
        Execute the file vulnerability scan.
        
        Args:
            target: Path to scan (file or directory)
            **kwargs: Additional options
                - recursive: bool (scan subdirectories)
                - exclude: list of patterns to exclude
        
        Returns:
            List of SecurityEvent objects
        """
        events: List[SecurityEvent] = []
        
        if not target:
            target = "."
        
        recursive = kwargs.get("recursive", True)
        exclude = kwargs.get("exclude", self.exclude_patterns)
        
        path = Path(target)
        
        if path.is_file():
            events.extend(await self.scan_file(path))
        elif path.is_dir():
            events.extend(await self.scan_directory(path, recursive, exclude))
        else:
            event = SecurityEvent(
                event_type=EventType.ALERT,
                severity=Severity.MEDIUM,
                title="Invalid Target",
                description=f"Target path does not exist: {target}",
                source=self.name
            )
            events.append(event)
        
        return events
    
    async def scan_file(self, file_path: Path) -> List[SecurityEvent]:
        """Scan a single file for vulnerabilities."""
        events: List[SecurityEvent] = []
        
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                events.append(SecurityEvent(
                    event_type=EventType.INFO,
                    severity=Severity.INFO,
                    title="File Too Large",
                    description=f"Skipping {file_path} (size: {file_size} bytes)",
                    source=self.name,
                    metadata={"path": str(file_path), "size": file_size}
                ))
                return events
            
            # Check file permissions
            file_events = self.check_file_permissions(file_path)
            events.extend(file_events)
            
            # Read and scan content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Scan for secrets
            secret_events = self.scan_for_secrets(file_path, content, lines)
            events.extend(secret_events)
            
            # Scan for insecure patterns
            insecure_events = self.scan_for_insecure_patterns(file_path, content, lines)
            events.extend(insecure_events)
            
        except Exception as e:
            events.append(SecurityEvent(
                event_type=EventType.ALERT,
                severity=Severity.MEDIUM,
                title="Scan Error",
                description=f"Error scanning {file_path}: {e}",
                source=self.name,
                metadata={"path": str(file_path), "error": str(e)}
            ))
        
        return events
    
    async def scan_directory(self, dir_path: Path, recursive: bool, exclude: List[str]) -> List[SecurityEvent]:
        """Scan a directory for vulnerabilities."""
        events: List[SecurityEvent] = []
        
        for item in dir_path.iterdir():
            if any(excl in str(item) for excl in exclude):
                continue
            
            if item.is_file():
                file_events = await self.scan_file(item)
                events.extend(file_events)
            elif item.is_dir() and recursive:
                dir_events = await self.scan_directory(item, recursive, exclude)
                events.extend(dir_events)
        
        return events
    
    def check_file_permissions(self, file_path: Path) -> List[SecurityEvent]:
        """Check for insecure file permissions."""
        events: List[SecurityEvent] = []
        
        try:
            stat = file_path.stat()
            mode = stat.st_mode
            
            # Check if world-writable
            if mode & 0o002:
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=Severity.HIGH,
                    title="World-Writable File",
                    description=f"File is world-writable: {file_path}",
                    source=self.name,
                    remediation="Remove world-writable permission: chmod o-w <file>",
                    metadata={"path": str(file_path), "mode": oct(mode)}
                ))
            
            # Check if world-readable for sensitive files
            sensitive_extensions = ['.env', '.key', '.pem', '.p12', '.pfx', '.json', '.yaml', '.yml']
            if any(file_path.suffix.lower() == ext for ext in sensitive_extensions):
                if mode & 0o004:
                    events.append(SecurityEvent(
                        event_type=EventType.VULNERABILITY_DETECTED,
                        severity=Severity.MEDIUM,
                        title="World-Readable Sensitive File",
                        description=f"Sensitive file is world-readable: {file_path}",
                        source=self.name,
                        remediation="Remove world-readable permission: chmod o-r <file>",
                        metadata={"path": str(file_path), "mode": oct(mode)}
                    ))
                    
        except Exception as e:
            pass
        
        return events
    
    def scan_for_secrets(self, file_path: Path, content: str, lines: List[str]) -> List[SecurityEvent]:
        """Scan file content for hardcoded secrets."""
        events: List[SecurityEvent] = []
        
        for pattern_name, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1].strip()
                
                # Mask the secret in the description
                secret_value = match.group(1) if match.groups() else match.group(0)
                masked_secret = secret_value[:4] + '*' * (len(secret_value) - 4) if len(secret_value) > 4 else '****'
                
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded {pattern_name.replace('_', ' ').title()}",
                    description=f"Found potential {pattern_name} in {file_path}:{line_num}",
                    source=self.name,
                    remediation=f"Remove hardcoded {pattern_name} and use environment variables or secret management",
                    metadata={
                        "path": str(file_path),
                        "line": line_num,
                        "line_content": line_content,
                        "pattern": pattern_name
                    }
                ))
        
        return events
    
    def scan_for_insecure_patterns(self, file_path: Path, content: str, lines: List[str]) -> List[SecurityEvent]:
        """Scan for insecure coding patterns."""
        events: List[SecurityEvent] = []
        
        for pattern_name, pattern in self.INSECURE_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1].strip()
                
                severity = Severity.HIGH if pattern_name in ['eval', 'exec', 'pickle_load'] else Severity.MEDIUM
                
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=severity,
                    title=f"Insecure Pattern: {pattern_name.replace('_', ' ').title()}",
                    description=f"Found insecure pattern in {file_path}:{line_num}",
                    source=self.name,
                    remediation=f"Avoid using {pattern_name} due to security risks",
                    metadata={
                        "path": str(file_path),
                        "line": line_num,
                        "line_content": line_content,
                        "pattern": pattern_name
                    }
                ))
        
        return events
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass
