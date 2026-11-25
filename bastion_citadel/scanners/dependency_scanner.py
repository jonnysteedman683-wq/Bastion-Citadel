"""Dependency vulnerability scanner."""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.plugin import SecurityPlugin, PluginType


class DependencyScanner(SecurityPlugin):
    """
    Scanner for detecting vulnerable dependencies.
    
    Supports:
    - Python (pip/requirements.txt)
    - Node.js (npm/package.json)
    - Generic dependency files
    """
    
    name = "dependency_scanner"
    plugin_type = PluginType.SCANNER
    description = "Scans project dependencies for known vulnerabilities"
    
    # Known vulnerability databases (simplified for demo)
    VULNERABILITY_DB = {
        "python": {
            "requests": {
                "2.28.0": ["CVE-2023-12345"],
                "2.27.0": ["CVE-2023-67890"],
            },
            "django": {
                "4.0.0": ["CVE-2022-12345"],
                "3.2.0": ["CVE-2021-54321"],
            },
            "flask": {
                "2.0.0": ["CVE-2022-21222"],
            }
        },
        "node": {
            "lodash": {
                "4.17.21": ["CVE-2021-23337"],
                "4.17.20": ["CVE-2020-8203"],
            },
            "axios": {
                "0.21.0": ["CVE-2021-3749"],
            }
        }
    }
    
    def __init__(self):
        self.timeout = 60
    
    async def initialize(self) -> bool:
        """Initialize the scanner."""
        return True
    
    async def execute(self, target: Optional[str] = None, **kwargs) -> List[SecurityEvent]:
        """
        Execute the dependency scan.
        
        Args:
            target: Path to project directory
            **kwargs: Additional options
        
        Returns:
            List of SecurityEvent objects
        """
        events: List[SecurityEvent] = []
        
        if not target:
            target = "."
        
        project_path = Path(target)
        
        # Detect project type
        project_type = self.detect_project_type(project_path)
        
        if project_type == "python":
            events.extend(await self.scan_python(project_path))
        elif project_type == "node":
            events.extend(await self.scan_node(project_path))
        else:
            events.append(SecurityEvent(
                event_type=EventType.INFO,
                severity=Severity.INFO,
                title="Unknown Project Type",
                description=f"Could not determine project type for: {target}",
                source=self.name
            ))
        
        return events
    
    def detect_project_type(self, path: Path) -> str:
        """Detect the project type based on files present."""
        files = [f.name for f in path.iterdir() if f.is_file()]
        
        if "requirements.txt" in files or "setup.py" in files or "pyproject.toml" in files:
            return "python"
        elif "package.json" in files or "package-lock.json" in files:
            return "node"
        
        return "unknown"
    
    async def scan_python(self, path: Path) -> List[SecurityEvent]:
        """Scan Python project dependencies."""
        events: List[SecurityEvent] = []
        
        # Try to read requirements.txt
        req_file = path / "requirements.txt"
        if req_file.exists():
            dependencies = await self.parse_requirements(req_file)
            vulnerabilities = self.check_vulnerabilities("python", dependencies)
            
            for dep, version, cvss, cvss_score in vulnerabilities:
                severity = self.cvss_to_severity(cvss_score)
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=severity,
                    title=f"Vulnerable Python Package: {dep}",
                    description=f"Package {dep}@{version} has known vulnerabilities: {', '.join(cvss)}",
                    source=self.name,
                    remediation=f"Upgrade {dep} to a non-vulnerable version",
                    metadata={
                        "package": dep,
                        "version": version,
                        "cves": cvss,
                        "cvss_score": cvss_score
                    }
                ))
        
        return events
    
    async def scan_node(self, path: Path) -> List[SecurityEvent]:
        """Scan Node.js project dependencies."""
        events: List[SecurityEvent] = []
        
        # Try to read package.json
        pkg_file = path / "package.json"
        if pkg_file.exists():
            dependencies = await self.parse_package_json(pkg_file)
            vulnerabilities = self.check_vulnerabilities("node", dependencies)
            
            for dep, version, cvss, cvss_score in vulnerabilities:
                severity = self.cvss_to_severity(cvss_score)
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=severity,
                    title=f"Vulnerable Node Package: {dep}",
                    description=f"Package {dep}@{version} has known vulnerabilities: {', '.join(cvss)}",
                    source=self.name,
                    remediation=f"Run: npm audit fix or update {dep}",
                    metadata={
                        "package": dep,
                        "version": version,
                        "cves": cvss,
                        "cvss_score": cvss_score
                    }
                ))
        
        return events
    
    async def parse_requirements(self, file_path: Path) -> List[Tuple[str, str]]:
        """Parse requirements.txt file."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package name and version
                    parts = line.split('==')
                    if len(parts) == 2:
                        name = parts[0].strip().lower()
                        version = parts[1].strip()
                        dependencies.append((name, version))
                    elif len(parts) == 1:
                        name = parts[0].strip().split('[')[0].strip().lower()
                        dependencies.append((name, "any"))
        except Exception as e:
            pass
        
        return dependencies
    
    async def parse_package_json(self, file_path: Path) -> List[Tuple[str, str]]:
        """Parse package.json file."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Get dependencies from dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies.append((name.lower(), str(version)))
        except Exception as e:
            pass
        
        return dependencies
    
    def check_vulnerabilities(self, ecosystem: str, dependencies: List[Tuple[str, str]]) -> List[Tuple[str, str, List[str], float]]:
        """Check dependencies against vulnerability database."""
        vulnerabilities = []
        
        if ecosystem not in self.VULNERABILITY_DB:
            return vulnerabilities
        
        db = self.VULNERABILITY_DB[ecosystem]
        
        for dep, version in dependencies:
            if dep in db:
                vuln_versions = db[dep]
                if version in vuln_versions:
                    # For demo, use a fixed CVSS score
                    vulnerabilities.append((dep, version, vuln_versions[version], 7.5))
        
        return vulnerabilities
    
    def cvss_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.INFO
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass
