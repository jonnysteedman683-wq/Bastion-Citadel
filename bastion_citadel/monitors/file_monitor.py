"""File integrity monitoring for Bastion-Citadel."""

import asyncio
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.plugin import SecurityPlugin, PluginType


@dataclass
class FileSignature:
    """File signature for integrity checking."""
    path: str
    hash: str
    size: int
    modified_time: datetime
    inode: int


class FileIntegrityMonitor(SecurityPlugin):
    """
    Monitors file integrity by detecting changes, additions, and deletions.
    
    Features:
    - Detects file modifications
    - Detects new files
    - Detects deleted files
    - Uses cryptographic hashing for verification
    """
    
    name = "file_integrity_monitor"
    plugin_type = PluginType.MONITOR
    description = "Monitors file system integrity and detects changes"
    
    def __init__(self):
        self.baseline: Dict[str, FileSignature] = {}
        self.watch_paths: List[str] = ["/etc", "/bin", "/usr/bin"]
        self.exclude_patterns: List[str] = [
            "*.log", "*.tmp", "*.swp", ".git", "__pycache__", ".cache"
        ]
        self.hash_algorithm = "sha256"
        self.initialized = False
    
    async def initialize(self) -> bool:
        """Initialize the monitor and create baseline."""
        await self.create_baseline()
        self.initialized = True
        return True
    
    async def create_baseline(self) -> None:
        """Create initial baseline of monitored files."""
        self.baseline = {}
        
        for watch_path in self.watch_paths:
            path = Path(watch_path)
            if path.exists():
                await self._scan_directory(path)
    
    async def _scan_directory(self, path: Path) -> None:
        """Recursively scan a directory and add to baseline."""
        try:
            for item in path.iterdir():
                if any(excl in str(item) for excl in self.exclude_patterns):
                    continue
                
                if item.is_file():
                    sig = await self._get_file_signature(item)
                    if sig:
                        self.baseline[str(item)] = sig
                elif item.is_dir():
                    await self._scan_directory(item)
        except PermissionError:
            pass
    
    async def _get_file_signature(self, file_path: Path) -> Optional[FileSignature]:
        """Get file signature with hash and metadata."""
        try:
            stat = file_path.stat()
            
            # Read file in chunks for large files
            hasher = hashlib.new(self.hash_algorithm)
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hasher.update(chunk)
            
            return FileSignature(
                path=str(file_path),
                hash=hasher.hexdigest(),
                size=stat.st_size,
                modified_time=datetime.fromtimestamp(stat.st_mtime),
                inode=stat.st_ino
            )
        except Exception:
            return None
    
    async def execute(self, **kwargs) -> List[SecurityEvent]:
        """
        Execute the file integrity check.
        
        Args:
            **kwargs: Additional options
                - paths: List of paths to monitor
                - reset_baseline: Reset the baseline
        
        Returns:
            List of SecurityEvent objects
        """
        events: List[SecurityEvent] = []
        
        if not self.initialized:
            events.append(SecurityEvent(
                event_type=EventType.ALERT,
                severity=Severity.MEDIUM,
                title="Monitor Not Initialized",
                description="File integrity monitor has not been initialized",
                source=self.name
            ))
            return events
        
        paths = kwargs.get("paths", self.watch_paths)
        reset_baseline = kwargs.get("reset_baseline", False)
        
        if reset_baseline:
            await self.create_baseline()
            events.append(SecurityEvent(
                event_type=EventType.INFO,
                severity=Severity.INFO,
                title="Baseline Reset",
                description="File integrity baseline has been reset",
                source=self.name
            ))
            return events
        
        # Check each watched path
        for watch_path in paths:
            path = Path(watch_path)
            if path.exists():
                current_files = await self._get_current_files(path)
                
                # Check for modified or new files
                for file_path, sig in current_files.items():
                    if file_path in self.baseline:
                        baseline_sig = self.baseline[file_path]
                        if sig.hash != baseline_sig.hash:
                            events.append(SecurityEvent(
                                event_type=EventType.ANOMALY_DETECTED,
                                severity=Severity.HIGH,
                                title="File Modified",
                                description=f"File has been modified: {file_path}",
                                source=self.name,
                                remediation="Investigate the file modification",
                                metadata={
                                    "path": file_path,
                                    "old_hash": baseline_sig.hash,
                                    "new_hash": sig.hash,
                                    "change_type": "modified"
                                }
                            ))
                    else:
                        events.append(SecurityEvent(
                            event_type=EventType.ANOMALY_DETECTED,
                            severity=Severity.MEDIUM,
                            title="New File Detected",
                            description=f"New file detected: {file_path}",
                            source=self.name,
                            remediation="Verify if this file should be present",
                            metadata={
                                "path": file_path,
                                "hash": sig.hash,
                                "change_type": "added"
                            }
                        ))
                
                # Check for deleted files
                for file_path, baseline_sig in self.baseline.items():
                    if file_path not in current_files and Path(file_path).parent in [Path(p) for p in paths]:
                        events.append(SecurityEvent(
                            event_type=EventType.ANOMALY_DETECTED,
                            severity=Severity.MEDIUM,
                            title="File Deleted",
                            description=f"File has been deleted: {file_path}",
                            source=self.name,
                            remediation="Verify if this file deletion was authorized",
                            metadata={
                                "path": file_path,
                                "hash": baseline_sig.hash,
                                "change_type": "deleted"
                            }
                        ))
        
        return events
    
    async def _get_current_files(self, path: Path) -> Dict[str, FileSignature]:
        """Get current file signatures for a path."""
        current_files = {}
        
        try:
            for item in path.iterdir():
                if any(excl in str(item) for excl in self.exclude_patterns):
                    continue
                
                if item.is_file():
                    sig = await self._get_file_signature(item)
                    if sig:
                        current_files[str(item)] = sig
                elif item.is_dir():
                    sub_files = await self._get_current_files(item)
                    current_files.update(sub_files)
        except PermissionError:
            pass
        
        return current_files
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        self.baseline = {}
        self.initialized = False
