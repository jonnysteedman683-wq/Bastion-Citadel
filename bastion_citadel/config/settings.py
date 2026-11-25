"""Settings management for Bastion-Citadel."""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Settings:
    """Application settings for Bastion-Citadel."""
    
    # Agent settings
    agent_name: str = "Bastion-Citadel"
    scan_interval: int = 3600
    auto_remediate: bool = False
    log_level: str = "INFO"
    
    # Scanner settings
    scan_paths: List[str] = field(default_factory=lambda: [".", "/etc", "/bin"])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        ".git", "__pycache__", ".venv", "node_modules", ".env", "*.log"
    ])
    
    # Monitor settings
    monitor_paths: List[str] = field(default_factory=lambda: ["/etc", "/bin", "/usr/bin"])
    log_files: List[str] = field(default_factory=lambda: [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog"
    ])
    
    # Plugin settings
    plugin_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Settings":
        """Create settings from dictionary."""
        return cls(
            agent_name=data.get("agent_name", "Bastion-Citadel"),
            scan_interval=data.get("scan_interval", 3600),
            auto_remediate=data.get("auto_remediate", False),
            log_level=data.get("log_level", "INFO"),
            scan_paths=data.get("scan_paths", [".", "/etc", "/bin"]),
            exclude_patterns=data.get("exclude_patterns", [
                ".git", "__pycache__", ".venv", "node_modules", ".env", "*.log"
            ]),
            monitor_paths=data.get("monitor_paths", ["/etc", "/bin", "/usr/bin"]),
            log_files=data.get("log_files", [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog"
            ]),
            plugin_config=data.get("plugin_config", {})
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return {
            "agent_name": self.agent_name,
            "scan_interval": self.scan_interval,
            "auto_remediate": self.auto_remediate,
            "log_level": self.log_level,
            "scan_paths": self.scan_paths,
            "exclude_patterns": self.exclude_patterns,
            "monitor_paths": self.monitor_paths,
            "log_files": self.log_files,
            "plugin_config": self.plugin_config
        }


# Default config file locations
CONFIG_FILES = [
    "bastion-citadel.json",
    "~/.config/bastion-citadel.json",
    "/etc/bastion-citadel.json"
]


def get_config_path() -> Path:
    """Get the configuration file path."""
    for config_file in CONFIG_FILES:
        path = Path(config_file).expanduser()
        if path.exists():
            return path
    return Path(CONFIG_FILES[0])


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Load settings from configuration file."""
    if config_path:
        path = Path(config_path)
    else:
        path = get_config_path()
    
    if not path.exists():
        return Settings()
    
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return Settings.from_dict(data)
    except Exception as e:
        print(f"Warning: Could not load config file: {e}")
        return Settings()


def save_settings(settings: Settings, config_path: Optional[str] = None) -> bool:
    """Save settings to configuration file."""
    if config_path:
        path = Path(config_path)
    else:
        path = get_config_path()
    
    try:
        # Create directory if it doesn't exist
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(settings.to_dict(), f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False
