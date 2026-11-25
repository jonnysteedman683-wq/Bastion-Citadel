"""
Bastion-Citadel: Autonomous Security Agent Framework

A modular security agent for vulnerability scanning, threat detection,
and automated remediation.
"""

__version__ = "0.1.0"
__author__ = "Bastion-Citadel Team"

from .core.agent import SecurityAgent
from .core.event import SecurityEvent
from .core.plugin import SecurityPlugin

__all__ = ["SecurityAgent", "SecurityEvent", "SecurityPlugin"]
