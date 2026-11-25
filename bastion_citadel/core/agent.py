"""Main Security Agent for Bastion-Citadel."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .event import SecurityEvent, EventType, Severity
from .plugin import PluginManager, PluginType, SecurityPlugin


logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Configuration for the security agent."""
    name: str = "Bastion-Citadel"
    scan_interval: int = 3600  # seconds
    auto_remediate: bool = False
    log_level: str = "INFO"
    plugin_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentConfig":
        """Create config from dictionary."""
        return cls(
            name=data.get("name", "Bastion-Citadel"),
            scan_interval=data.get("scan_interval", 3600),
            auto_remediate=data.get("auto_remediate", False),
            log_level=data.get("log_level", "INFO"),
            plugin_config=data.get("plugin_config", {})
        )


class SecurityAgent:
    """
    Autonomous Security Agent for Bastion-Citadel.
    
    Coordinates security scanning, monitoring, and remediation
    across multiple plugins.
    """
    
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.plugin_manager = PluginManager()
        self.event_handlers: List[Callable[[SecurityEvent], Any]] = []
        self.running = False
        self._scan_task: Optional[asyncio.Task] = None
        
        self.setup_logging()
    
    def setup_logging(self) -> None:
        """Configure logging based on agent config."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper(), logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger.info(f"Security Agent '{self.config.name}' initialized")
    
    async def initialize(self) -> None:
        """Initialize the agent and all plugins."""
        logger.info("Initializing security agent...")
        
        # Discover and load plugins
        self.plugin_manager.discover_plugins()
        await self.plugin_manager.load_all(**self.config.plugin_config)
        
        logger.info(f"Loaded {len(self.plugin_manager.list_plugins())} plugins")
        logger.info("Security agent initialized successfully")
    
    async def scan(self, target: Optional[str] = None, **kwargs) -> List[SecurityEvent]:
        """
        Perform a security scan using all scanner plugins.
        
        Args:
            target: Optional target to scan (file, directory, URL, etc.)
            **kwargs: Additional arguments passed to scanners
        
        Returns:
            List of security events found
        """
        events: List[SecurityEvent] = []
        scanner_plugins = []
        
        for name, plugin in self.plugin_manager.instances.items():
            if plugin.plugin_type == PluginType.SCANNER:
                scanner_plugins.append((name, plugin))
        
        if not scanner_plugins:
            logger.warning("No scanner plugins loaded")
            return events
        
        logger.info(f"Starting scan with {len(scanner_plugins)} scanners")
        
        scan_event = SecurityEvent(
            event_type=EventType.SCAN_STARTED,
            severity=Severity.INFO,
            title="Security Scan Started",
            description=f"Initiating scan with {len(scanner_plugins)} scanners",
            source="agent"
        )
        await self.emit_event(scan_event)
        
        for name, scanner in scanner_plugins:
            try:
                logger.info(f"Running scanner: {name}")
                result = await scanner.execute(target=target, **kwargs)
                
                if isinstance(result, list):
                    events.extend(result)
                elif isinstance(result, dict) and "events" in result:
                    events.extend(result["events"])
                elif isinstance(result, SecurityEvent):
                    events.append(result)
                    
            except Exception as e:
                logger.error(f"Scanner {name} failed: {e}")
                error_event = SecurityEvent(
                    event_type=EventType.ALERT,
                    severity=Severity.HIGH,
                    title=f"Scanner {name} Failed",
                    description=str(e),
                    source=name
                )
                events.append(error_event)
        
        scan_complete_event = SecurityEvent(
            event_type=EventType.SCAN_COMPLETED,
            severity=Severity.INFO,
            title="Security Scan Completed",
            description=f"Scan completed. Found {len(events)} events.",
            source="agent",
            metadata={"event_count": len(events)}
        )
        await self.emit_event(scan_complete_event)
        
        return events
    
    async def monitor(self, **kwargs) -> List[SecurityEvent]:
        """
        Run monitoring plugins to detect threats and anomalies.
        
        Returns:
            List of security events detected
        """
        events: List[SecurityEvent] = []
        monitor_plugins = []
        
        for name, plugin in self.plugin_manager.instances.items():
            if plugin.plugin_type == PluginType.MONITOR:
                monitor_plugins.append((name, plugin))
        
        for name, monitor in monitor_plugins:
            try:
                result = await monitor.execute(**kwargs)
                if isinstance(result, list):
                    events.extend(result)
            except Exception as e:
                logger.error(f"Monitor {name} failed: {e}")
        
        return events
    
    async def remediate(self, event: SecurityEvent, **kwargs) -> bool:
        """
        Attempt to automatically remediate a security event.
        
        Args:
            event: The security event to remediate
            **kwargs: Additional arguments for remediation
        
        Returns:
            True if remediation was successful
        """
        if not self.config.auto_remediate:
            logger.info(f"Auto-remediation disabled. Event requires manual action: {event.title}")
            return False
        
        remediator_plugins = []
        for name, plugin in self.plugin_manager.instances.items():
            if plugin.plugin_type == PluginType.REMEDIATOR:
                remediator_plugins.append((name, plugin))
        
        if not remediator_plugins:
            logger.warning("No remediator plugins available")
            return False
        
        for name, remediator in remediator_plugins:
            try:
                result = await remediator.execute(event=event, **kwargs)
                if result.get("success", False):
                    remediation_event = SecurityEvent(
                        event_type=EventType.REMEDIATION_APPLIED,
                        severity=Severity.INFO,
                        title=f"Remediated: {event.title}",
                        description=f"Auto-remediation applied by {name}",
                        source=name,
                        metadata={"original_event_id": event.event_id}
                    )
                    await self.emit_event(remediation_event)
                    return True
            except Exception as e:
                logger.error(f"Remediator {name} failed: {e}")
        
        return False
    
    async def start_continuous_monitoring(self) -> None:
        """Start continuous monitoring and scanning."""
        if self.running:
            logger.warning("Agent is already running")
            return
        
        self.running = True
        logger.info("Starting continuous monitoring...")
        
        async def monitoring_loop():
            while self.running:
                try:
                    events = await self.scan()
                    events.extend(await self.monitor())
                    
                    for event in events:
                        if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                            await self.remediate(event)
                            
                except Exception as e:
                    logger.error(f"Monitoring loop error: {e}")
                
                await asyncio.sleep(self.config.scan_interval)
        
        self._scan_task = asyncio.create_task(monitoring_loop())
    
    async def stop(self) -> None:
        """Stop the agent and cleanup."""
        self.running = False
        
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        
        # Cleanup plugins
        for plugin in self.plugin_manager.instances.values():
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error(f"Plugin cleanup failed: {e}")
        
        logger.info("Security agent stopped")
    
    def on_event(self, handler: Callable[[SecurityEvent], Any]) -> None:
        """Register an event handler."""
        self.event_handlers.append(handler)
    
    async def emit_event(self, event: SecurityEvent) -> None:
        """Emit a security event to all handlers."""
        for handler in self.event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Event handler failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "name": self.config.name,
            "running": self.running,
            "plugins_loaded": len(self.plugin_manager.instances),
            "plugins": list(self.plugin_manager.list_plugins()),
            "auto_remediate": self.config.auto_remediate,
            "scan_interval": self.config.scan_interval
        }
