"""Network port scanner for Bastion-Citadel."""

import asyncio
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.plugin import SecurityPlugin, PluginType


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    service: str
    protocol: str
    is_common: bool


class PortScanner(SecurityPlugin):
    """
    Scanner for detecting open network ports and services.
    
    Identifies:
    - Open ports and running services
    - Common vulnerable services
    - Unexpected open ports
    """
    
    name = "port_scanner"
    plugin_type = PluginType.SCANNER
    description = "Scans network ports for open services and vulnerabilities"
    
    # Common ports and their typical services
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MS SQL",
        1521: "Oracle",
        27017: "MongoDB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Alt",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
    }
    
    # Ports that should typically not be exposed
    DANGEROUS_PORTS = [21, 23, 139, 445, 3389, 5900]
    
    def __init__(self):
        self.timeout = 2.0
        self.max_concurrent = 100
    
    async def initialize(self) -> bool:
        """Initialize the scanner."""
        return True
    
    async def execute(self, target: Optional[str] = None, **kwargs) -> List[SecurityEvent]:
        """
        Execute the port scan.
        
        Args:
            target: Target host or IP address
            **kwargs: Additional options
                - ports: List of ports to scan (default: common ports)
                - all_ports: Scan all ports (1-65535)
                - timeout: Connection timeout in seconds
        
        Returns:
            List of SecurityEvent objects
        """
        events: List[SecurityEvent] = []
        
        if not target:
            target = "localhost"
        
        ports = kwargs.get("ports", list(self.COMMON_PORTS.keys()))
        all_ports = kwargs.get("all_ports", False)
        timeout = kwargs.get("timeout", self.timeout)
        
        if all_ports:
            ports = range(1, 65536)
        
        logger = kwargs.get("logger")
        
        if logger:
            logger.info(f"Scanning {target} for open ports...")
        
        open_ports = await self.scan_ports(target, ports, timeout)
        
        for port, service in open_ports:
            port_info = PortInfo(
                port=port,
                service=service,
                protocol="TCP",
                is_common=port in self.COMMON_PORTS
            )
            
            # Check for dangerous ports
            if port in self.DANGEROUS_PORTS:
                events.append(SecurityEvent(
                    event_type=EventType.VULNERABILITY_DETECTED,
                    severity=Severity.HIGH,
                    title=f"Dangerous Port Open: {port}",
                    description=f"Port {port} ({service}) is open and potentially dangerous",
                    source=self.name,
                    remediation=f"Close port {port} or restrict access with firewall rules",
                    metadata={"port": port, "service": service, "target": target}
                ))
            else:
                events.append(SecurityEvent(
                    event_type=EventType.INFO,
                    severity=Severity.INFO,
                    title=f"Open Port: {port}",
                    description=f"Port {port} ({service}) is open",
                    source=self.name,
                    metadata={"port": port, "service": service, "target": target}
                ))
        
        if not open_ports:
            events.append(SecurityEvent(
                event_type=EventType.INFO,
                severity=Severity.INFO,
                title="No Open Ports Found",
                description=f"No open ports detected on {target}",
                source=self.name,
                metadata={"target": target}
            ))
        
        return events
    
    async def scan_ports(self, host: str, ports: List[int], timeout: float) -> List[Tuple[int, str]]:
        """Scan multiple ports concurrently."""
        open_ports = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_port(port: int) -> Optional[Tuple[int, str]]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                
                service = self.COMMON_PORTS.get(port, "Unknown")
                return (port, service)
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                return None
            except Exception:
                return None
        
        tasks = []
        for port in ports:
            task = asyncio.create_task(scan_port(port))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                open_ports.append(result)
        
        return open_ports
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass
