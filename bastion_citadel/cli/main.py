"""Main CLI for Bastion-Citadel Security Agent."""

import argparse
import asyncio
import json
import logging
import sys
from typing import Any, Dict, List

from bastion_citadel.core.agent import SecurityAgent, AgentConfig
from bastion_citadel.core.event import SecurityEvent, EventType, Severity


logger = logging.getLogger(__name__)


class CLI:
    """Command-line interface for the security agent."""
    
    def __init__(self):
        self.agent: Optional[SecurityAgent] = None
        self.parser = self.create_parser()
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description="Bastion-Citadel: Autonomous Security Agent",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  bastion scan                    # Run a full security scan
  bastion scan /path/to/project   # Scan a specific directory
  bastion monitor                 # Run monitoring checks
  bastion start                   # Start continuous monitoring
  bastion status                  # Show agent status
  bastion config --auto-remediate # Enable auto-remediation
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Run security scan')
        scan_parser.add_argument('target', nargs='?', default=None, help='Target to scan')
        scan_parser.add_argument('--type', choices=['file', 'dependency', 'port', 'all'], 
                                default='all', help='Scan type')
        scan_parser.add_argument('--output', '-o', choices=['text', 'json'], 
                                default='text', help='Output format')
        scan_parser.add_argument('--recursive', action='store_true', 
                                help='Scan recursively')
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Run monitoring checks')
        monitor_parser.add_argument('--output', '-o', choices=['text', 'json'], 
                                   default='text', help='Output format')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start continuous monitoring')
        start_parser.add_argument('--interval', type=int, default=None,
                                 help='Scan interval in seconds')
        
        # Stop command
        subparsers.add_parser('stop', help='Stop the agent')
        
        # Status command
        subparsers.add_parser('status', help='Show agent status')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Configure the agent')
        config_parser.add_argument('--name', type=str, help='Agent name')
        config_parser.add_argument('--interval', type=int, help='Scan interval')
        config_parser.add_argument('--auto-remediate', action='store_true', 
                                   help='Enable auto-remediation')
        config_parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                                   help='Set log level')
        
        # Version command
        subparsers.add_parser('version', help='Show version')
        
        return parser
    
    async def run(self, args: List[str] = None) -> int:
        """Run the CLI with the given arguments."""
        if args is None:
            args = sys.argv[1:]
        
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return 1
        
        # Initialize agent
        await self.initialize_agent()
        
        # Handle commands
        if parsed_args.command == 'scan':
            return await self.handle_scan(parsed_args)
        elif parsed_args.command == 'monitor':
            return await self.handle_monitor(parsed_args)
        elif parsed_args.command == 'start':
            return await self.handle_start(parsed_args)
        elif parsed_args.command == 'stop':
            return await self.handle_stop(parsed_args)
        elif parsed_args.command == 'status':
            return await self.handle_status(parsed_args)
        elif parsed_args.command == 'config':
            return await self.handle_config(parsed_args)
        elif parsed_args.command == 'version':
            return await self.handle_version(parsed_args)
        
        return 0
    
    async def initialize_agent(self) -> None:
        """Initialize the security agent."""
        if self.agent is None:
            self.agent = SecurityAgent()
            await self.agent.initialize()
    
    async def handle_scan(self, args: Any) -> int:
        """Handle the scan command."""
        events: List[SecurityEvent] = []
        
        if args.type == 'all' or args.type == 'file':
            from bastion_citadel.scanners.file_scanner import FileVulnerabilityScanner
            scanner = FileVulnerabilityScanner()
            await scanner.initialize()
            file_events = await scanner.execute(args.target, recursive=args.recursive)
            events.extend(file_events)
        
        if args.type == 'all' or args.type == 'dependency':
            from bastion_citadel.scanners.dependency_scanner import DependencyScanner
            scanner = DependencyScanner()
            await scanner.initialize()
            dep_events = await scanner.execute(args.target)
            events.extend(dep_events)
        
        if args.type == 'all' or args.type == 'port':
            from bastion_citadel.scanners.port_scanner import PortScanner
            scanner = PortScanner()
            await scanner.initialize()
            port_events = await scanner.execute(args.target if args.target else "localhost")
            events.extend(port_events)
        
        # Output results
        if args.output == 'json':
            output = json.dumps([e.to_dict() for e in events], indent=2)
            print(output)
        else:
            self.print_events(events)
        
        return 0
    
    async def handle_monitor(self, args: Any) -> int:
        """Handle the monitor command."""
        events = await self.agent.monitor()
        
        if args.output == 'json':
            output = json.dumps([e.to_dict() for e in events], indent=2)
            print(output)
        else:
            self.print_events(events)
        
        return 0
    
    async def handle_start(self, args: Any) -> int:
        """Handle the start command."""
        if args.interval:
            self.agent.config.scan_interval = args.interval
        
        print("Starting continuous monitoring...")
        print("Press Ctrl+C to stop")
        
        await self.agent.start_continuous_monitoring()
        
        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.agent.stop()
        
        return 0
    
    async def handle_stop(self, args: Any) -> int:
        """Handle the stop command."""
        await self.agent.stop()
        print("Agent stopped")
        return 0
    
    async def handle_status(self, args: Any) -> int:
        """Handle the status command."""
        status = self.agent.get_status()
        print("Security Agent Status:")
        print(f"  Name: {status['name']}")
        print(f"  Running: {status['running']}")
        print(f"  Plugins Loaded: {status['plugins_loaded']}")
        print(f"  Auto-Remediate: {status['auto_remediate']}")
        print(f"  Scan Interval: {status['scan_interval']}s")
        print(f"  Plugins: {', '.join(status['plugins'])}")
        return 0
    
    async def handle_config(self, args: Any) -> int:
        """Handle the config command."""
        if self.agent is None:
            self.agent = SecurityAgent()
        
        config_dict: Dict[str, Any] = {}
        
        if args.name:
            config_dict['name'] = args.name
        if args.interval:
            config_dict['scan_interval'] = args.interval
        if args.auto_remediate is not None:
            config_dict['auto_remediate'] = args.auto_remediate
        if args.log_level:
            config_dict['log_level'] = args.log_level
        
        if config_dict:
            new_config = AgentConfig.from_dict(config_dict)
            # Update specific fields
            for key, value in config_dict.items():
                setattr(self.agent.config, key, value)
            print(f"Configuration updated: {config_dict}")
        else:
            print("Current configuration:")
            print(f"  Name: {self.agent.config.name}")
            print(f"  Scan Interval: {self.agent.config.scan_interval}")
            print(f"  Auto-Remediate: {self.agent.config.auto_remediate}")
            print(f"  Log Level: {self.agent.config.log_level}")
        
        return 0
    
    async def handle_version(self, args: Any) -> int:
        """Handle the version command."""
        from bastion_citadel import __version__
        print(f"Bastion-Citadel v{__version__}")
        return 0
    
    def print_events(self, events: List[SecurityEvent]) -> None:
        """Print events in a readable format."""
        if not events:
            print("No security events found.")
            return
        
        print(f"\n{'='*80}")
        print(f"SECURITY SCAN RESULTS: {len(events)} events found")
        print(f"{'='*80}\n")
        
        # Group by severity
        critical = [e for e in events if e.severity == Severity.CRITICAL]
        high = [e for e in events if e.severity == Severity.HIGH]
        medium = [e for e in events if e.severity == Severity.MEDIUM]
        low = [e for e in events if e.severity == Severity.LOW]
        info = [e for e in events if e.severity == Severity.INFO]
        
        # Print summary
        print("SUMMARY:")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        print(f"  Medium: {len(medium)}")
        print(f"  Low: {len(low)}")
        print(f"  Info: {len(info)}")
        print()
        
        # Print events by severity
        for severity, severity_events in [
            (Severity.CRITICAL, critical),
            (Severity.HIGH, high),
            (Severity.MEDIUM, medium),
            (Severity.LOW, low),
            (Severity.INFO, info)
        ]:
            if severity_events:
                print(f"\n{'-'*80}")
                print(f"{severity.value.upper()} ({len(severity_events)} events)")
                print(f"{'-'*80}")
                
                for event in severity_events:
                    print(f"\n[{event.event_type.value}] {event.title}")
                    print(f"  Severity: {event.severity.value}")
                    print(f"  Source: {event.source}")
                    print(f"  Description: {event.description}")
                    if event.remediation:
                        print(f"  Remediation: {event.remediation}")
                    if event.metadata:
                        print(f"  Metadata: {event.metadata}")
        
        print(f"\n{'='*80}\n")


async def main() -> None:
    """Main entry point for the CLI."""
    cli = CLI()
    sys.exit(await cli.run())


if __name__ == "__main__":
    asyncio.run(main())
