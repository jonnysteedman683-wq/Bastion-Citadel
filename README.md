# Bastion-Citadel: Autonomous Security Agent

[![Codacy Security Scan](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/codacy.yml/badge.svg)](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/codacy.yml)
[![Contrast Scan](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/contrast-scan.yml/badge.svg)](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/contrast-scan.yml)
[![Frogbot Scan and Fix](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/frogbot-scan-and-fix.yml/badge.svg)](https://github.com/jonnysteedman683-wq/Bastion-Citadel/actions/workflows/frogbot-scan-and-fix.yml)

**Bastion-Citadel** is an **autonomous security agent framework** that provides comprehensive security scanning, monitoring, and remediation capabilities. Built with a modular plugin architecture, it can detect vulnerabilities, monitor system integrity, and respond to threats in real-time.

## Features

### Core Capabilities
- **Modular Plugin System**: Easily extend with custom scanners, monitors, and remediators
- **Event-Driven Architecture**: React to security events in real-time
- **Continuous Monitoring**: Run scans on a schedule or trigger-based
- **Auto-Remediation**: Optionally automatically fix detected issues
- **Comprehensive Reporting**: Generate detailed security reports

### Built-in Plugins

#### Scanners
- **File Vulnerability Scanner**: Detects hardcoded secrets, insecure patterns, and file permission issues
- **Dependency Scanner**: Scans Python and Node.js projects for vulnerable dependencies
- **Port Scanner**: Identifies open ports and potentially dangerous services

#### Monitors
- **File Integrity Monitor**: Detects file modifications, additions, and deletions
- **Log Monitor**: Analyzes log files for security threats and suspicious activity

## Installation

### From Source

```bash
git clone https://github.com/jonnysteedman683-wq/Bastion-Citadel.git
cd Bastion-Citadel
pip install -e .
```

### Using pip (coming soon)

```bash
pip install bastion-citadel
```

## Usage

### Command Line Interface

```bash
# Show help
bastion --help

# Run a full security scan
bastion scan

# Scan a specific directory
bastion scan /path/to/project

# Run monitoring checks
bastion monitor

# Start continuous monitoring
bastion start --interval 3600

# Check agent status
bastion status

# Configure the agent
bastion config --auto-remediate --log-level DEBUG

# Show version
bastion version
```

### Scan Types

```bash
# Run all scanners
bastion scan --type all

# Run only file vulnerability scanner
bastion scan --type file

# Run only dependency scanner
bastion scan --type dependency

# Run only port scanner
bastion scan --type port
```

### Output Formats

```bash
# Text output (default)
bastion scan

# JSON output
bastion scan --output json
```

## Python API

```python
import asyncio
from bastion_citadel import SecurityAgent

async def main():
    # Create and initialize the agent
    agent = SecurityAgent()
    await agent.initialize()
    
    # Run a scan
    events = await agent.scan("/path/to/scan")
    
    for event in events:
        print(f"[{event.severity.value}] {event.title}: {event.description}")
    
    # Start continuous monitoring
    await agent.start_continuous_monitoring()
    
    # Later, stop the agent
    await agent.stop()

asyncio.run(main())
```

## Configuration

Create a `bastion-citadel.json` configuration file:

```json
{
  "agent_name": "My Security Agent",
  "scan_interval": 3600,
  "auto_remediate": false,
  "log_level": "INFO",
  "scan_paths": [".", "/etc", "/bin"],
  "exclude_patterns": [".git", "__pycache__", ".venv"],
  "monitor_paths": ["/etc", "/bin", "/usr/bin"],
  "log_files": ["/var/log/auth.log", "/var/log/syslog"],
  "plugin_config": {}
}
```

## Security Events

Bastion-Citadel generates security events with the following structure:

```python
{
    "event_id": "unique-id",
    "event_type": "vulnerability_detected|threat_detected|anomaly_detected|scan_started|scan_completed|remediation_applied|alert|info",
    "severity": "critical|high|medium|low|info",
    "title": "Event title",
    "description": "Detailed description",
    "source": "plugin_name",
    "timestamp": "ISO-8601 timestamp",
    "metadata": {"additional": "context"},
    "remediation": "Suggested fix"
}
```

## Extending Bastion-Citadel

Create custom plugins by subclassing `SecurityPlugin`:

```python
from bastion_citadel.core.plugin import SecurityPlugin, PluginType
from bastion_citadel.core.event import SecurityEvent, EventType, Severity

class MyCustomScanner(SecurityPlugin):
    name = "my_custom_scanner"
    plugin_type = PluginType.SCANNER
    description = "My custom security scanner"
    
    async def initialize(self) -> bool:
        # Initialize the plugin
        return True
    
    async def execute(self, **kwargs) -> List[SecurityEvent]:
        # Perform scanning
        events = []
        
        # Example: Detect something
        events.append(SecurityEvent(
            event_type=EventType.VULNERABILITY_DETECTED,
            severity=Severity.HIGH,
            title="Custom Issue Found",
            description="My scanner found an issue",
            source=self.name,
            remediation="Fix it"
        ))
        
        return events
    
    async def cleanup(self) -> None:
        # Clean up resources
        pass
```

## Security Best Practices

When using Bastion-Citadel:

1. **Run with least privilege**: Use a dedicated user with minimal permissions
2. **Secure configuration files**: Store sensitive data in environment variables
3. **Monitor the monitor**: Review Bastion-Citadel's own logs regularly
4. **Keep updated**: Regularly update to get the latest security checks
5. **Test in staging**: Test scans in non-production environments first

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Bastion-Citadel                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Security    │    │   Security    │    │   Security    │  │
│  │    Agent      │◄──►│    Events     │◄──►│   Plugins     │  │
│  │  (Core)       │    │  (Bus)       │    │  (Registry)   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│           ▲                   ▲                   ▲            │
│           │                   │                   │            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │    CLI       │    │  Config      │    │  Utils       │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    Plugins                              │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │  │
│  │  │  Scanners   │  │  Monitors   │  │ Remediators │    │  │
│  │  │             │  │             │  │             │    │  │
│  │  │ - File      │  │ - File      │  │ - Auto      │    │  │
│  │  │ - Dependency│  │   Integrity │  │   Fix       │    │  │
│  │  │ - Port      │  │ - Log       │  │             │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security

If you discover a security vulnerability in Bastion-Citadel, please report it responsibly by opening an issue or contacting the maintainers directly.

## Acknowledgments

- Inspired by security tools like OSSEC, Wazuh, and OpenVAS
- Built with Python's asyncio for high performance
- Designed for extensibility and ease of use
