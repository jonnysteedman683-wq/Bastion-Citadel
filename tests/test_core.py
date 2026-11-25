"""Tests for core components."""

import asyncio
import pytest
from datetime import datetime

from bastion_citadel.core.event import SecurityEvent, EventType, Severity
from bastion_citadel.core.agent import SecurityAgent, AgentConfig
from bastion_citadel.core.plugin import SecurityPlugin, PluginType, PluginManager


class TestSecurityEvent:
    """Tests for SecurityEvent."""
    
    def test_event_creation(self):
        """Test creating a security event."""
        event = SecurityEvent(
            event_type=EventType.VULNERABILITY_DETECTED,
            severity=Severity.HIGH,
            title="Test Event",
            description="Test description",
            source="test_source"
        )
        
        assert event.event_type == EventType.VULNERABILITY_DETECTED
        assert event.severity == Severity.HIGH
        assert event.title == "Test Event"
        assert event.description == "Test description"
        assert event.source == "test_source"
        assert event.timestamp is not None
        assert event.event_id is not None
    
    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event = SecurityEvent(
            event_type=EventType.ALERT,
            severity=Severity.CRITICAL,
            title="Alert",
            description="Test alert",
            source="test",
            remediation="Fix it"
        )
        
        data = event.to_dict()
        
        assert data["event_type"] == "alert"
        assert data["severity"] == "critical"
        assert data["title"] == "Alert"
        assert data["description"] == "Test alert"
        assert data["source"] == "test"
        assert data["remediation"] == "Fix it"
        assert "timestamp" in data
        assert "event_id" in data
    
    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        data = {
            "event_type": "vulnerability_detected",
            "severity": "high",
            "title": "Vulnerability",
            "description": "Test vuln",
            "source": "scanner",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"key": "value"}
        }
        
        event = SecurityEvent.from_dict(data)
        
        assert event.event_type == EventType.VULNERABILITY_DETECTED
        assert event.severity == Severity.HIGH
        assert event.title == "Vulnerability"
        assert event.source == "scanner"
        assert event.metadata == {"key": "value"}


class TestAgentConfig:
    """Tests for AgentConfig."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = AgentConfig()
        
        assert config.name == "Bastion-Citadel"
        assert config.scan_interval == 3600
        assert config.auto_remediate is False
        assert config.log_level == "INFO"
    
    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            "name": "Custom Agent",
            "scan_interval": 600,
            "auto_remediate": True,
            "log_level": "DEBUG"
        }
        
        config = AgentConfig.from_dict(data)
        
        assert config.name == "Custom Agent"
        assert config.scan_interval == 600
        assert config.auto_remediate is True
        assert config.log_level == "DEBUG"


@pytest.mark.asyncio
class TestSecurityAgent:
    """Tests for SecurityAgent."""
    
    async def test_agent_initialization(self):
        """Test agent initialization."""
        agent = SecurityAgent()
        await agent.initialize()
        
        assert agent.config is not None
        assert agent.plugin_manager is not None
        assert agent.running is False
    
    async def test_agent_status(self):
        """Test getting agent status."""
        agent = SecurityAgent()
        status = agent.get_status()
        
        assert "name" in status
        assert "running" in status
        assert "plugins_loaded" in status
        assert "plugins" in status
        assert status["running"] is False
    
    async def test_agent_scan(self):
        """Test running a scan."""
        agent = SecurityAgent()
        await agent.initialize()
        
        # This will run all scanner plugins
        events = await agent.scan()
        
        assert isinstance(events, list)


class TestPluginManager:
    """Tests for PluginManager."""
    
    def test_plugin_manager_initialization(self):
        """Test plugin manager initialization."""
        manager = PluginManager()
        
        assert manager.plugins == {}
        assert manager.instances == {}
    
    def test_register_plugin(self):
        """Test registering a plugin."""
        manager = PluginManager()
        
        class TestPlugin(SecurityPlugin):
            name = "test_plugin"
            plugin_type = PluginType.SCANNER
            
            async def initialize(self):
                return True
            
            async def execute(self, **kwargs):
                return {}
            
            async def cleanup(self):
                pass
        
        plugin = TestPlugin()
        manager.register_plugin(plugin)
        
        assert "test_plugin" in manager.plugins
        assert manager.plugins["test_plugin"] == TestPlugin
    
    @pytest.mark.asyncio
    async def test_load_plugin(self):
        """Test loading a plugin."""
        manager = PluginManager()
        
        class TestPlugin(SecurityPlugin):
            name = "test_plugin"
            plugin_type = PluginType.SCANNER
            
            async def initialize(self):
                return True
            
            async def execute(self, **kwargs):
                return {}
            
            async def cleanup(self):
                pass
        
        manager.register_plugin(TestPlugin())
        plugin = await manager.load_plugin("test_plugin")
        
        assert plugin is not None
        assert plugin.name == "test_plugin"
        assert "test_plugin" in manager.instances
