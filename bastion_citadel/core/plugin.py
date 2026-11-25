"""Plugin system for Bastion-Citadel security agent."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Type
import importlib
import pkgutil


class PluginType(Enum):
    """Types of security plugins."""
    SCANNER = "scanner"
    MONITOR = "monitor"
    REMEDIATOR = "remediator"
    ANALYZER = "analyzer"


class SecurityPlugin(ABC):
    """Base class for all security plugins."""
    
    name: str = ""
    version: str = "1.0.0"
    plugin_type: PluginType = PluginType.SCANNER
    description: str = ""
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict:
        """Execute the plugin's main functionality."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass


class PluginManager:
    """Manages loading and registration of security plugins."""
    
    def __init__(self):
        self.plugins: Dict[str, Type[SecurityPlugin]] = {}
        self.instances: Dict[str, SecurityPlugin] = {}
    
    def discover_plugins(self, package_name: str = "bastion_citadel") -> None:
        """Discover plugins in the specified package."""
        package = importlib.import_module(package_name)
        
        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            try:
                module = importlib.import_module(f"{package_name}.{module_name}")
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, SecurityPlugin) and 
                        attr != SecurityPlugin):
                        plugin_instance = attr()
                        self.register_plugin(plugin_instance)
            except ImportError:
                continue
    
    def register_plugin(self, plugin: SecurityPlugin) -> None:
        """Register a plugin."""
        if not plugin.name:
            raise ValueError("Plugin must have a name")
        self.plugins[plugin.name] = type(plugin)
    
    async def load_plugin(self, name: str, **config) -> SecurityPlugin:
        """Load and initialize a plugin."""
        if name not in self.plugins:
            raise ValueError(f"Plugin '{name}' not found")
        
        plugin_class = self.plugins[name]
        instance = plugin_class()
        
        if config:
            for key, value in config.items():
                setattr(instance, key, value)
        
        await instance.initialize()
        self.instances[name] = instance
        return instance
    
    async def load_all(self, **config) -> Dict[str, SecurityPlugin]:
        """Load all registered plugins."""
        results = {}
        for name in self.plugins:
            results[name] = await self.load_plugin(name, **config.get(name, {}))
        return results
    
    def get_plugin(self, name: str) -> Optional[SecurityPlugin]:
        """Get a loaded plugin instance."""
        return self.instances.get(name)
    
    def list_plugins(self) -> List[str]:
        """List all registered plugin names."""
        return list(self.plugins.keys())
