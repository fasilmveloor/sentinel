"""
Plugin System for Sentinel.

Provides a flexible plugin architecture for extending Sentinel's capabilities.
Supports attack plugins, reporter plugins, and analysis plugins.

v3.0 Feature: Extensible Plugin Architecture
"""

import importlib
import inspect
import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, Any, List
from zipfile import ZipFile

from .models import (
    Endpoint,
    AttackResult,
    AttackType,
    Severity,
    HttpMethod,
    Vulnerability
)


class PluginType(Enum):
    """Types of plugins."""
    ATTACK = "attack"
    REPORTER = "reporter"
    ANALYZER = "analyzer"
    AUTH = "auth"
    PASSIVE = "passive"
    SCANNER = "scanner"


class PluginPriority(Enum):
    """Plugin execution priority."""
    HIGHEST = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    LOWEST = 5


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    priority: PluginPriority = PluginPriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    config_schema: Optional[dict] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class PluginContext:
    """Context provided to plugins during execution."""
    target_url: str
    endpoint: Optional[Endpoint] = None
    config: dict = field(default_factory=dict)
    shared_data: dict = field(default_factory=dict)
    request_count: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    
    # Results
    results: List[AttackResult] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    # Logging
    log_messages: List[dict] = field(default_factory=list)
    
    def log(self, level: str, message: str, data: Optional[dict] = None):
        """Log a message."""
        self.log_messages.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data
        })
    
    def debug(self, message: str, data: Optional[dict] = None):
        self.log("DEBUG", message, data)
    
    def info(self, message: str, data: Optional[dict] = None):
        self.log("INFO", message, data)
    
    def warning(self, message: str, data: Optional[dict] = None):
        self.log("WARNING", message, data)
    
    def error(self, message: str, data: Optional[dict] = None):
        self.log("ERROR", message, data)


class BasePlugin(ABC):
    """
    Abstract base class for all plugins.
    
    All plugins must inherit from this class and implement required methods.
    """
    
    # Plugin metadata - should be overridden
    INFO = PluginInfo(
        name="base_plugin",
        version="1.0.0",
        description="Base plugin class",
        author="Sentinel Team",
        plugin_type=PluginType.SCANNER
    )
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = True
        self._validate_config()
    
    def _validate_config(self):
        """Validate plugin configuration against schema."""
        if self.INFO.config_schema:
            # JSON Schema validation could be added here
            pass
    
    @abstractmethod
    def execute(self, context: PluginContext) -> list[AttackResult]:
        """
        Execute the plugin logic.
        
        Args:
            context: Plugin execution context
            
        Returns:
            List of attack results
        """
        pass
    
    def setup(self, context: PluginContext):
        """Called before plugin execution. Override for initialization."""
        pass
    
    def teardown(self, context: PluginContext):
        """Called after plugin execution. Override for cleanup."""
        pass
    
    def enable(self):
        """Enable the plugin."""
        self.enabled = True
    
    def disable(self):
        """Disable the plugin."""
        self.enabled = False
    
    def get_info(self) -> PluginInfo:
        """Get plugin information."""
        return self.INFO
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self.enabled and self.INFO.enabled


class AttackPlugin(BasePlugin):
    """
    Base class for attack plugins.
    
    Implement to create custom attack modules.
    """
    
    INFO = PluginInfo(
        name="attack_plugin",
        version="1.0.0",
        description="Base attack plugin",
        author="Sentinel Team",
        plugin_type=PluginType.ATTACK
    )
    
    def __init__(self, target_url: str, timeout: int = 5, config: Optional[dict] = None):
        super().__init__(config)
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
    
    @abstractmethod
    def attack(self, endpoint: Endpoint) -> list[AttackResult]:
        """Run the attack on an endpoint."""
        pass
    
    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Execute attack plugin."""
        if context.endpoint:
            return self.attack(context.endpoint)
        return []


class ReporterPlugin(BasePlugin):
    """
    Base class for reporter plugins.
    
    Implement to create custom report formats.
    """
    
    INFO = PluginInfo(
        name="reporter_plugin",
        version="1.0.0",
        description="Base reporter plugin",
        author="Sentinel Team",
        plugin_type=PluginType.REPORTER
    )
    
    @abstractmethod
    def generate(self, context: PluginContext) -> str:
        """Generate the report content."""
        pass
    
    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Reporter plugins don't return attack results."""
        return []


class AnalyzerPlugin(BasePlugin):
    """
    Base class for analyzer plugins.
    
    Implement to create custom result analysis.
    """
    
    INFO = PluginInfo(
        name="analyzer_plugin",
        version="1.0.0",
        description="Base analyzer plugin",
        author="Sentinel Team",
        plugin_type=PluginType.ANALYZER
    )
    
    @abstractmethod
    def analyze(self, resultsg: List[AttackResult]) -> dict:
        """Analyze attack results."""
        pass
    
    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Analyzer plugins process existing results."""
        if context.results:
            analysis = self.analyze(context.results)
            context.shared_data['analysis'] = analysis
        return []


class PassivePlugin(BasePlugin):
    """
    Base class for passive scanner plugins.
    
    Implement to add custom passive scanning rules.
    """
    
    INFO = PluginInfo(
        name="passive_plugin",
        version="1.0.0",
        description="Base passive plugin",
        author="Sentinel Team",
        plugin_type=PluginType.PASSIVE
    )
    
    @abstractmethod
    def check(self, request: dict, response: dict) -> list[dict]:
        """
        Check for security issues in request/response.
        
        Args:
            request: Request dict with url, method, headers, body
            response: Response dict with status, headers, body
            
        Returns:
            List of finding dicts
        """
        pass
    
    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Passive plugins process traffic, not endpoints."""
        return []


class PluginManager:
    """
    Manages plugin discovery, loading, and execution.
    
    Features:
    - Plugin discovery from directories
    - Plugin loading from Python modules
    - Plugin isolation and error handling
    - Plugin configuration management
    """
    
    def __init__(self, plugin_dirs: Optional[list[str]] = None):
        self.plugins: dict[str, BasePlugin] = {}
        self.plugin_classes: dict[str, type] = {}
        self.plugin_dirs = plugin_dirs or []
        self._hooks: dict[str, list[Callable]] = {}
        
        # Add default plugin directory
        default_dir = Path(__file__).parent / "plugins"
        if default_dir.exists():
            self.plugin_dirs.append(str(default_dir))
    
    def discover_plugins(self) -> list[str]:
        """
        Discover available plugins in plugin directories.
        
        Returns:
            List of discovered plugin names
        """
        discovered = []
        
        for plugin_dir in self.plugin_dirs:
            plugin_path = Path(plugin_dir)
            if not plugin_path.exists():
                continue
            
            # Find Python files
            for py_file in plugin_path.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                
                module_name = py_file.stem
                discovered.append(module_name)
            
            # Find plugin packages
            for pkg_dir in plugin_path.iterdir():
                if pkg_dir.is_dir() and (pkg_dir / "__init__.py").exists():
                    discovered.append(pkg_dir.name)
        
        return discovered
    
    def load_plugin(self, plugin_path: str) -> Optional[BasePlugin]:
        """
        Load a plugin from a file path or module name.
        
        Args:
            plugin_path: Path to plugin file or module name
            
        Returns:
            Loaded plugin instance or None
        """
        try:
            # Handle file path
            if plugin_path.endswith(".py"):
                spec = importlib.util.spec_from_file_location(
                    "custom_plugin",
                    plugin_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            else:
                # Handle module name
                module = importlib.import_module(plugin_path)
            
            # Find plugin classes
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BasePlugin) and obj != BasePlugin and \
                   obj != AttackPlugin and obj != ReporterPlugin and \
                   obj != AnalyzerPlugin and obj != PassivePlugin:
                    plugin_class = obj
                    break
            
            if plugin_class:
                instance = plugin_class()
                self.plugins[instance.INFO.name] = instance
                self.plugin_classes[instance.INFO.name] = plugin_class
                return instance
            
        except Exception as e:
            print(f"Error loading plugin {plugin_path}: {e}")
        
        return None
    
    def load_plugins_from_dir(self, directory: str):
        """Load all plugins from a directory."""
        plugin_path = Path(directory)
        
        if not plugin_path.exists():
            return
        
        for py_file in plugin_path.glob("*.py"):
            if not py_file.name.startswith("_"):
                self.load_plugin(str(py_file))
    
    def register_plugin(self, plugin: BasePlugin):
        """Register a plugin instance."""
        self.plugins[plugin.INFO.name] = plugin
    
    def unregister_plugin(self, name: str):
        """Unregister a plugin by name."""
        self.plugins.pop(name, None)
        self.plugin_classes.pop(name, None)
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> list[BasePlugin]:
        """Get all plugins of a specific type."""
        return [
            p for p in self.plugins.values()
            if p.INFO.plugin_type == plugin_type and p.is_enabled()
        ]
    
    def execute_plugin(self, name: str, context: PluginContext) -> list[AttackResult]:
        """
        Execute a plugin by name.
        
        Args:
            name: Plugin name
            context: Execution context
            
        Returns:
            Plugin results
        """
        plugin = self.plugins.get(name)
        
        if not plugin:
            context.error(f"Plugin not found: {name}")
            return []
        
        if not plugin.is_enabled():
            context.warning(f"Plugin disabled: {name}")
            return []
        
        try:
            # Setup
            plugin.setup(context)
            
            # Execute
            results = plugin.execute(context)
            
            # Teardown
            plugin.teardown(context)
            
            return results
            
        except Exception as e:
            context.error(f"Plugin execution error: {name}", {"error": str(e)})
            return []
    
    def execute_all(self, plugin_type: Optional[PluginType], 
                    context: PluginContext) -> list[AttackResult]:
        """
        Execute all plugins of a type in priority order.
        
        Args:
            plugin_type: Type of plugins to execute (None for all)
            context: Execution context
            
        Returns:
            Combined results from all plugins
        """
        all_results = []
        
        # Get plugins and sort by priority
        plugins = list(self.plugins.values())
        if plugin_type:
            plugins = [p for p in plugins if p.INFO.plugin_type == plugin_type]
        
        plugins.sort(key=lambda p: p.INFO.priority.value)
        
        for plugin in plugins:
            if plugin.is_enabled():
                results = self.execute_plugin(plugin.INFO.name, context)
                all_results.extend(results)
        
        return all_results
    
    def add_hook(self, event: str, callback: Callable):
        """Add a callback for a plugin event."""
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append(callback)
    
    def trigger_hook(self, event: str, *args, **kwargs):
        """Trigger callbacks for a plugin event."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"Hook callback error: {e}")
    
    def list_plugins(self) -> list[dict]:
        """List all registered plugins with their info."""
        return [
            {
                "name": p.INFO.name,
                "version": p.INFO.version,
                "type": p.INFO.plugin_type.value,
                "enabled": p.is_enabled(),
                "description": p.INFO.description
            }
            for p in self.plugins.values()
        ]
    
    def enable_plugin(self, name: str):
        """Enable a plugin by name."""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enable()
    
    def disable_plugin(self, name: str):
        """Disable a plugin by name."""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.disable()
    
    def configure_plugin(self, name: str, config: dict):
        """Configure a plugin."""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.config.update(config)
    
    def create_plugin_package(self, plugin_class: type, output_path: str):
        """
        Package a plugin for distribution.
        
        Args:
            plugin_class: Plugin class to package
            output_path: Output directory for the package
        """
        import shutil
        
        # Get plugin source file
        source_file = inspect.getfile(plugin_class)
        plugin_name = plugin_class.INFO.name
        
        # Create package directory
        pkg_dir = Path(output_path) / plugin_name
        pkg_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy plugin file
        shutil.copy(source_file, pkg_dir / Path(source_file).name)
        
        # Create manifest
        manifest = {
            "name": plugin_name,
            "version": plugin_class.INFO.version,
            "description": plugin_class.INFO.description,
            "author": plugin_class.INFO.author,
            "type": plugin_class.INFO.plugin_type.value,
            "main": Path(source_file).name
        }
        
        with open(pkg_dir / "manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)
        
        # Create zip
        zip_path = Path(output_path) / f"{plugin_name}.zip"
        with ZipFile(zip_path, "w") as zf:
            for file in pkg_dir.iterdir():
                zf.write(file, arcname=f"{plugin_name}/{file.name}")
        
        # Cleanup
        shutil.rmtree(pkg_dir)
        
        return str(zip_path)


# Plugin template generators

def create_attack_plugin_template(name: str, output_dir: str) -> str:
    """Generate an attack plugin template."""
    
    template = f'''"""
{name} Attack Plugin for Sentinel.

Auto-generated attack plugin template.
"""

from sentinel.plugin import AttackPlugin, PluginInfo, PluginType, PluginPriority
from sentinel.models import Endpoint, AttackResult, Severity


class {name.replace("_", "").title()}Plugin(AttackPlugin):
    """Custom attack plugin: {name}"""
    
    INFO = PluginInfo(
        name="{name}",
        version="1.0.0",
        description="Custom attack plugin for {name}",
        author="Your Name",
        plugin_type=PluginType.ATTACK,
        priority=PluginPriority.NORMAL,
        tags=["custom", "attack"]
    )
    
    def attack(self, endpoint: Endpoint) -> list[AttackResult]:
        """Execute the attack."""
        results = []
        
        # TODO: Implement your attack logic here
        
        # Example: Test a parameter
        for param in endpoint.parameters:
            result = AttackResult(
                endpoint=endpoint,
                attack_type=self.INFO.name,
                success=False,  # Set to True if vulnerability found
                severity=Severity.MEDIUM,
                payload="test_payload",
                evidence="",
                description=f"Testing {{param.name}} for {name}"
            )
            results.append(result)
        
        return results
'''
    
    output_path = Path(output_dir) / f"{name}_plugin.py"
    output_path.write_text(template)
    return str(output_path)


def create_passive_plugin_template(name: str, output_dir: str) -> str:
    """Generate a passive scanner plugin template."""
    
    template = f'''"""
{name} Passive Plugin for Sentinel.

Auto-generated passive scanner plugin template.
"""

from sentinel.plugin import PassivePlugin, PluginInfo, PluginType, PluginPriority


class {name.replace("_", "").title()}Plugin(PassivePlugin):
    """Custom passive plugin: {name}"""
    
    INFO = PluginInfo(
        name="{name}",
        version="1.0.0",
        description="Custom passive scanner for {name}",
        author="Your Name",
        plugin_type=PluginType.PASSIVE,
        priority=PluginPriority.NORMAL
    )
    
    def check(self, request: dict, response: dict) -> list[dict]:
        """Check request/response for security issues."""
        findings = []
        
        # Request structure:
        # request = {{'url': str, 'method': str, 'headers': dict, 'body': str}}
        
        # Response structure:
        # response = {{'status': int, 'headers': dict, 'body': str}}
        
        # TODO: Implement your passive check logic here
        
        # Example: Check for missing header
        if "X-Custom-Header" not in response.get("headers", {{}}):
            findings.append({{
                "title": "Missing X-Custom-Header",
                "severity": "low",
                "description": "Response missing custom security header",
                "evidence": "Header not found in response"
            }})
        
        return findings
'''
    
    output_path = Path(output_dir) / f"{name}_passive_plugin.py"
    output_path.write_text(template)
    return str(output_path)


# Create default plugin manager instance
plugin_manager = PluginManager()


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    return plugin_manager
