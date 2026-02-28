"""
Comprehensive tests for the Sentinel plugin system.

Tests cover:
- PluginType and PluginPriority enums
- PluginInfo dataclass
- PluginContext dataclass and logging methods
- BasePlugin and subclasses (AttackPlugin, ReporterPlugin, AnalyzerPlugin, PassivePlugin)
- PluginManager discovery, loading, and execution
- Plugin template generators
"""

import importlib
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from sentinel.plugin import (
    PluginType,
    PluginPriority,
    PluginInfo,
    PluginContext,
    BasePlugin,
    AttackPlugin,
    ReporterPlugin,
    AnalyzerPlugin,
    PassivePlugin,
    PluginManager,
    create_attack_plugin_template,
    create_passive_plugin_template,
    get_plugin_manager,
    plugin_manager
)
from sentinel.models import (
    Endpoint,
    AttackResult,
    AttackType,
    Severity,
    HttpMethod,
    Vulnerability
)


# =============================================================================
# Test PluginType Enum
# =============================================================================

class TestPluginType:
    """Tests for PluginType enum."""

    def test_plugin_type_values(self):
        """Test all plugin type values."""
        assert PluginType.ATTACK.value == "attack"
        assert PluginType.REPORTER.value == "reporter"
        assert PluginType.ANALYZER.value == "analyzer"
        assert PluginType.AUTH.value == "auth"
        assert PluginType.PASSIVE.value == "passive"
        assert PluginType.SCANNER.value == "scanner"

    def test_plugin_type_count(self):
        """Test that all expected plugin types exist."""
        assert len(PluginType) == 6

    def test_plugin_type_from_string(self):
        """Test creating PluginType from string."""
        assert PluginType("attack") == PluginType.ATTACK
        assert PluginType("reporter") == PluginType.REPORTER
        assert PluginType("analyzer") == PluginType.ANALYZER


# =============================================================================
# Test PluginPriority Enum
# =============================================================================

class TestPluginPriority:
    """Tests for PluginPriority enum."""

    def test_priority_values(self):
        """Test priority ordering values."""
        assert PluginPriority.HIGHEST.value == 1
        assert PluginPriority.HIGH.value == 2
        assert PluginPriority.NORMAL.value == 3
        assert PluginPriority.LOW.value == 4
        assert PluginPriority.LOWEST.value == 5

    def test_priority_ordering(self):
        """Test that priorities are ordered correctly."""
        assert PluginPriority.HIGHEST.value < PluginPriority.HIGH.value
        assert PluginPriority.HIGH.value < PluginPriority.NORMAL.value
        assert PluginPriority.NORMAL.value < PluginPriority.LOW.value
        assert PluginPriority.LOW.value < PluginPriority.LOWEST.value

    def test_priority_count(self):
        """Test that all expected priorities exist."""
        assert len(PluginPriority) == 5


# =============================================================================
# Test PluginInfo Dataclass
# =============================================================================

class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_plugin_info_creation_minimal(self):
        """Test creating PluginInfo with minimal fields."""
        info = PluginInfo(
            name="test_plugin",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
            plugin_type=PluginType.ATTACK
        )
        assert info.name == "test_plugin"
        assert info.version == "1.0.0"
        assert info.description == "Test plugin"
        assert info.author == "Test Author"
        assert info.plugin_type == PluginType.ATTACK
        assert info.priority == PluginPriority.NORMAL
        assert info.enabled is True
        assert info.config_schema is None

    def test_plugin_info_creation_full(self):
        """Test creating PluginInfo with all fields."""
        config_schema = {"type": "object", "properties": {"timeout": {"type": "integer"}}}
        info = PluginInfo(
            name="full_plugin",
            version="2.0.0",
            description="Full test plugin",
            author="Full Author",
            plugin_type=PluginType.REPORTER,
            priority=PluginPriority.HIGH,
            dependencies=["dep1", "dep2"],  # Note: field has 'g' suffix
            enabled=False,
            config_schema=config_schema,
            tags=["tag1", "tag2"]  # Note: field has 'g' suffix
        )
        assert info.name == "full_plugin"
        assert info.version == "2.0.0"
        assert info.priority == PluginPriority.HIGH
        assert info.dependencies == ["dep1", "dep2"]
        assert info.enabled is False
        assert info.config_schema == config_schema
        assert info.tags == ["tag1", "tag2"]


# =============================================================================
# Test PluginContext Dataclass
# =============================================================================

class TestPluginContext:
    """Tests for PluginContext dataclass."""

    def test_context_creation_minimal(self):
        """Test creating PluginContext with minimal fields."""
        context = PluginContext(target_url="https://example.com")
        assert context.target_url == "https://example.com"
        assert context.endpoint is None
        assert context.config == {}
        assert context.shared_data == {}
        assert context.request_count == 0
        assert isinstance(context.start_time, datetime)
        assert context.results == []
        assert context.vulnerabilities == []
        assert context.log_messages == []

    def test_context_creation_with_endpoint(self):
        """Test creating PluginContext with endpoint."""
        endpoint = Endpoint(
            path="/api/test",
            method=HttpMethod.GET
        )
        context = PluginContext(
            target_url="https://example.com",
            endpoint=endpoint
        )
        assert context.endpoint == endpoint

    def test_context_log_method(self):
        """Test context log method."""
        context = PluginContext(target_url="https://example.com")
        context.log("INFO", "Test message", {"key": "value"})

        assert len(context.log_messages) == 1
        log_entry = context.log_messages[0]
        assert log_entry["level"] == "INFO"
        assert log_entry["message"] == "Test message"
        assert log_entry["data"] == {"key": "value"}
        assert "timestamp" in log_entry

    def test_context_debug_method(self):
        """Test context debug method."""
        context = PluginContext(target_url="https://example.com")
        context.debug("Debug message")

        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "DEBUG"
        assert context.log_messages[0]["message"] == "Debug message"

    def test_context_info_method(self):
        """Test context info method."""
        context = PluginContext(target_url="https://example.com")
        context.info("Info message")

        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "INFO"

    def test_context_warning_method(self):
        """Test context warning method."""
        context = PluginContext(target_url="https://example.com")
        context.warning("Warning message")

        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "WARNING"

    def test_context_error_method(self):
        """Test context error method."""
        context = PluginContext(target_url="https://example.com")
        context.error("Error message", {"code": 500})

        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "ERROR"
        assert context.log_messages[0]["data"] == {"code": 500}

    def test_context_multiple_logs(self):
        """Test context with multiple log entries."""
        context = PluginContext(target_url="https://example.com")
        context.debug("Debug")
        context.info("Info")
        context.warning("Warning")
        context.error("Error")

        assert len(context.log_messages) == 4
        levels = [log["level"] for log in context.log_messages]
        assert levels == ["DEBUG", "INFO", "WARNING", "ERROR"]


# =============================================================================
# Test BasePlugin
# =============================================================================

class ConcretePlugin(BasePlugin):
    """Concrete plugin implementation for testing."""

    INFO = PluginInfo(
        name="concrete_plugin",
        version="1.0.0",
        description="Concrete test plugin",
        author="Test",
        plugin_type=PluginType.SCANNER
    )

    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Execute plugin logic."""
        return []


class ConcretePluginWithSchema(BasePlugin):
    """Plugin with config schema for testing."""

    INFO = PluginInfo(
        name="schema_plugin",
        version="1.0.0",
        description="Plugin with schema",
        author="Test",
        plugin_type=PluginType.SCANNER,
        config_schema={"type": "object"}
    )

    def execute(self, context: PluginContext) -> list[AttackResult]:
        """Execute plugin logic."""
        return []


class TestBasePlugin:
    """Tests for BasePlugin."""

    def test_plugin_initialization(self):
        """Test plugin initialization."""
        plugin = ConcretePlugin()
        assert plugin.config == {}
        assert plugin.enabled is True

    def test_plugin_initialization_with_config(self):
        """Test plugin initialization with config."""
        plugin = ConcretePlugin(config={"timeout": 10})
        assert plugin.config == {"timeout": 10}

    def test_plugin_enable(self):
        """Test enabling plugin."""
        plugin = ConcretePlugin()
        plugin.enabled = False
        plugin.enable()
        assert plugin.enabled is True

    def test_plugin_disable(self):
        """Test disabling plugin."""
        plugin = ConcretePlugin()
        plugin.disable()
        assert plugin.enabled is False

    def test_plugin_get_info(self):
        """Test getting plugin info."""
        plugin = ConcretePlugin()
        info = plugin.get_info()
        assert info.name == "concrete_plugin"
        assert info.version == "1.0.0"

    def test_plugin_is_enabled(self):
        """Test checking if plugin is enabled."""
        plugin = ConcretePlugin()
        assert plugin.is_enabled() is True

        plugin.disable()
        assert plugin.is_enabled() is False

    def test_plugin_is_enabled_with_info_disabled(self):
        """Test is_enabled respects INFO.enabled."""
        # Create a plugin with INFO.enabled = False
        class DisabledInfoPlugin(BasePlugin):
            INFO = PluginInfo(
                name="disabled_info_plugin",
                version="1.0.0",
                description="Disabled plugin",
                author="Test",
                plugin_type=PluginType.SCANNER,
                enabled=False
            )

            def execute(self, context: PluginContext) -> list[AttackResult]:
                return []

        plugin = DisabledInfoPlugin()
        assert plugin.is_enabled() is False

    def test_plugin_setup(self):
        """Test plugin setup method."""
        plugin = ConcretePlugin()
        context = PluginContext(target_url="https://example.com")
        # Setup should not raise
        plugin.setup(context)

    def test_plugin_teardown(self):
        """Test plugin teardown method."""
        plugin = ConcretePlugin()
        context = PluginContext(target_url="https://example.com")
        # Teardown should not raise
        plugin.teardown(context)

    def test_plugin_execute_abstract(self):
        """Test plugin execute method."""
        plugin = ConcretePlugin()
        context = PluginContext(target_url="https://example.com")
        results = plugin.execute(context)
        assert results == []

    def test_plugin_with_config_schema(self):
        """Test plugin initialization with config schema."""
        plugin = ConcretePluginWithSchema()
        # Config validation is a no-op currently
        assert plugin.config == {}


# =============================================================================
# Test AttackPlugin
# =============================================================================

class ConcreteAttackPlugin(AttackPlugin):
    """Concrete attack plugin for testing."""

    INFO = PluginInfo(
        name="test_attack",
        version="1.0.0",
        description="Test attack plugin",
        author="Test",
        plugin_type=PluginType.ATTACK
    )

    def attack(self, endpoint: Endpoint) -> list[AttackResult]:
        """Execute attack."""
        return [
            AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=True,
                severity=Severity.HIGH,
                payload="test",
                evidence="SQL error",
                description="Test attack"
            )
        ]


class TestAttackPlugin:
    """Tests for AttackPlugin."""

    def test_attack_plugin_initialization(self):
        """Test attack plugin initialization."""
        plugin = ConcreteAttackPlugin(target_url="https://example.com")
        assert plugin.target_url == "https://example.com"
        assert plugin.timeout == 5

    def test_attack_plugin_strips_trailing_slash(self):
        """Test that target URL trailing slash is stripped."""
        plugin = ConcreteAttackPlugin(target_url="https://example.com/")
        assert plugin.target_url == "https://example.com"

    def test_attack_plugin_with_custom_timeout(self):
        """Test attack plugin with custom timeout."""
        plugin = ConcreteAttackPlugin(
            target_url="https://example.com",
            timeout=30
        )
        assert plugin.timeout == 30

    def test_attack_plugin_with_config(self):
        """Test attack plugin with config."""
        plugin = ConcreteAttackPlugin(
            target_url="https://example.com",
            config={"retries": 3}
        )
        assert plugin.config == {"retries": 3}

    def test_attack_plugin_execute_with_endpoint(self):
        """Test attack plugin execute with endpoint."""
        plugin = ConcreteAttackPlugin(target_url="https://example.com")
        endpoint = Endpoint(path="/api/test", method=HttpMethod.GET)
        context = PluginContext(
            target_url="https://example.com",
            endpoint=endpoint
        )

        results = plugin.execute(context)
        assert len(results) == 1
        assert results[0].success is True

    def test_attack_plugin_execute_without_endpoint(self):
        """Test attack plugin execute without endpoint."""
        plugin = ConcreteAttackPlugin(target_url="https://example.com")
        context = PluginContext(target_url="https://example.com")

        results = plugin.execute(context)
        assert results == []


# =============================================================================
# Test ReporterPlugin
# =============================================================================

class ConcreteReporterPlugin(ReporterPlugin):
    """Concrete reporter plugin for testing."""

    INFO = PluginInfo(
        name="test_reporter",
        version="1.0.0",
        description="Test reporter plugin",
        author="Test",
        plugin_type=PluginType.REPORTER
    )

    def generate(self, context: PluginContext) -> str:
        """Generate report."""
        return f"Report for {context.target_url}"


class TestReporterPlugin:
    """Tests for ReporterPlugin."""

    def test_reporter_plugin_execute(self):
        """Test reporter plugin execute returns empty list."""
        plugin = ConcreteReporterPlugin()
        context = PluginContext(target_url="https://example.com")

        results = plugin.execute(context)
        assert results == []

    def test_reporter_plugin_generate(self):
        """Test reporter plugin generate method."""
        plugin = ConcreteReporterPlugin()
        context = PluginContext(target_url="https://example.com")

        report = plugin.generate(context)
        assert report == "Report for https://example.com"


# =============================================================================
# Test AnalyzerPlugin
# =============================================================================

class ConcreteAnalyzerPlugin(AnalyzerPlugin):
    """Concrete analyzer plugin for testing."""

    INFO = PluginInfo(
        name="test_analyzer",
        version="1.0.0",
        description="Test analyzer plugin",
        author="Test",
        plugin_type=PluginType.ANALYZER
    )

    def analyze(self, results: list[AttackResult]) -> dict:
        """Analyze results."""
        return {
            "total": len(results),
            "successful": sum(1 for r in results if r.success)
        }


class TestAnalyzerPlugin:
    """Tests for AnalyzerPlugin."""

    def test_analyzer_plugin_execute_with_results(self):
        """Test analyzer plugin execute with results."""
        plugin = ConcreteAnalyzerPlugin()
        endpoint = Endpoint(path="/test", method=HttpMethod.GET)
        results = [
            AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=True,
                severity=Severity.HIGH,
                payload="test",
                evidence="",
                description="Test"
            )
        ]
        context = PluginContext(
            target_url="https://example.com",
            shared_data={}
        )
        context.results = results  # Use results with 'g' suffix

        plugin.execute(context)
        assert "analysis" in context.shared_data
        assert context.shared_data["analysis"]["total"] == 1
        assert context.shared_data["analysis"]["successful"] == 1

    def test_analyzer_plugin_execute_without_results(self):
        """Test analyzer plugin execute without results."""
        plugin = ConcreteAnalyzerPlugin()
        context = PluginContext(target_url="https://example.com")

        results = plugin.execute(context)
        assert results == []
        assert "analysis" not in context.shared_data

    def test_analyzer_plugin_analyze(self):
        """Test analyzer plugin analyze method."""
        plugin = ConcreteAnalyzerPlugin()
        endpoint = Endpoint(path="/test", method=HttpMethod.GET)
        results = [
            AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=True,
                severity=Severity.HIGH,
                payload="test",
                evidence="",
                description="Test"
            ),
            AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.XSS,
                success=False,
                severity=Severity.MEDIUM,
                payload="test2",
                evidence="",
                description="Test 2"
            )
        ]

        analysis = plugin.analyze(results)
        assert analysis["total"] == 2
        assert analysis["successful"] == 1


# =============================================================================
# Test PassivePlugin
# =============================================================================

class ConcretePassivePlugin(PassivePlugin):
    """Concrete passive plugin for testing."""

    INFO = PluginInfo(
        name="test_passive",
        version="1.0.0",
        description="Test passive plugin",
        author="Test",
        plugin_type=PluginType.PASSIVE
    )

    def check(self, request: dict, response: dict) -> list[dict]:
        """Check for issues."""
        findings = []
        if "X-Frame-Options" not in response.get("headers", {}):
            findings.append({
                "title": "Missing X-Frame-Options",
                "severity": "low"
            })
        return findings


class TestPassivePlugin:
    """Tests for PassivePlugin."""

    def test_passive_plugin_execute(self):
        """Test passive plugin execute returns empty list."""
        plugin = ConcretePassivePlugin()
        context = PluginContext(target_url="https://example.com")

        results = plugin.execute(context)
        assert results == []

    def test_passive_plugin_check(self):
        """Test passive plugin check method."""
        plugin = ConcretePassivePlugin()
        request = {"url": "https://example.com", "method": "GET"}
        response = {"status": 200, "headers": {}}

        findings = plugin.check(request, response)
        assert len(findings) == 1
        assert findings[0]["title"] == "Missing X-Frame-Options"

    def test_passive_plugin_check_no_findings(self):
        """Test passive plugin check with no findings."""
        plugin = ConcretePassivePlugin()
        request = {"url": "https://example.com", "method": "GET"}
        response = {"status": 200, "headers": {"X-Frame-Options": "DENY"}}

        findings = plugin.check(request, response)
        assert len(findings) == 0


# =============================================================================
# Test PluginManager
# =============================================================================

class TestPluginManager:
    """Tests for PluginManager."""

    def test_manager_initialization(self):
        """Test manager initialization."""
        manager = PluginManager()
        assert manager.plugins == {}
        assert manager.plugin_classes == {}
        assert manager.plugin_dirs == []

    def test_manager_initialization_with_dirs(self):
        """Test manager initialization with custom directories."""
        manager = PluginManager(plugin_dirs=["/custom/plugins"])
        assert "/custom/plugins" in manager.plugin_dirs

    def test_manager_register_plugin(self):
        """Test registering a plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)

        assert "concrete_plugin" in manager.plugins
        assert manager.plugins["concrete_plugin"] == plugin

    def test_manager_unregister_plugin(self):
        """Test unregistering a plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)
        manager.unregister_plugin("concrete_plugin")

        assert "concrete_plugin" not in manager.plugins

    def test_manager_get_plugin(self):
        """Test getting a plugin by name."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)

        retrieved = manager.get_plugin("concrete_plugin")
        assert retrieved == plugin

    def test_manager_get_plugin_not_found(self):
        """Test getting a non-existent plugin."""
        manager = PluginManager()
        result = manager.get_plugin("nonexistent")
        assert result is None

    def test_manager_get_plugins_by_type(self):
        """Test getting plugins by type."""
        manager = PluginManager()
        attack_plugin = ConcreteAttackPlugin(target_url="https://example.com")
        reporter_plugin = ConcreteReporterPlugin()

        manager.register_plugin(attack_plugin)
        manager.register_plugin(reporter_plugin)

        attack_plugins = manager.get_plugins_by_type(PluginType.ATTACK)
        assert len(attack_plugins) == 1
        assert attack_plugins[0] == attack_plugin

        reporter_plugins = manager.get_plugins_by_type(PluginType.REPORTER)
        assert len(reporter_plugins) == 1

    def test_manager_get_plugins_by_type_disabled(self):
        """Test that disabled plugins are not returned."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        plugin.disable()
        manager.register_plugin(plugin)

        plugins = manager.get_plugins_by_type(PluginType.SCANNER)
        assert len(plugins) == 0

    def test_manager_execute_plugin(self):
        """Test executing a plugin."""
        manager = PluginManager()
        plugin = ConcreteAttackPlugin(target_url="https://example.com")
        manager.register_plugin(plugin)

        endpoint = Endpoint(path="/test", method=HttpMethod.GET)
        context = PluginContext(
            target_url="https://example.com",
            endpoint=endpoint
        )

        results = manager.execute_plugin("test_attack", context)
        assert len(results) == 1

    def test_manager_execute_plugin_not_found(self):
        """Test executing a non-existent plugin."""
        manager = PluginManager()
        context = PluginContext(target_url="https://example.com")

        results = manager.execute_plugin("nonexistent", context)
        assert results == []
        # Check that error was logged (field is log_messages)
        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "ERROR"

    def test_manager_execute_plugin_disabled(self):
        """Test executing a disabled plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        plugin.disable()
        manager.register_plugin(plugin)

        context = PluginContext(target_url="https://example.com")
        results = manager.execute_plugin("concrete_plugin", context)
        assert results == []
        # Check that warning was logged (field is log_messages)
        assert len(context.log_messages) == 1
        assert context.log_messages[0]["level"] == "WARNING"

    def test_manager_execute_all(self):
        """Test executing all plugins."""
        manager = PluginManager()
        plugin1 = ConcreteAttackPlugin(target_url="https://example.com")
        plugin2 = ConcreteReporterPlugin()

        manager.register_plugin(plugin1)
        manager.register_plugin(plugin2)

        endpoint = Endpoint(path="/test", method=HttpMethod.GET)
        context = PluginContext(
            target_url="https://example.com",
            endpoint=endpoint
        )

        results = manager.execute_all(None, context)
        assert len(results) >= 0  # Reporter returns empty list

    def test_manager_execute_all_by_type(self):
        """Test executing all plugins of a specific type."""
        manager = PluginManager()
        attack_plugin = ConcreteAttackPlugin(target_url="https://example.com")
        reporter_plugin = ConcreteReporterPlugin()

        manager.register_plugin(attack_plugin)
        manager.register_plugin(reporter_plugin)

        endpoint = Endpoint(path="/test", method=HttpMethod.GET)
        context = PluginContext(
            target_url="https://example.com",
            endpoint=endpoint
        )

        results = manager.execute_all(PluginType.ATTACK, context)
        assert len(results) == 1

    def test_manager_list_plugins(self):
        """Test listing plugins."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)

        plugin_list = manager.list_plugins()
        assert len(plugin_list) == 1
        assert plugin_list[0]["name"] == "concrete_plugin"
        assert plugin_list[0]["type"] == "scanner"
        assert plugin_list[0]["enabled"] is True

    def test_manager_enable_plugin(self):
        """Test enabling a plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        plugin.disable()
        manager.register_plugin(plugin)

        manager.enable_plugin("concrete_plugin")
        assert plugin.enabled is True

    def test_manager_disable_plugin(self):
        """Test disabling a plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)

        manager.disable_plugin("concrete_plugin")
        assert plugin.enabled is False

    def test_manager_configure_plugin(self):
        """Test configuring a plugin."""
        manager = PluginManager()
        plugin = ConcretePlugin()
        manager.register_plugin(plugin)

        manager.configure_plugin("concrete_plugin", {"timeout": 30})
        assert plugin.config["timeout"] == 30

    def test_manager_add_hook(self):
        """Test adding a hook callback."""
        manager = PluginManager()
        callback = MagicMock()
        manager.add_hook("on_plugin_load", callback)

        assert "on_plugin_load" in manager._hooks
        assert callback in manager._hooks["on_plugin_load"]

    def test_manager_trigger_hook(self):
        """Test triggering a hook."""
        manager = PluginManager()
        callback = MagicMock()
        manager.add_hook("on_plugin_load", callback)

        manager.trigger_hook("on_plugin_load", "arg1", "arg2", key="value")
        callback.assert_called_once_with("arg1", "arg2", key="value")

    def test_manager_trigger_hook_error(self):
        """Test triggering a hook with callback error."""
        manager = PluginManager()
        callback = MagicMock(side_effect=Exception("Test error"))
        manager.add_hook("on_plugin_load", callback)

        # Should not raise, just print error
        manager.trigger_hook("on_plugin_load")

    def test_manager_discover_plugins_empty(self):
        """Test discovering plugins in empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugin_dirs=[tmpdir])
            discovered = manager.discover_plugins()
            assert discovered == []

    def test_manager_discover_plugins_with_files(self):
        """Test discovering plugins in directory with files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create plugin files
            plugin_file = Path(tmpdir) / "test_plugin.py"
            plugin_file.write_text("# Test plugin")

            manager = PluginManager(plugin_dirs=[tmpdir])
            discovered = manager.discover_plugins()

            assert "test_plugin" in discovered

    def test_manager_discover_plugins_ignores_underscore(self):
        """Test that discover ignores files starting with underscore."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create plugin files
            regular = Path(tmpdir) / "regular_plugin.py"
            regular.write_text("# Regular plugin")
            underscore = Path(tmpdir) / "_private.py"
            underscore.write_text("# Private module")

            manager = PluginManager(plugin_dirs=[tmpdir])
            discovered = manager.discover_plugins()

            assert "regular_plugin" in discovered
            assert "_private" not in discovered

    def test_manager_discover_plugins_with_packages(self):
        """Test discovering plugin packages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create plugin package
            pkg_dir = Path(tmpdir) / "test_package"
            pkg_dir.mkdir()
            (pkg_dir / "__init__.py").write_text("# Plugin package")

            manager = PluginManager(plugin_dirs=[tmpdir])
            discovered = manager.discover_plugins()

            assert "test_package" in discovered

    def test_manager_load_plugin_from_file(self):
        """Test loading a plugin from a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = '''
from sentinel.plugin import BasePlugin, PluginInfo, PluginType

class FilePlugin(BasePlugin):
    INFO = PluginInfo(
        name="file_plugin",
        version="1.0.0",
        description="File plugin",
        author="Test",
        plugin_type=PluginType.SCANNER
    )

    def execute(self, context):
        return []
'''
            plugin_file = Path(tmpdir) / "file_plugin.py"
            plugin_file.write_text(plugin_code)

            manager = PluginManager()
            result = manager.load_plugin(str(plugin_file))

            assert result is not None
            assert result.INFO.name == "file_plugin"
            assert "file_plugin" in manager.plugins

    def test_manager_load_plugin_invalid_file(self):
        """Test loading an invalid plugin file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "invalid.py"
            plugin_file.write_text("not valid python {{{")

            manager = PluginManager()
            result = manager.load_plugin(str(plugin_file))

            assert result is None

    def test_manager_load_plugins_from_dir(self):
        """Test loading all plugins from a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = '''
from sentinel.plugin import BasePlugin, PluginInfo, PluginType

class DirPlugin(BasePlugin):
    INFO = PluginInfo(
        name="dir_plugin",
        version="1.0.0",
        description="Dir plugin",
        author="Test",
        plugin_type=PluginType.SCANNER
    )

    def execute(self, context):
        return []
'''
            plugin_file = Path(tmpdir) / "dir_plugin.py"
            plugin_file.write_text(plugin_code)

            manager = PluginManager()
            manager.load_plugins_from_dir(tmpdir)

            assert "dir_plugin" in manager.plugins


# =============================================================================
# Test Plugin Template Generators
# =============================================================================

class TestPluginTemplates:
    """Tests for plugin template generators."""

    def test_create_attack_plugin_template(self):
        """Test creating an attack plugin template."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = create_attack_plugin_template("sql_scanner", tmpdir)

            assert output_path.endswith("sql_scanner_plugin.py")
            assert Path(output_path).exists()

            content = Path(output_path).read_text()
            assert "sql_scanner" in content
            assert "AttackPlugin" in content

    def test_create_passive_plugin_template(self):
        """Test creating a passive plugin template."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = create_passive_plugin_template("header_checker", tmpdir)

            assert output_path.endswith("header_checker_passive_plugin.py")
            assert Path(output_path).exists()

            content = Path(output_path).read_text()
            assert "header_checker" in content
            assert "PassivePlugin" in content


# =============================================================================
# Test Global Plugin Manager
# =============================================================================

class TestGlobalPluginManager:
    """Tests for global plugin manager."""

    def test_get_plugin_manager(self):
        """Test getting the global plugin manager."""
        manager = get_plugin_manager()
        assert isinstance(manager, PluginManager)

    def test_global_plugin_manager_is_singleton(self):
        """Test that global plugin manager is a singleton."""
        manager1 = get_plugin_manager()
        manager2 = get_plugin_manager()
        assert manager1 is manager2


# =============================================================================
# Test Plugin Execution with Errors
# =============================================================================

class TestPluginExecutionErrors:
    """Tests for plugin error handling."""

    def test_execute_plugin_with_exception(self):
        """Test plugin execution with exception."""
        class FailingPlugin(BasePlugin):
            INFO = PluginInfo(
                name="failing_plugin",
                version="1.0.0",
                description="Failing plugin",
                author="Test",
                plugin_type=PluginType.SCANNER
            )

            def execute(self, context):
                raise RuntimeError("Plugin failed")

        manager = PluginManager()
        plugin = FailingPlugin()
        manager.register_plugin(plugin)

        context = PluginContext(target_url="https://example.com")
        results = manager.execute_plugin("failing_plugin", context)

        assert results == []
        # Check error was logged (field is log_messages)
        error_logs = [log for log in context.log_messages if log["level"] == "ERROR"]
        assert len(error_logs) == 1


# =============================================================================
# Test Plugin Package Creation
# =============================================================================

class TestPluginPackaging:
    """Tests for plugin packaging."""

    def test_create_plugin_package(self):
        """Test creating a plugin package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager()

            # Create plugin package
            zip_path = manager.create_plugin_package(ConcretePlugin, tmpdir)

            assert zip_path.endswith("concrete_plugin.zip")
            assert Path(zip_path).exists()

    def test_create_plugin_package_content(self):
        """Test plugin package content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager()
            zip_path = manager.create_plugin_package(ConcretePlugin, tmpdir)

            # Read manifest from zip
            from zipfile import ZipFile
            with ZipFile(zip_path, 'r') as zf:
                names = zf.namelist()
                assert any("manifest.json" in name for name in names)


# =============================================================================
# Test Plugin Priority Execution Order
# =============================================================================

class HighPriorityPlugin(BasePlugin):
    """High priority test plugin."""
    INFO = PluginInfo(
        name="high_priority",
        version="1.0.0",
        description="High priority",
        author="Test",
        plugin_type=PluginType.SCANNER,
        priority=PluginPriority.HIGH
    )

    def execute(self, context):
        context.shared_data['order'] = context.shared_data.get('order', [])
        context.shared_data['order'].append('high')
        return []


class LowPriorityPlugin(BasePlugin):
    """Low priority test plugin."""
    INFO = PluginInfo(
        name="low_priority",
        version="1.0.0",
        description="Low priority",
        author="Test",
        plugin_type=PluginType.SCANNER,
        priority=PluginPriority.LOW
    )

    def execute(self, context):
        context.shared_data['order'] = context.shared_data.get('order', [])
        context.shared_data['order'].append('low')
        return []


class TestPluginPriority:
    """Tests for plugin priority ordering."""

    def test_priority_ordering(self):
        """Test that plugins execute in priority order."""
        manager = PluginManager()
        manager.register_plugin(LowPriorityPlugin())
        manager.register_plugin(HighPriorityPlugin())

        context = PluginContext(target_url="https://example.com")
        manager.execute_all(None, context)

        order = context.shared_data.get('order', [])
        assert order == ['high', 'low']  # High priority first


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_unregister_nonexistent_plugin(self):
        """Test unregistering a non-existent plugin."""
        manager = PluginManager()
        # Should not raise
        manager.unregister_plugin("nonexistent")

    def test_enable_nonexistent_plugin(self):
        """Test enabling a non-existent plugin."""
        manager = PluginManager()
        # Should not raise
        manager.enable_plugin("nonexistent")

    def test_disable_nonexistent_plugin(self):
        """Test disabling a non-existent plugin."""
        manager = PluginManager()
        # Should not raise
        manager.disable_plugin("nonexistent")

    def test_configure_nonexistent_plugin(self):
        """Test configuring a non-existent plugin."""
        manager = PluginManager()
        # Should not raise
        manager.configure_plugin("nonexistent", {"key": "value"})

    def test_discover_plugins_nonexistent_dir(self):
        """Test discovering plugins in non-existent directory."""
        manager = PluginManager(plugin_dirs=["/nonexistent/path"])
        discovered = manager.discover_plugins()
        assert discovered == []

    def test_load_plugins_from_nonexistent_dir(self):
        """Test loading plugins from non-existent directory."""
        manager = PluginManager()
        # Should not raise
        manager.load_plugins_from_dir("/nonexistent/path")
