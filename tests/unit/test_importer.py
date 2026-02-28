"""
Unit tests for Sentinel Benchmark Importer.

Tests cover:
- OWASP Benchmark CSV import
- Juice Shop YAML import
- VAmPI, DVWA, WebGoat vulnerabilities
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from sentinel.benchmarks.importer import (
    OWASPBenchmarkImporter,
    JuiceShopImporter,
    VAmPIImporter,
    DVWAImporter,
    WebGoatImporter,
    CrAPIImporter,
    BenchmarkDataAggregator,
    get_real_benchmark_stats,
    RealBenchmarkCategory,
)
from sentinel.benchmarks.framework import BenchmarkCategory
from sentinel.models import Severity


# ==================== OWASPBenchmarkImporter Tests ====================

class TestOWASPBenchmarkImporter:
    """Tests for OWASP Benchmark CSV importer."""
    
    def test_create_importer(self):
        """Test creating OWASP Benchmark importer."""
        importer = OWASPBenchmarkImporter()
        assert importer is not None
    
    def test_importer_has_load_method(self):
        """Test that importer has load method."""
        importer = OWASPBenchmarkImporter()
        assert hasattr(importer, 'load')
    
    def test_importer_has_get_statistics(self):
        """Test that importer has get_statistics method."""
        importer = OWASPBenchmarkImporter()
        assert hasattr(importer, 'get_statistics')
    
    def test_importer_has_category_map(self):
        """Test that importer has category mapping."""
        importer = OWASPBenchmarkImporter()
        assert hasattr(importer, 'CATEGORY_MAP')
        assert 'sqli' in importer.CATEGORY_MAP
    
    def test_importer_has_cwe_severity_map(self):
        """Test that importer has CWE severity mapping."""
        importer = OWASPBenchmarkImporter()
        assert hasattr(importer, 'CWE_SEVERITY')
    
    def test_load_returns_list(self):
        """Test that load returns list."""
        importer = OWASPBenchmarkImporter(use_cache=False)
        result = importer.load()
        
        assert isinstance(result, list)
    
    def test_get_statistics_returns_dict(self):
        """Test that get_statistics returns dict."""
        importer = OWASPBenchmarkImporter()
        stats = importer.get_statistics()
        
        assert isinstance(stats, dict)


# ==================== JuiceShopImporter Tests ====================

class TestJuiceShopImporter:
    """Tests for Juice Shop YAML importer."""
    
    def test_create_importer(self):
        """Test creating Juice Shop importer."""
        importer = JuiceShopImporter()
        assert importer is not None
    
    def test_importer_has_load_method(self):
        """Test that importer has load method."""
        importer = JuiceShopImporter()
        assert hasattr(importer, 'load')
    
    def test_importer_has_get_statistics(self):
        """Test that importer has get_statistics method."""
        importer = JuiceShopImporter()
        assert hasattr(importer, 'get_statistics')
    
    def test_importer_has_category_map(self):
        """Test that importer has category mapping."""
        importer = JuiceShopImporter()
        assert hasattr(importer, 'CATEGORY_MAP')
    
    def test_importer_has_difficulty_severity_map(self):
        """Test that importer has difficulty severity mapping."""
        importer = JuiceShopImporter()
        assert hasattr(importer, 'DIFFICULTY_SEVERITY')
    
    def test_load_returns_list(self):
        """Test that load returns list."""
        importer = JuiceShopImporter(use_cache=False)
        result = importer.load()
        
        assert isinstance(result, list)


# ==================== VAmPIImporter Tests ====================

class TestVAmPIImporter:
    """Tests for VAmPI vulnerability importer."""
    
    def test_create_importer(self):
        """Test creating VAmPI importer."""
        importer = VAmPIImporter()
        assert importer is not None
    
    def test_has_vulnerabilities(self):
        """Test that importer has vulnerabilities defined."""
        importer = VAmPIImporter()
        assert hasattr(importer, 'VULNERABILITIES')
    
    def test_load_vulnerabilities(self):
        """Test loading vulnerabilities."""
        importer = VAmPIImporter()
        result = importer.load_vulnerabilities()
        
        assert isinstance(result, list)


# ==================== DVWAImporter Tests ====================

class TestDVWAImporter:
    """Tests for DVWA vulnerability importer."""
    
    def test_create_importer(self):
        """Test creating DVWA importer."""
        importer = DVWAImporter()
        assert importer is not None
    
    def test_has_vulnerabilities(self):
        """Test that importer has vulnerabilities defined."""
        importer = DVWAImporter()
        assert hasattr(importer, 'VULNERABILITIES')


# ==================== WebGoatImporter Tests ====================

class TestWebGoatImporter:
    """Tests for WebGoat lesson importer."""
    
    def test_create_importer(self):
        """Test creating WebGoat importer."""
        importer = WebGoatImporter()
        assert importer is not None
    
    def test_importer_exists(self):
        """Test that importer exists."""
        importer = WebGoatImporter()
        assert importer is not None


# ==================== CrAPIImporter Tests ====================

class TestCrAPIImporter:
    """Tests for crAPI vulnerability importer."""
    
    def test_create_importer(self):
        """Test creating crAPI importer."""
        importer = CrAPIImporter()
        assert importer is not None
    
    def test_has_vulnerabilities(self):
        """Test that importer has vulnerabilities defined."""
        importer = CrAPIImporter()
        assert hasattr(importer, 'VULNERABILITIES')
    
    def test_load_vulnerabilities(self):
        """Test loading vulnerabilities."""
        importer = CrAPIImporter()
        result = importer.load_vulnerabilities()
        
        assert isinstance(result, list)


# ==================== BenchmarkDataAggregator Tests ====================

class TestBenchmarkDataAggregator:
    """Tests for benchmark data aggregator."""
    
    def test_create_aggregator(self):
        """Test creating aggregator."""
        aggregator = BenchmarkDataAggregator()
        assert aggregator is not None


# ==================== Convenience Function Tests ====================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_get_real_benchmark_stats(self):
        """Test get_real_benchmark_stats function."""
        stats = get_real_benchmark_stats()
        
        assert isinstance(stats, dict)


# ==================== Data Class Tests ====================

class TestDataClasses:
    """Tests for data classes."""
    
    def test_real_benchmark_category_enum(self):
        """Test RealBenchmarkCategory enum."""
        assert RealBenchmarkCategory.SQLI.value == "sqli"
        assert RealBenchmarkCategory.XSS.value == "xss"


# ==================== Edge Cases ====================

class TestImporterEdgeCases:
    """Tests for edge cases in importers."""
    
    def test_owasp_importer_with_use_cache_false(self):
        """Test OWASP importer with caching disabled."""
        importer = OWASPBenchmarkImporter(use_cache=False)
        
        assert importer.use_cache is False
    
    def test_juice_shop_importer_with_use_cache_false(self):
        """Test Juice Shop importer with caching disabled."""
        importer = JuiceShopImporter(use_cache=False)
        
        assert importer.use_cache is False
