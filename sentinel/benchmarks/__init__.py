"""
Sentinel Benchmark Framework

Comprehensive benchmarking system for measuring Sentinel's security testing
capabilities against industry-standard vulnerable applications.
"""

from .framework import (
    BenchmarkCategory,
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkTarget,
    GroundTruthDatabase,
    GroundTruthVulnerability,
    run_all_benchmarks,
    run_crapi_benchmark,
    run_dvwa_benchmark,
    run_juice_shop_benchmark,
    run_owasp_benchmark,
    run_webgoat_benchmark,
)

__all__ = [
    # Enums
    'BenchmarkTarget',
    'BenchmarkCategory',

    # Data classes
    'BenchmarkResult',
    'BenchmarkReport',
    'GroundTruthVulnerability',

    # Classes
    'BenchmarkRunner',
    'GroundTruthDatabase',

    # Convenience functions
    'run_crapi_benchmark',
    'run_juice_shop_benchmark',
    'run_owasp_benchmark',
    'run_dvwa_benchmark',
    'run_webgoat_benchmark',
    'run_all_benchmarks',
]
