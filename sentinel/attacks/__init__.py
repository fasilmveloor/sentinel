"""
Attack modules for Sentinel security testing.

This package contains modules for different attack types:
- injection: SQL injection attacks
- auth: Authentication bypass attacks
- idor: Insecure Direct Object Reference attacks
- xss: Cross-Site Scripting attacks
- ssrf: Server-Side Request Forgery attacks
- jwt: JWT vulnerability testing
- cmd_injection: OS Command Injection
- rate_limit: Rate Limit Detection

v1.0.0 Enhanced Modules:
- bola: Broken Object Level Authorization (advanced IDOR)
- excessive_data: Excessive Data Exposure detection
- mass_assignment: Mass Assignment vulnerability detection
- bfla: Broken Function Level Authorization detection
- nosql_injection: NoSQL injection attacks
- broken_auth: Broken Authentication testing
"""

from .auth import AuthBypassAttacker
from .bfla import BFLAAttacker, UserRole

# v1.0.0 Enhanced Modules
from .bola import BOLAAttacker, UserCredentials
from .broken_auth import AuthContext, BrokenAuthAttacker
from .cmd_injection import CommandInjectionAttacker
from .excessive_data import ExcessiveDataExposureAttacker
from .idor import IDORAttacker
from .injection import SQLInjectionAttacker
from .jwt import JWTAttacker
from .mass_assignment import MassAssignmentAttacker
from .nosql_injection import NoSQLInjectionAttacker
from .rate_limit import RateLimitAttacker
from .ssrf import SSRFAttacker
from .xss import XSSAttacker

__all__ = [
    # Core Attack Modules
    'SQLInjectionAttacker',
    'AuthBypassAttacker',
    'IDORAttacker',
    'XSSAttacker',
    'SSRFAttacker',
    'JWTAttacker',
    'CommandInjectionAttacker',
    'RateLimitAttacker',

    # v1.0.0 Enhanced Modules
    'BOLAAttacker',
    'UserCredentials',
    'ExcessiveDataExposureAttacker',
    'MassAssignmentAttacker',
    'BFLAAttacker',
    'UserRole',
    'NoSQLInjectionAttacker',
    'BrokenAuthAttacker',
    'AuthContext',
]
