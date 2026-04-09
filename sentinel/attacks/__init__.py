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

from .injection import SQLInjectionAttacker
from .auth import AuthBypassAttacker
from .idor import IDORAttacker
from .xss import XSSAttacker
from .ssrf import SSRFAttacker
from .jwt import JWTAttacker
from .cmd_injection import CommandInjectionAttacker
from .rate_limit import RateLimitAttacker

# v1.0.0 Enhanced Modules
from .bola import BOLAAttacker, UserCredentials
from .excessive_data import ExcessiveDataExposureAttacker
from .mass_assignment import MassAssignmentAttacker
from .bfla import BFLAAttacker, UserRole
from .nosql_injection import NoSQLInjectionAttacker
from .broken_auth import BrokenAuthAttacker, AuthContext

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
