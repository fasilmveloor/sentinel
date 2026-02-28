"""
Attack modules for Sentinel security testing.

This package contains modules for different attack types:
- injection: SQL and NoSQL injection attacks
- auth: Authentication bypass attacks
- idor: Insecure Direct Object Reference attacks
- xss: Cross-Site Scripting attacks (v2.0)
- ssrf: Server-Side Request Forgery attacks (v2.0)
- jwt: JWT vulnerability testing (v2.0)
- cmd_injection: OS Command Injection (v2.0)
- rate_limit: Rate Limit Detection (v2.0)
"""

from .injection import SQLInjectionAttacker
from .auth import AuthBypassAttacker
from .idor import IDORAttacker
from .xss import XSSAttacker
from .ssrf import SSRFAttacker
from .jwt import JWTAttacker
from .cmd_injection import CommandInjectionAttacker
from .rate_limit import RateLimitAttacker

__all__ = [
    'SQLInjectionAttacker',
    'AuthBypassAttacker', 
    'IDORAttacker',
    'XSSAttacker',
    'SSRFAttacker',
    'JWTAttacker',
    'CommandInjectionAttacker',
    'RateLimitAttacker'
]
