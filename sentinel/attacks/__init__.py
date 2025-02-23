"""
Attack modules for Sentinel security testing.

This package contains modules for different attack types:
- injection: SQL and NoSQL injection attacks
- auth: Authentication bypass attacks
- idor: Insecure Direct Object Reference attacks
"""

from .injection import SQLInjectionAttacker
from .auth import AuthBypassAttacker
from .idor import IDORAttacker

__all__ = [
    'SQLInjectionAttacker',
    'AuthBypassAttacker', 
    'IDORAttacker'
]
