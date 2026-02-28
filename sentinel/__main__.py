"""
Entry point for running Sentinel as a module.

Usage: python -m sentinel [COMMAND] [OPTIONS]

Examples:
    python -m sentinel scan --swagger api.yaml --target http://localhost:8000
    python -m sentinel inspect api.yaml
    python -m sentinel list-attacks
"""

from .main import main

if __name__ == '__main__':
    main()
