from .passwords import check_password_strength
from .secrets import scan_file_for_secrets
from .urls import check_url_risk
from .logs import parse_failed_logins

__all__ = [
    "check_password_strength",
    "scan_file_for_secrets",
    "check_url_risk",
    "parse_failed_logins",
]

On Linux/macOS:
Bash
touch checks/__init__.py

On Windows (PowerShell):
PowerShell
New-Item -Path checks/__init__.py -ItemType File
