"""SonaRise - Automated SonarQube upgrade tool with safety features."""

from sonarise.upgrade import upgrade_sonarqube
from sonarise.version_check import get_latest_version, get_current_version
from sonarise.config import load_config
from sonarise.cli import main

__version__ = "0.1.0"
__all__ = [
    "upgrade_sonarqube",
    "get_latest_version",
    "get_current_version",
    "load_config",
    "main",
]
