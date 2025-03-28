from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os


class ConfigError(Exception):
    """Base configuration error"""


class ValidationError(ConfigError):
    """Configuration validation error"""


class PermissionError(ConfigError):
    """Permission-related configuration error"""


@dataclass(frozen=True)
class SonarConfig:
    base_url: str
    token: str
    cert_path: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30

    def __post_init__(self):
        if not self.base_url:
            raise ValidationError("SonarQube URL is required")
        if not self.token:
            raise ValidationError("SonarQube token is required")
        if self.cert_path and not os.path.exists(self.cert_path):
            raise ValidationError(f"Certificate file not found: {self.cert_path}")


@dataclass(frozen=True)
class FileConfig:
    install_dir: Path = field(default_factory=lambda: Path("/opt/sonarqube"))
    backup_dir: Path = field(default_factory=lambda: Path("/var/backup/sonarqube"))
    temp_dir: Path = field(default_factory=lambda: Path("/var/tmp/sonarqube"))
    lock_dir: Path = field(default_factory=lambda: Path("/var/run/sonarqube"))
    log_dir: Path = field(default_factory=lambda: Path("/var/log/sonarqube/upgrade"))

    def validate(self) -> bool:
        for path in [
            self.install_dir,
            self.backup_dir,
            self.temp_dir,
            self.lock_dir,
            self.log_dir,
        ]:
            try:
                path.mkdir(parents=True, exist_ok=True)
                if not os.access(path, os.W_OK):
                    raise PermissionError(f"Directory not writable: {path}")
            except OSError as e:
                raise ValidationError(f"Failed to create/access directory {path}: {e}")
        return True


def load_config() -> tuple[SonarConfig, FileConfig]:
    """Load configuration from environment variables"""
    sonar_config = SonarConfig(
        base_url=os.getenv("SONARQUBE_URL", "https://sonarqube.local"),
        token=os.getenv("SONARQUBE_TOKEN", ""),
        cert_path=os.getenv("SONARQUBE_CERT_PATH"),
        verify_ssl=os.getenv("SONARQUBE_VERIFY_SSL", "true").lower() == "true",
    )

    file_config = FileConfig()
    file_config.validate()

    return sonar_config, file_config
