from __future__ import annotations
from dataclasses import dataclass, field
import logging
import os
import re
import time
from functools import wraps
from typing import Any, Callable, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sonarise.config import SonarConfig, load_config
from sonarise.utils.logger import logger

# Constants
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_TTL = 3600
SONARQUBE_BASE_URL = os.getenv("SONARQUBE_URL", "https://sonarqube.local")
DOWNLOAD_BASE_URL = "https://www.sonarsource.com/products/sonarqube/downloads/"


class SecurityError(Exception):
    """Raised for security-related issues"""


class VersionCheckError(Exception):
    """Base exception for version checking errors"""


class ConnectionError(VersionCheckError):
    """Network connection issues"""


class VersionParseError(VersionCheckError):
    """Version parsing failures"""


@dataclass(frozen=True)
class VersionCheckResult:
    version: Optional[str] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def is_success(self) -> bool:
        return self.version is not None and self.error is None

    @property
    def is_fresh(self, max_age: int = DEFAULT_CACHE_TTL) -> bool:
        """Fix is_fresh property to not use self parameter for max_age"""
        return time.time() - self.timestamp < max_age


def create_secure_session(
    retries: int = 3,
    backoff: float = 0.3,
    status_forcelist: list[int] = [500, 502, 503, 504],
    verify_ssl: bool = True,
) -> requests.Session:
    """Create a secure session with retry handling"""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    return session


def ttl_cache(ttl: int = DEFAULT_CACHE_TTL) -> Callable:
    """Thread-safe TTL cache decorator"""

    def decorator(func: Callable) -> Callable:
        cache: dict[str, tuple[Any, float]] = {}

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = str(args) + str(kwargs)
            now = time.time()

            # Clean expired entries
            expired = [k for k, v in cache.items() if now - v[1] > ttl]
            for k in expired:
                del cache[k]

            if key in cache and now - cache[key][1] < ttl:
                return cache[key][0]

            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result

        return wrapper

    return decorator


class SonarQubeVersionChecker:
    """Add type hints and improve error handling"""

    def __init__(self, config: SonarConfig) -> None:
        if not isinstance(config, SonarConfig):
            raise TypeError("config must be an instance of SonarConfig")
        self.config = config
        self.session = create_secure_session(verify_ssl=config.verify_ssl)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def check_deployed_version(self) -> VersionCheckResult:
        try:
            if not self.validate_connection():
                return VersionCheckResult(error="Failed to validate connection")

            version_url = f"{self.config.base_url}/api/server/version"
            response = self.session.get(
                version_url,
                headers={"Authorization": f"Bearer {self.config.token}"},
                timeout=self.config.timeout,
                verify=(
                    self.config.cert_path
                    if self.config.cert_path
                    else self.config.verify_ssl
                ),
            )
            response.raise_for_status()

            version = response.text.strip()
            if not version:
                return VersionCheckResult(error="Empty version received")

            return VersionCheckResult(version=version)

        except Exception as e:
            return VersionCheckResult(error=str(e))

    def validate_connection(self) -> bool:
        try:
            status_url = f"{self.config.base_url}/api/system/status"
            response = self.session.get(
                status_url,
                headers={"Authorization": f"Bearer {self.config.token}"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
            response.raise_for_status()

            status_data = response.json()
            return status_data.get("status") in ["UP", "STARTING"]

        except Exception:
            return False


def sonarqube_get_deployed() -> Optional[str]:
    """Get the deployed version with config integration."""
    config = load_config()[0]  # Only get SonarConfig
    if not config.token:
        logger.error("SONARQUBE_TOKEN not set")
        return None

    with SonarQubeVersionChecker(config) as checker:
        result = checker.check_deployed_version()
        if result.is_success:
            return result.version
        logger.error(f"Version check failed: {result.error}")
        return None


@ttl_cache()
def sonarqube_get_latest() -> VersionCheckResult:
    """Get latest SonarQube version with improved security"""
    session = create_secure_session()
    try:
        url = urljoin(DOWNLOAD_BASE_URL, "success-download-developer-edition/")
        response = session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        anchor = soup.select_one(
            "#gatsby-focus-wrapper > main > div > section:nth-of-type(1) > div > div > div > a"
        )

        if not anchor:
            raise VersionParseError("Version information not found")

        match = re.search(
            r"sonarqube-developer-(\d+\.\d+\.\d+\.\d+)\.zip", anchor["href"]
        )
        if not match:
            raise VersionParseError("Invalid version format")

        return VersionCheckResult(version=match.group(1))

    except requests.RequestException as e:
        return VersionCheckResult(error=f"Network error: {str(e)}")
    except VersionParseError as e:
        return VersionCheckResult(error=str(e))
    except Exception as e:
        return VersionCheckResult(error=f"Unexpected error: {str(e)}")
    finally:
        session.close()


def main():
    """Main function for testing version checks."""
    config = load_config()[0]  # Only get SonarConfig
    with SonarQubeVersionChecker(config) as checker:
        deployed_version_result = checker.check_deployed_version()
        if deployed_version_result.is_success:
            logging.info(
                f"Deployed SonarQube version: {deployed_version_result.version}"
            )
        else:
            logging.error(
                f"Error getting deployed SonarQube version: {deployed_version_result.error}"
            )

    latest_version_result = sonarqube_get_latest()
    if latest_version_result.is_success:
        logging.info(f"Latest SonarQube version: {latest_version_result.version}")
    else:
        logging.error(
            f"Error getting latest SonarQube version: {latest_version_result.error}"
        )


if __name__ == "__main__":
    main()
