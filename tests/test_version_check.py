from __future__ import annotations
import pytest
from unittest.mock import Mock, patch

from src.sonarise.config import SonarConfig
from src.sonarise.version_check import (
    VersionCheckResult,
    VersionCheckError,
    VersionParseError,
    create_secure_session,
    SonarQubeVersionChecker,
)


def test_version_check_result():
    result = VersionCheckResult(version="1.0.0")
    assert result.is_success
    assert result.version == "1.0.0"
    assert result.error is None


def test_create_secure_session():
    session = create_secure_session()
    assert session.verify is True
