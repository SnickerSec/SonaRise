from __future__ import annotations
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.sonarise.config import FileConfig
from src.sonarise.upgrade import (
    UpgradeError,
    ensure_secure_directory,
    is_version_upgrade_compatible,
    validate_backup,
    validate_version_string,
)
from src.sonarise.utils.logger import logger


def test_validate_version_string():
    assert validate_version_string("9.9.1.1234") == "9.9.1.1234"
    with pytest.raises(ValueError):
        validate_version_string("invalid")


def test_version_compatibility():
    assert is_version_upgrade_compatible("9.8.0.1234", "9.9.0.1234") is True
    with pytest.raises(UpgradeError):
        is_version_upgrade_compatible("9.9.0.1234", "9.8.0.1234")


def test_validate_backup(tmp_path):
    test_file = tmp_path / "backup.gz"
    test_file.write_bytes(b"x" * 2048)  # 2KB file
    assert validate_backup(str(test_file)) is True

    empty_file = tmp_path / "empty.gz"
    empty_file.touch()
    with pytest.raises(UpgradeError):
        validate_backup(str(empty_file))


def test_ensure_secure_directory(tmp_path):
    test_dir = tmp_path / "secure"
    result = ensure_secure_directory(str(test_dir))
    assert os.path.exists(result)
    assert os.stat(result).st_mode & 0o777 == 0o700
