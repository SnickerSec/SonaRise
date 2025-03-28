from __future__ import annotations
import os
from pathlib import Path

import pytest

from src.sonarise.config import (
    FileConfig,
    PermissionError,
    SonarConfig,
    ValidationError,
    load_config,
)


def test_sonar_config_validation():
    # Valid config
    config = SonarConfig(base_url="http://test", token="token123")
    assert config.base_url == "http://test"
    assert config.token == "token123"

    # Invalid configs
    with pytest.raises(ValidationError):
        SonarConfig(base_url="", token="token123")
    with pytest.raises(ValidationError):
        SonarConfig(base_url="http://test", token="")


def test_file_config_paths():
    config = FileConfig()
    assert isinstance(config.install_dir, Path)
    assert isinstance(config.backup_dir, Path)
    assert isinstance(config.temp_dir, Path)
    assert isinstance(config.lock_dir, Path)
    assert isinstance(config.log_dir, Path)


@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "http://test")
    monkeypatch.setenv("SONARQUBE_TOKEN", "token123")


def test_load_config(mock_env, tmp_path):
    sonar_config, _ = load_config()
    assert sonar_config.base_url == "http://test"
    assert sonar_config.token == "token123"
