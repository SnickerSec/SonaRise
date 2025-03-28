from __future__ import annotations
import shutil
import tempfile
from pathlib import Path

import pytest
from requests.models import Response


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_sonarqube_response():
    """Mock response from SonarQube API."""
    return {"version": "9.9.1.1234", "status": "UP", "details": {}}


@pytest.fixture
def mock_file_structure(temp_dir):
    """Create a mock file structure for testing."""
    (temp_dir / "conf").mkdir()
    (temp_dir / "extensions" / "plugins").mkdir(parents=True)
    (temp_dir / "conf" / "sonar.properties").write_text("sonar.test=value")
    return temp_dir
