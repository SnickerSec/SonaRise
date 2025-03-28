from __future__ import annotations
from unittest.mock import patch, Mock

import pytest
from logging import Logger

from src.sonarise.utils.logger import StructuredLogger, logger


def test_structured_logger():
    logger = StructuredLogger()
    assert logger.current_operation == "main"


def test_logger_context():
    logger = StructuredLogger()
    with logger.operation("test"):
        assert logger.current_operation == "test"
    assert logger.current_operation == "main"


def test_operation_id():
    logger = StructuredLogger()
    assert len(logger.operation_id) == 8


def test_nested_operations():
    logger = StructuredLogger()
    with logger.operation("outer"):
        assert logger.current_operation == "outer"
        with logger.operation("inner"):
            assert logger.current_operation == "inner"
        assert logger.current_operation == "outer"
    assert logger.current_operation == "main"
