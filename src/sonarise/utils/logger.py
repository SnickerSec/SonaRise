from __future__ import annotations
import logging
import logging.handlers
import uuid
from contextlib import contextmanager


class StructuredLogger:
    def __init__(self):
        self.operation_id = str(uuid.uuid4())[:8]
        self.current_operation = "main"

    @contextmanager
    def operation(self, name):
        previous = self.current_operation
        self.current_operation = name
        try:
            yield
        finally:
            self.current_operation = previous

    def _log(self, level, message, **kwargs):
        formatted_message = f"[{level.upper()}] - [{self.current_operation}] {message}"
        extra_str = " ".join(f"{k}={v}" for k, v in kwargs.items() if k != "operation")
        getattr(logger, level)(formatted_message)
        if extra_str:
            logger.debug(f"Additional context: {extra_str}")

    def info(self, message, **kwargs):
        self._log("info", message, **kwargs)

    def error(self, message, **kwargs):
        self._log("error", message, **kwargs)

    def warning(self, message, **kwargs):
        self._log("warning", message, **kwargs)

    def debug(self, message, **kwargs):
        self._log("debug", message, **kwargs)


# Configure base logger
logger = logging.getLogger("sonarqube_upgrade")
logger.setLevel(logging.INFO)
logger.propagate = False

# Create logger instance
structured_logger = StructuredLogger()
