# detection_engine/utils/logger.py
"""
Centralized logging configuration for NetSentinel.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from .. import config


def setup_logging(level: str = "INFO") -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger("netsentinel")
    root.setLevel(numeric)
    root.propagate = False

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(numeric)
    ch.setFormatter(_fmt())
    root.addHandler(ch)

    # Rotating file handler
    os.makedirs(config.LOG_DIR, exist_ok=True)
    log_path = os.path.join(config.LOG_DIR, "netsentinel.log")
    fh = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
    fh.setLevel(numeric)
    fh.setFormatter(_fmt())
    root.addHandler(fh)


def _fmt() -> logging.Formatter:
    return logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )