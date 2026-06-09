# main.py
"""
NetSentinel LA-IDRS — root entry point.
Run with: sudo python3 main.py
"""

import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(__file__))

from orchestrator.config_loader import load_env_file
load_env_file()

from orchestrator.runner import NetSentinelRunner

if __name__ == "__main__":
    runner = NetSentinelRunner()
    runner.start()
