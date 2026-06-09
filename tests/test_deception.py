# tests/test_deception.py
"""
Unit tests for deception layer — port manager and signal bridge.
Run with: pytest tests/
"""

import pytest
from deception.port_manager import pick_ports, RESERVED_PORTS
from deception.signal import HoneypotSignal


class TestPortManager:
    def test_returns_correct_count(self):
        ports = pick_ports(5, 20000, 60000, set())
        assert len(ports) == 5

    def test_no_reserved_ports(self):
        ports = pick_ports(20, 20000, 60000, set())
        for p in ports:
            assert p not in RESERVED_PORTS

    def test_no_duplicates(self):
        ports = pick_ports(10, 20000, 60000, set())
        assert len(ports) == len(set(ports))

    def test_respects_used_ports(self):
        used  = set(range(20000, 20100))
        ports = pick_ports(5, 20000, 20110, used)
        for p in ports:
            assert p not in used

    def test_returns_fewer_if_range_exhausted(self):
        # Only 5 ports available (20001–20005), none reserved
        ports = pick_ports(10, 20001, 20005, set())
        assert len(ports) <= 5

    def test_within_range(self):
        ports = pick_ports(5, 30000, 35000, set())
        for p in ports:
            assert 30000 <= p <= 35000


class TestHoneypotSignal:
    def test_emit_calls_callback(self):
        received = []
        sig = HoneypotSignal(on_contact=lambda ip, port: received.append((ip, port)))
        sig.emit("10.0.0.1", 31337)
        assert received == [("10.0.0.1", 31337)]

    def test_no_callback_no_error(self):
        sig = HoneypotSignal()
        sig.emit("10.0.0.2", 12345)   # should not raise

    def test_register_replaces_callback(self):
        received = []
        sig = HoneypotSignal(on_contact=lambda ip, port: None)
        sig.register(lambda ip, port: received.append((ip, port)))
        sig.emit("10.0.0.3", 9999)
        assert ("10.0.0.3", 9999) in received

    def test_multiple_emits(self):
        received = []
        sig = HoneypotSignal(on_contact=lambda ip, port: received.append(port))
        for port in [1111, 2222, 3333]:
            sig.emit("10.0.0.4", port)
        assert received == [1111, 2222, 3333]
