# comms/socket_server.py
"""
UNIX domain socket server that receives packet_meta_t structs from the
C packet engine and forwards them to the detection engine.
This module is used as a standalone bridge when the detector is run
in a separate process from the orchestrator.
"""

import logging
import os
import socket
import struct
import threading
from typing import Callable

logger = logging.getLogger("netsentinel.comms")

SOCKET_PATH  = "/tmp/netsentinel.sock"

# Must match packet_meta_t in emitter.h
# src_ip[16], dst_ip[16], src_port(H), dst_port(H), protocol(B),
# tcp_flags(B), payload_len(H), ts_sec(I), ts_usec(I)
PACKET_FMT  = "16s16sHHBBHII"
PACKET_SIZE = struct.calcsize(PACKET_FMT)


def parse_packet_struct(raw: bytes) -> dict | None:
    """Unpack a raw packet_meta_t into a Python dict."""
    if len(raw) < PACKET_SIZE:
        return None
    try:
        fields = struct.unpack(PACKET_FMT, raw[:PACKET_SIZE])
    except struct.error:
        return None
    return {
        "src_ip":      fields[0].rstrip(b"\x00").decode(errors="replace"),
        "dst_ip":      fields[1].rstrip(b"\x00").decode(errors="replace"),
        "src_port":    fields[2],
        "dst_port":    fields[3],
        "protocol":    fields[4],
        "tcp_flags":   fields[5],
        "payload_len": fields[6],
        "ts_sec":      fields[7],
        "ts_usec":     fields[8],
    }


class PacketSocketServer:
    """
    Listens on a UNIX domain socket for binary packet structs from the
    C packet engine. Calls `on_packet` for each parsed packet.
    """

    def __init__(self, on_packet: Callable[[dict], None],
                 socket_path: str = SOCKET_PATH):
        self._on_packet   = on_packet
        self._socket_path = socket_path
        self._running     = False
        self._server: socket.socket | None = None

    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._serve, daemon=True,
                             name="packet-socket-server")
        t.start()
        logger.info("PacketSocketServer listening on %s", self._socket_path)

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

    def _serve(self) -> None:
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self._socket_path)
        self._server.listen(4)
        self._server.settimeout(1.0)

        while self._running:
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle,
                             args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while self._running:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= PACKET_SIZE:
                    raw, buf = buf[:PACKET_SIZE], buf[PACKET_SIZE:]
                    pkt = parse_packet_struct(raw)
                    if pkt and pkt["src_ip"]:
                        try:
                            self._on_packet(pkt)
                        except Exception as e:
                            logger.error("on_packet callback error: %s", e)
        except Exception as e:
            logger.debug("Socket handle error: %s", e)
        finally:
            conn.close()