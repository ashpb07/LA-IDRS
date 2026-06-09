# p2p/gossip.py
"""
Lightweight peer-to-peer threat intelligence sharing using a gossip protocol.
Broadcasts anonymized attack signatures to known peer nodes.
Disabled by default; enabled via NS_P2P=true in environment.
"""

import asyncio
import json
import logging
import time
from typing import List

from .peer_registry import PeerRegistry
from .signature_sanitizer import sanitize

logger = logging.getLogger("netsentinel.p2p")

GOSSIP_PORT    = 9999
RECV_TIMEOUT   = 5.0
MAX_MSG_BYTES  = 4096


class GossipNode:
    def __init__(self, registry: PeerRegistry, port: int = GOSSIP_PORT):
        self._registry = registry
        self._port     = port
        self._seen: set = set()   # deduplicate received signatures
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------ #
    async def broadcast(self, raw_signature: dict) -> None:
        """Sanitize and send a signature to all known peers."""
        sig = sanitize(raw_signature)
        sig_id = sig.get("sig_id", "")
        if sig_id in self._seen:
            return
        self._seen.add(sig_id)

        payload = json.dumps(sig).encode()
        peers = self._registry.active_peers()
        if not peers:
            return

        logger.info("Broadcasting signature %s to %d peers", sig_id, len(peers))
        tasks = [self._send_to(host, payload) for host in peers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_to(self, host: str, payload: bytes) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, self._port), timeout=3.0)
            writer.write(len(payload).to_bytes(4, "big") + payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug("Failed to send to %s: %s", host, e)

    # ------------------------------------------------------------------ #
    async def listen(self, on_receive) -> None:
        """Start a server that accepts inbound gossip messages."""
        server = await asyncio.start_server(
            lambda r, w: self._handle(r, w, on_receive),
            "0.0.0.0", self._port)
        logger.info("Gossip listener on port %d", self._port)
        async with server:
            await server.serve_forever()

    async def _handle(self, reader, writer, on_receive) -> None:
        try:
            size_bytes = await asyncio.wait_for(reader.read(4), timeout=RECV_TIMEOUT)
            if len(size_bytes) < 4:
                return
            size = int.from_bytes(size_bytes, "big")
            if size > MAX_MSG_BYTES:
                return
            data = await asyncio.wait_for(reader.read(size), timeout=RECV_TIMEOUT)
            sig = json.loads(data.decode())
            sig_id = sig.get("sig_id", "")
            if sig_id and sig_id not in self._seen:
                self._seen.add(sig_id)
                logger.info("Received peer signature: %s", sig_id)
                on_receive(sig)
        except Exception as e:
            logger.debug("Gossip handle error: %s", e)
        finally:
            writer.close()
