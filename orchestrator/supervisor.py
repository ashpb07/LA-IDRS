# orchestrator/supervisor.py
"""
Process supervisor — monitors the packet engine subprocess and
restarts it if it crashes unexpectedly.
"""

import logging
import os
import subprocess
import threading
import time

logger = logging.getLogger("netsentinel.supervisor")

MAX_RESTARTS    = 10
RESTART_DELAY   = 3   # seconds between restart attempts
CRASH_WINDOW    = 60  # if MAX_RESTARTS happen within this window → give up


class ProcessSupervisor:
    def __init__(self, binary: str, args: list | None = None):
        self._binary   = binary
        self._args     = args or []
        self._proc: subprocess.Popen | None = None
        self._running  = False
        self._restarts = 0
        self._first_start = 0.0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._running     = True
        self._first_start = time.time()
        self._thread = threading.Thread(target=self._supervise,
                                         daemon=True, name="supervisor")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _supervise(self) -> None:
        while self._running:
            if not os.path.exists(self._binary):
                logger.error("Binary not found: %s — supervisor idle", self._binary)
                time.sleep(10)
                continue

            logger.info("Supervisor launching: %s %s",
                        self._binary, " ".join(self._args))
            self._proc = subprocess.Popen(
                [self._binary] + self._args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            # Stream output
            threading.Thread(target=self._stream_output,
                              args=(self._proc,), daemon=True).start()

            self._proc.wait()
            if not self._running:
                break

            exit_code = self._proc.returncode
            logger.warning("Process exited with code %d", exit_code)

            # Check restart budget
            if time.time() - self._first_start < CRASH_WINDOW:
                self._restarts += 1
            else:
                self._restarts = 1
                self._first_start = time.time()

            if self._restarts >= MAX_RESTARTS:
                logger.error("Max restarts (%d) reached within %ds — giving up",
                             MAX_RESTARTS, CRASH_WINDOW)
                self._running = False
                break

            logger.info("Restarting in %ds (attempt %d/%d) …",
                        RESTART_DELAY, self._restarts, MAX_RESTARTS)
            time.sleep(RESTART_DELAY)

    def _stream_output(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            logger.debug("[packet_engine] %s", line.decode().rstrip())
