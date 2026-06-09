# response_engine/core/scheduler.py
"""
Scheduler: manages timed tasks for the response engine,
such as periodic unbanning and cache eviction.
"""

import logging
import threading
import time
from typing import Callable, List

logger = logging.getLogger("netsentinel.response.scheduler")


class PeriodicTask:
    def __init__(self, name: str, interval_sec: float,
                 fn: Callable, *args, **kwargs):
        self.name         = name
        self.interval_sec = interval_sec
        self.fn           = fn
        self.args         = args
        self.kwargs       = kwargs
        self._last_run    = 0.0

    def due(self) -> bool:
        return time.time() - self._last_run >= self.interval_sec

    def run(self) -> None:
        try:
            self.fn(*self.args, **self.kwargs)
        except Exception as e:
            logger.error("Task %s failed: %s", self.name, e)
        self._last_run = time.time()


class TaskScheduler:
    def __init__(self, tick_sec: float = 5.0):
        self._tick    = tick_sec
        self._tasks: List[PeriodicTask] = []
        self._running = False
        self._thread: threading.Thread | None = None

    def register(self, name: str, interval_sec: float,
                 fn: Callable, *args, **kwargs) -> None:
        task = PeriodicTask(name, interval_sec, fn, *args, **kwargs)
        self._tasks.append(task)
        logger.debug("Registered task: %s (every %ds)", name, interval_sec)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop,
                                         daemon=True, name="task-scheduler")
        self._thread.start()
        logger.info("Task scheduler started (%d tasks)", len(self._tasks))

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            for task in self._tasks:
                if task.due():
                    task.run()
            time.sleep(self._tick)
