"""Serialize CLI mutations across API workers and the recovery watchdog."""
import fcntl
import os
import time
from contextlib import contextmanager

from .constants import CONFIG_DIR


@contextmanager
def mutation_lock(timeout=120):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(os.path.join(CONFIG_DIR, "mutation.lock"), "a") as lock:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Another VPN operation is still running; retry later")
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
