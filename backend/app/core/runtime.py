"""Process-model checks (C-review item 5).

Several pieces of state live in ONE Python process: the pipeline run lock (orchestrator._RUN_LOCK), the VirusTotal client
(quota counters, result cache and circuit breaker, see services/threat_intel.get_client) and the mock/caches of the rule
agents. With N worker processes each one has its own copy, so the run lock no longer serialises runs across the workers and
the VirusTotal budget becomes up to N times larger than configured. SQLite is shared, but the locks above are not.

The application cannot see every way a server is started (for example `uvicorn --workers 4` on the command line), so this
checks only what it can see: the WEB_CONCURRENCY environment variable, which uvicorn reads as its default worker count.
The Dockerfile starts a single worker. See docs/ARCHITECTURE.md for the full list of process-local limits.
"""
import os
from typing import Mapping, Optional


def worker_processes(env: Mapping[str, str] = os.environ) -> int:
    """The worker count the environment asks for (WEB_CONCURRENCY), 1 when unset or unreadable."""
    try:
        return max(1, int(str(env.get("WEB_CONCURRENCY", "1")).strip() or "1"))
    except ValueError:
        return 1


def process_model_note(workers: int, live_provider: bool) -> Optional[str]:
    """A warning for a server that runs more than one worker process, or None when one process is configured."""
    if workers <= 1:
        return None
    note = (f"WEB_CONCURRENCY={workers}: the server runs {workers} worker processes. The pipeline run lock, the VirusTotal quota, "
            "cache and circuit breaker are per process, so they are not shared between workers.")
    if live_provider:
        note += " Live VirusTotal lookups can use up to %d times the configured request budget." % workers
    return note + " Run one worker process unless you accept these limits."
