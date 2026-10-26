"""Access to the sample log source (data/sample_logs/sample_logs.json)."""
import json
import os
from typing import Any, Dict, List

LOG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "sample_logs", "sample_logs.json")
)


# Repository-relative path, shown to analysts so they know where investigation logs come from
LOG_SOURCE_PATH = "data/sample_logs/sample_logs.json"


def load_sample_logs(path: str = LOG_PATH) -> List[Dict[str, Any]]:
    """Returns the sample log records, or an empty list if the file is missing or invalid."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []
