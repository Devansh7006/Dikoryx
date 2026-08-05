"""In-memory runtime state for active agent telemetry."""

from typing import Any, Dict, List

systems: Dict[str, Dict[str, Any]] = {}
events: Dict[str, List[Dict[str, Any]]] = {}
