"""
Legacy auth router re-export.

The active router lives in ``backend.api.auth`` and is mounted by ``backend.main``.
"""

from backend.api.auth import router

__all__ = ["router"]
