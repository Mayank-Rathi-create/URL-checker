"""
Caching utility module.
Provides transparent caching using Streamlit's cache_data when running within
a Streamlit server runtime, and falls back to a clean in-memory TTL cache when
executing outside Streamlit (e.g., during automated unit tests or CLI tasks).
"""

from __future__ import annotations

import functools
import time
from typing import Any, Callable


def _is_streamlit_running() -> bool:
    """Checks whether code is executing inside an active Streamlit server runtime."""
    try:
        from streamlit.runtime import exists

        return exists()
    except Exception:
        return False


def ttl_cache(ttl: int = 600, show_spinner: bool = False) -> Callable:
    """
    Decorator for caching function return values with a Time-To-Live (TTL).
    Uses Streamlit's `@st.cache_data` when within an active runtime, or an
    in-memory dictionary cache with TTL expiration when outside Streamlit.
    """
    if _is_streamlit_running():
        import streamlit as st

        return st.cache_data(ttl=ttl, show_spinner=show_spinner)

    def decorator(func: Callable) -> Callable:
        _store: dict[tuple, tuple[float, Any]] = {}

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Create a hashable cache key from positional and sorted keyword arguments
            key = (args, tuple(sorted(kwargs.items())))
            now = time.time()

            if key in _store:
                cached_time, cached_val = _store[key]
                if now - cached_time < ttl:
                    return cached_val

            result = func(*args, **kwargs)
            _store[key] = (now, result)
            return result

        wrapper.clear_cache = lambda: _store.clear()  # type: ignore[attr-defined]
        return wrapper

    return decorator

