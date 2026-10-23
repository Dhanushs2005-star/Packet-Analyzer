"""
Processing engines for the DPI system:
- single_threaded: Reference implementation matching main_working.cpp
- multi_threaded: Concurrent pipeline matching dpi_mt.cpp / dpi_engine.cpp
"""

from .single_threaded import SingleThreadedEngine
from .multi_threaded import MultiThreadedEngine

__all__ = ["SingleThreadedEngine", "MultiThreadedEngine"]
