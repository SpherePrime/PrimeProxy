"""
SwiftProxy UI layer — pywebview frontend.

Contains the Python ↔ JavaScript API bridge (api.py), the window/tray
lifecycle (window.py) and the static HTML/CSS/JS assets under pages/,
theme/ and js/.
"""
from .api import SwiftAPI

__all__ = ["SwiftAPI"]