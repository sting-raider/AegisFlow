"""Prepare Npcap before NFStream's spawned Windows workers import _lib_engine."""

from __future__ import annotations

import os
from typing import Any

_NPCAP_DLL_HANDLE: Any | None = None
_NPCAP_DIR = r"C:\Windows\System32\Npcap"

if os.name == "nt" and os.path.isdir(_NPCAP_DIR):
    # Retain the handle for the interpreter lifetime. Closing it removes the DLL
    # directory again before NFStream has loaded its native extension.
    _NPCAP_DLL_HANDLE = os.add_dll_directory(_NPCAP_DIR)
