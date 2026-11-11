# src/spyscan/enrich/peinfo.py
"""The name a Windows program carries inside its own file.

A copy of cmd.exe saved as updater.exe still verifies as Microsoft-signed, and
its file name no longer says what it is. The PE version resource keeps the
name it was built under (OriginalFilename), and it is covered by the
signature, so a renamed copy cannot change it without losing the signature.
"""
from __future__ import annotations

import pefile

_RESOURCE_DIR = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]


def original_filename(path: str) -> str:    # impure edge
    """The OriginalFilename in ``path``'s PE version resource, or '' when the
    file is missing, unreadable, not a PE, or has none. Reads the headers and
    the resource directory only. Never raises."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return ""
    try:
        pe.parse_data_directories(directories=[_RESOURCE_DIR])
        for info in getattr(pe, "FileInfo", None) or []:
            for entry in info:
                for table in getattr(entry, "StringTable", None) or []:
                    name = table.entries.get(b"OriginalFilename")
                    if name:
                        return name.decode("utf-8", errors="replace").strip()[:260]
    except Exception:
        return ""
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return ""
