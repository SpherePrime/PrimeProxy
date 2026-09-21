"""
Layered list files management (ported from ZapretGUI lists/, fully portable).

Maintains other.txt + ipset-all.txt/ipset-ru.txt from base/ (bundled defaults)
and user/ (user-editable) layers, rebuilt atomically.
"""
from .file_manager import ensure_required_files_fast
from .hostlists_manager import ensure_hostlists_exist, rebuild_other_files
from .ipsets_manager import ensure_ipsets_exist

__all__ = [
    "ensure_hostlists_exist",
    "ensure_ipsets_exist",
    "ensure_required_files_fast",
    "rebuild_other_files",
]