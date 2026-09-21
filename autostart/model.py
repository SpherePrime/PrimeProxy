from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class StartEntry:
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    working_dir: str = ""
    run_level: str = "highest"
    display_name: str = ""
    description: str = ""