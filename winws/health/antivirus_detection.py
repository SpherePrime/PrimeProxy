from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._log import log

_ANTIVIRUS_PRODUCT_MARKERS: Dict[str, Tuple[str, str]] = {
    "kaspersky": ("Kaspersky", "kaspersky"),
    "avast antivirus": ("Avast", "avast"),
    "avg antivirus": ("AVG", "avg"),
    "avira": ("Avira", "avira"),
    "malwarebytes": ("Malwarebytes", "malwarebytes"),
    "eset": ("ESET", "eset"),
    "bitdefender": ("Bitdefender", "bitdefender"),
    "norton": ("Norton", "norton"),
    "mcafee": ("McAfee", "mcafee"),
    "360": ("360 Total Security", "360"),
}

_ANTIVIRUS_PROCESS_MARKERS: Dict[str, Tuple[str, str]] = {
    "avp.exe": ("Kaspersky", "Kaspersky"),
    "isavp.exe": ("Kaspersky", "Kaspersky"),
    "avpui.exe": ("Kaspersky", "Kaspersky"),
    "kavsvc.exe": ("Kaspersky", "Kaspersky"),
    "avgnt.exe": ("Avira", "Avira"),
    "avfwsvc.exe": ("Avast", "Avast"),
    "avgui.exe": ("AVG", "AVG"),
    "mbam.exe": ("Malwarebytes", "Malwarebytes"),
    "mbamservice.exe": ("Malwarebytes", "Malwarebytes"),
    "egui.exe": ("ESET", "ESET"),
    "ekrn.exe": ("ESET", "ESET"),
    "bdagent.exe": ("Bitdefender", "Bitdefender"),
    "ns.exe": ("Norton", "Norton"),
    "mcshield.exe": ("McAfee", "McAfee"),
    "360tray.exe": ("360", "360TotalSecurity"),
}


def _find_known_antivirus_name(product_name: str) -> Optional[str]:
    lowered = str(product_name).lower()
    for marker, (name, key) in _ANTIVIRUS_PRODUCT_MARKERS.items():
        if marker in lowered:
            return name
    return None


def _detect_active_antivirus() -> Optional[str]:
    try:
        from utils.windows_process_probe import _iter_process_name_records_winapi
        for record in _iter_process_name_records_winapi():
            name = str(record.get("name", "")).lower()
            if name in _ANTIVIRUS_PROCESS_MARKERS:
                return _ANTIVIRUS_PROCESS_MARKERS[name][0]
    except Exception:
        pass
    try:
        import subprocess
        ps = (
            "Get-CimInstance -Namespace root/SecurityCenter2 "
            "-ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=8,
        ).stdout
        for line in out.splitlines():
            name = line.strip()
            if name:
                found = _find_known_antivirus_name(name)
                if found:
                    return found
    except Exception:
        pass
    return None


def _is_windows_defender_active() -> bool:
    name = _detect_active_antivirus()
    if name and name != "Microsoft Defender":
        return False
    try:
        from utils.service_manager import get_service_state
        state = get_service_state("WinDefend")
        return state == 4
    except Exception:
        return False


def _warn_about_antivirus() -> None:
    try:
        enabled = _detect_active_antivirus()
        if not enabled:
            return
        log.warn(f"Обнаружен активный антивирус, могущий блокировать WinDivert: {enabled}")
    except Exception:
        pass