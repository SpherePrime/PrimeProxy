"""
Best-effort UPnP / IGD port mapping using only the standard library.

Discovers the router's Internet Gateway Device via SSDP, then adds /
removes port mappings with AddPortMapping / DeletePortMapping SOAP calls.

Everything is best-effort: failures return ``{"ok": False}`` instead of
raising, so the caller (API/CLI) can surface a human-readable hint.
"""
from __future__ import annotations

import logging
import socket
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("swift.upnp")

_IGD_URN = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
_WAN_CONN_TYPES = (
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
_NS = {"upnp": "urn:schemas-upnp-org:device-1-0", "s": "http://schemas.xmlsoap.org/soap/envelope/"}
_TIMEOUT = 4.0


def _msearch() -> List[str]:
    """Discover IGD control URLs via SSDP M-SEARCH. Returns LOCATION URLs."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: 239.255.255.250:1900\r\n"
        f"MAN: \"ssdp:discover\"\r\n"
        f"MX: 2\r\n"
        f"ST: {_IGD_URN}\r\n"
        "\r\n"
    ).encode("utf-8")
    locations: List[str] = []
    for family in (socket.AF_INET,):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(_TIMEOUT)
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except OSError:
                s.close()
                continue
            while True:
                try:
                    data, _ = s.recvfrom(1024)
                except socket.timeout:
                    break
                headers = data.decode("iso-8859-1", "replace").split("\r\n")
                for line in headers:
                    if line.lower().startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        if loc and loc not in locations:
                            locations.append(loc)
            s.close()
        except OSError as exc:
            log.warning("SSDP failed: %s", exc)
    return locations


def _fetch_xml(url: str) -> Optional[ET.Element]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "swift-proxy/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = resp.read(1_000_000)
        return ET.fromstring(data)
    except Exception as exc:  # noqa: BLE001
        log.warning("UPnP XML fetch failed (%s): %s", url, exc)
        return None


def _control_url(desc: ET.Element, device_url: str) -> Optional[Tuple[str, str]]:
    """Find a WAN connection service + control URL in a device description."""
    for service in desc.iter("service"):
        st = service.findtext("serviceType", "", _NS)
        if st in _WAN_CONN_TYPES:
            control = service.findtext("controlURL", "", _NS)
            if control:
                return urllib.parse.urljoin(device_url, control), st
    # descend into embedded devices (some routers nest WANIPConnection deeper)
    for dev in desc.iter("device"):
        for service in dev.iter("service"):
            st = service.findtext("serviceType", "", _NS)
            if st in _WAN_CONN_TYPES:
                control = service.findtext("controlURL", "", _NS)
                if control:
                    return urllib.parse.urljoin(device_url, control), st
    return None


def _soap(control_url: str, service_type: str, action: str, args: Dict[str, str]) -> bool:
    body = (
        '<?xml version="1.0"?>'
        f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f"<s:Body><u:{action} xmlns:u=\"{service_type}\">"
        + "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
        + f"</u:{action}></s:Body></s:Envelope>"
    )
    try:
        req = urllib.request.Request(
            control_url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service_type}#{action}"',
                "User-Agent": "swift-proxy/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT * 3) as resp:
            resp.read()
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("UPnP %s failed: %s", action, exc)
        return False


def _discover_control() -> Optional[Tuple[str, str]]:
    for loc in _msearch():
        desc = _fetch_xml(loc)
        if desc is None:
            continue
        found = _control_url(desc, loc)
        if found:
            return found
    return None


def add_port_mapping(port: int, external_ip: str = "0.0.0.0") -> Dict[str, object]:
    found = _discover_control()
    if not found:
        return {"ok": False, "reason": "router_upnp_not_found"}
    control_url, service_type = found
    args = {
        "NewRemoteHost": "",
        "NewExternalPort": str(port),
        "NewProtocol": "TCP",
        "NewInternalPort": str(port),
        "NewInternalClient": external_ip,
        "NewEnabled": "1",
        "NewPortMappingDescription": "SwiftProxy",
        "NewLeaseDuration": "0",
    }
    ok = _soap(control_url, service_type, "AddPortMapping", args)
    if not ok:
        args.pop("NewRemoteHost")
        ok = _soap(control_url, service_type, "AddPortMapping", args)
    return {"ok": ok}


def delete_port_mapping(port: int) -> Dict[str, object]:
    found = _discover_control()
    if not found:
        return {"ok": False, "reason": "router_upnp_not_found"}
    control_url, service_type = found
    args = {"NewRemoteHost": "", "NewExternalPort": str(port), "NewProtocol": "TCP"}
    ok = _soap(control_url, service_type, "DeletePortMapping", args)
    if not ok:
        args.pop("NewRemoteHost")
        ok = _soap(control_url, service_type, "DeletePortMapping", args)
    return {"ok": ok}


def is_supported() -> bool:
    return _discover_control() is not None