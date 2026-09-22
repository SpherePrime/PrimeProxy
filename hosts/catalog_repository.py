"""Read-only repository for the shipped PrimeProxy Hosts SQLite catalog.

Ported from ZapretGUI ``hosts/catalog_repository.py``. The database is a
ready application resource bundled into ``resources/hosts/``; runtime code
only ever reads it (no Qt, no network, no writes).
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config.paths import resources_dir

CATALOG_APPLICATION_ID = 0x5A484354  # "ZHCT"
CATALOG_SCHEMA_VERSION = 1
CATALOG_FILE_NAME = "hosts_catalog.sqlite3"
DEFAULT_BLOCK_IP = "127.0.0.1"


class HostsCatalogError(RuntimeError):
    """The shipped catalog is missing, damaged or has an unsupported schema."""


@dataclass(frozen=True)
class CatalogService:
    service_id: str
    name: str
    category: str
    kind: str
    sort_order: int
    enabled: bool
    icon_name: str
    icon_color: Optional[str]
    domains: Tuple[str, ...]
    host_entries: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class HostsCatalog:
    catalog_version: str
    content_sha256: str
    services: Dict[str, CatalogService]
    service_order: Tuple[str, ...]


def catalog_path() -> Path:
    """Path of the bundled read-only hosts catalog resource."""
    return resources_dir() / "hosts" / CATALOG_FILE_NAME


def _connect_read_only(path: Path) -> sqlite3.Connection:
    try:
        resolved = path.resolve()
        is_windows_unc = os.name == "nt" and str(resolved).startswith(("\\\\", "//"))
        if is_windows_unc:
            connection = sqlite3.connect(resolved, timeout=5.0)
        else:
            uri = resolved.as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    except (OSError, sqlite3.Error) as exc:
        raise HostsCatalogError(f"не удалось открыть базу только для чтения: {exc}") from exc
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def _hash_query(
    digest: "hashlib._Hash",
    connection: sqlite3.Connection,
    table_name: str,
    query: str,
) -> None:
    import json

    digest.update(table_name.encode("ascii"))
    digest.update(b"\n")
    for row in connection.execute(query):
        payload = json.dumps(
            list(row),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)


def compute_content_sha256(connection: sqlite3.Connection) -> str:
    """Hash all logical catalog rows except self-referential metadata."""
    digest = hashlib.sha256()
    _hash_query(
        digest,
        connection,
        "services",
        """
        SELECT service_id, name, category, kind, sort_order, enabled,
               icon_name, icon_color
        FROM services
        ORDER BY service_id
        """,
    )
    _hash_query(
        digest,
        connection,
        "dns_profiles",
        """
        SELECT profile_id, name, sort_order, enabled
        FROM dns_profiles
        ORDER BY profile_id
        """,
    )
    _hash_query(
        digest,
        connection,
        "domains",
        """
        SELECT domain_id, service_id, hostname, sort_order
        FROM domains
        ORDER BY domain_id
        """,
    )
    _hash_query(
        digest,
        connection,
        "dns_answers",
        """
        SELECT domain_id, profile_id, ip_address, priority
        FROM dns_answers
        ORDER BY domain_id, profile_id, priority, ip_address
        """,
    )
    _hash_query(
        digest,
        connection,
        "hosts_entries",
        """
        SELECT entry_id, service_id, hostname, ip_address, priority
        FROM hosts_entries
        ORDER BY entry_id
        """,
    )
    return digest.hexdigest()


def catalog_meta(connection: sqlite3.Connection) -> Dict[str, str]:
    return {
        str(row["key"]): str(row["value"])
        for row in connection.execute("SELECT key, value FROM catalog_meta")
    }


def list_services(
    connection: sqlite3.Connection,
    enabled_only: bool = True,
) -> List[CatalogService]:
    query = """
        SELECT service_id, name, category, kind, sort_order, enabled,
               icon_name, icon_color
        FROM services
        {where}
        ORDER BY sort_order, service_id
    """
    where = "WHERE enabled = 1" if enabled_only else ""
    rows = []
    for row in connection.execute(query.format(where=where)):
        rows.append(
            CatalogService(
                service_id=str(row["service_id"]),
                name=str(row["name"]),
                category=str(row["category"]),
                kind=str(row["kind"]),
                sort_order=int(row["sort_order"]),
                enabled=bool(row["enabled"]),
                icon_name=str(row["icon_name"]),
                icon_color=(
                    str(row["icon_color"]) if row["icon_color"] is not None else None
                ),
                domains=(),
                host_entries=(),
            )
        )
    return rows


def count_services(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM services").fetchone()[0])


def count_domains(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM domains").fetchone()[0])


def count_host_entries(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM hosts_entries").fetchone()[0])


def dns_domains(connection: sqlite3.Connection, service_id: str) -> List[str]:
    rows = connection.execute(
        """
        SELECT hostname
        FROM domains
        WHERE service_id = ?
        ORDER BY sort_order, domain_id
        """,
        (service_id,),
    )
    return [str(row["hostname"]) for row in rows]


def host_entries(connection: sqlite3.Connection, service_id: str) -> Dict[str, str]:
    rows = connection.execute(
        """
        SELECT hostname, ip_address
        FROM hosts_entries
        WHERE service_id = ?
        ORDER BY priority, entry_id
        """,
        (service_id,),
    )
    out: Dict[str, str] = {}
    for row in rows:
        hostname = str(row["hostname"])
        out.setdefault(hostname, str(row["ip_address"]))
    return out


def get_service_domains(connection: sqlite3.Connection, service_id: str) -> Dict[str, str]:
    """Domain->IP map for one service.

    ``hosts``-kind services use the concrete IPs from ``hosts_entries``;
    ``dns``-kind services block every domain with the loopback IP.
    """
    row = connection.execute(
        "SELECT kind FROM services WHERE service_id = ?",
        (service_id,),
    ).fetchone()
    if row is None:
        return {}
    if str(row["kind"]) == "hosts":
        return host_entries(connection, service_id)
    domains = dns_domains(connection, service_id)
    return {domain: DEFAULT_BLOCK_IP for domain in domains}


def catalog_domain_names(
    path: Path | None = None,
    enabled_only: bool = True,
) -> List[str]:
    """All targetable hostnames from the catalog (enabled services by default).

    Combines ``hosts_entries`` hostnames (hosts-kind services) and ``domains``
    hostnames (dns-kind services), deduplicated, sorted. Used to build
    blockcheck target lists that follow the catalog domain names. Read-only,
    no logical-content validation (cheap, runtime-safe).
    """
    db_path = path or catalog_path()
    if not db_path.is_file():
        return []
    connection = _connect_read_only(db_path)
    try:
        ids: set[str] = set()
        if enabled_only:
            for row in connection.execute(
                "SELECT service_id FROM services WHERE enabled = 1"
            ):
                ids.add(str(row["service_id"]))
        out: set[str] = set()
        for row in connection.execute(
            "SELECT service_id, hostname FROM hosts_entries "
            "UNION "
            "SELECT service_id, hostname FROM domains"
        ):
            if enabled_only and str(row["service_id"]) not in ids:
                continue
            host = str(row["hostname"]).strip().lower().rstrip(".")
            if host:
                out.add(host)
        return sorted(out)
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _load_services(connection: sqlite3.Connection) -> Dict[str, CatalogService]:
    services: Dict[str, CatalogService] = {}
    for row in list_services(connection, enabled_only=True):
        services[str(row.service_id)] = row

    domain_rows = connection.execute(
        """
        SELECT service_id, hostname
        FROM domains
        ORDER BY service_id, sort_order, domain_id
        """
    )
    per_service: Dict[str, List[str]] = {sid: [] for sid in services}
    for row in domain_rows:
        sid = str(row["service_id"])
        if sid in per_service:
            per_service[sid].append(str(row["hostname"]))

    host_rows = connection.execute(
        """
        SELECT service_id, hostname, ip_address
        FROM hosts_entries
        ORDER BY service_id, priority, entry_id
        """
    )
    host_per_service: Dict[str, List[Tuple[str, str]]] = {sid: [] for sid in services}
    for row in host_rows:
        sid = str(row["service_id"])
        if sid in host_per_service:
            host_per_service[sid].append((str(row["hostname"]), str(row["ip_address"])))

    return {
        sid: CatalogService(
            service_id=svc.service_id,
            name=svc.name,
            category=svc.category,
            kind=svc.kind,
            sort_order=svc.sort_order,
            enabled=svc.enabled,
            icon_name=svc.icon_name,
            icon_color=svc.icon_color,
            domains=tuple(per_service[sid]),
            host_entries=tuple(host_per_service[sid]),
        )
        for sid, svc in services.items()
    }


def _validate_database(connection: sqlite3.Connection) -> Dict[str, str]:
    quick_check = connection.execute("PRAGMA quick_check").fetchone()
    if quick_check is None or str(quick_check[0]).casefold() != "ok":
        detail = str(quick_check[0]) if quick_check is not None else "нет результата"
        raise HostsCatalogError(f"PRAGMA quick_check: {detail}")

    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    if application_id != CATALOG_APPLICATION_ID:
        raise HostsCatalogError(
            f"неверный application_id: {application_id}, ожидался {CATALOG_APPLICATION_ID}"
        )

    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if user_version != CATALOG_SCHEMA_VERSION:
        raise HostsCatalogError(
            f"неподдерживаемая схема {user_version}, ожидалась {CATALOG_SCHEMA_VERSION}"
        )

    try:
        meta = catalog_meta(connection)
    except sqlite3.Error as exc:
        raise HostsCatalogError(f"не удалось прочитать catalog_meta: {exc}") from exc

    if meta.get("schema_version") != str(CATALOG_SCHEMA_VERSION):
        raise HostsCatalogError("catalog_meta.schema_version не соответствует PRAGMA user_version")
    if not meta.get("catalog_version"):
        raise HostsCatalogError("catalog_meta.catalog_version отсутствует")
    expected_hash = str(meta.get("content_sha256") or "").casefold()
    if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
        raise HostsCatalogError("catalog_meta.content_sha256 имеет неверный формат")

    try:
        actual_hash = compute_content_sha256(connection)
    except sqlite3.Error as exc:
        raise HostsCatalogError(f"структура таблиц каталога повреждена: {exc}") from exc
    if actual_hash != expected_hash:
        raise HostsCatalogError(
            "логическая контрольная сумма каталога не совпадает с catalog_meta.content_sha256"
        )
    return meta


def load_catalog(path: Path) -> HostsCatalog:
    if not path.is_file():
        raise HostsCatalogError(f"файл не найден: {path}")
    connection = _connect_read_only(path)
    try:
        meta = _validate_database(connection)
        services = _load_services(connection)
        return HostsCatalog(
            catalog_version=meta["catalog_version"],
            content_sha256=meta["content_sha256"],
            services=services,
            service_order=tuple(services),
        )
    except HostsCatalogError:
        raise
    except sqlite3.Error as exc:
        raise HostsCatalogError(f"ошибка чтения SQLite: {exc}") from exc
    finally:
        connection.close()


__all__ = [
    "CATALOG_APPLICATION_ID",
    "CATALOG_FILE_NAME",
    "CATALOG_SCHEMA_VERSION",
    "DEFAULT_BLOCK_IP",
    "CatalogService",
    "HostsCatalog",
    "HostsCatalogError",
    "catalog_meta",
    "catalog_path",
    "catalog_domain_names",
    "compute_content_sha256",
    "count_domains",
    "count_host_entries",
    "count_services",
    "dns_domains",
    "get_service_domains",
    "host_entries",
    "list_services",
    "load_catalog",
]