"""
Hosts-file unblock management for PrimeProxy.

Cross-platform hosts file manager + built-in service catalog
(replaces the Windows-only ZapretGUI hosts module).
"""
from .catalog import (
    SERVICE_CATALOG,
    catalog_signature,
    invalidate_catalog_cache,
    merge_service_domains,
    normalize_service_ids,
    service_domains,
    services_snapshot,
)
from .manager import (
    HOSTS_PATH,
    apply_host_entries,
    clear_host_entries,
    get_hosts_path_str,
    open_hosts_file,
    read_active_domains_map,
    read_hosts_file,
    write_hosts_file,
)

__all__ = [
    "HOSTS_PATH",
    "SERVICE_CATALOG",
    "apply_host_entries",
    "catalog_signature",
    "clear_host_entries",
    "get_hosts_path_str",
    "invalidate_catalog_cache",
    "merge_service_domains",
    "normalize_service_ids",
    "open_hosts_file",
    "read_active_domains_map",
    "read_hosts_file",
    "service_domains",
    "services_snapshot",
    "write_hosts_file",
]