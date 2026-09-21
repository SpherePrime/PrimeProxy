"""
DNS provider catalog and cross-platform DNS checks for SwiftProxy.

Combines ZapretGUI's DNS provider data with a fresh platform-aware
check/force implementation (works on Windows, macOS and Linux).
"""
from .check import (
    flush_dns_cache,
    force_dns,
    get_provider_list,
    get_system_dns_servers,
    restore_dns,
    run_provider_tests,
    test_dns_udp,
    test_doh_endpoint,
)
from .providers import DNS_PROVIDERS, get_provider

__all__ = [
    "DNS_PROVIDERS",
    "flush_dns_cache",
    "force_dns",
    "get_provider",
    "get_provider_list",
    "get_system_dns_servers",
    "restore_dns",
    "run_provider_tests",
    "test_dns_udp",
    "test_doh_endpoint",
]