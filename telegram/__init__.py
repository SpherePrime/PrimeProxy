"""
Telegram WSS/SOCKS5/MTProxy proxy engine (ported from ZapretGUI).

Provides a local SOCKS5 and MTProxy server that tunnels Telegram traffic
through Cloudflare WebSocket relays (kws{N}.web.telegram.org) to bypass
IP-based blocking. Fully stdlib + cryptography (no tgcrypto).

The main entry point is :class:`TelegramWSProxy` from :mod:`telegram.server`.
"""
from .socks5 import handshake, Socks5Error, Socks5ReplyError
from .server import TelegramWSProxy

__all__ = ["TelegramWSProxy", "Socks5Error", "Socks5ReplyError", "handshake"]