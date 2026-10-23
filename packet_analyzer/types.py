"""
Core types, data structures, and application mappings for the DPI Engine.
Preserves semantics of include/types.h and src/types.cpp.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


def parse_ip(ip: str | int) -> int:
    """
    Parse an IPv4 string into uint32 integer representation matching C++:
    Little-endian representation (first octet in lowest 8 bits).
    e.g. '192.168.1.100' -> 192 | (168 << 8) | (1 << 16) | (100 << 24)
    """
    if isinstance(ip, int):
        return ip & 0xFFFFFFFF
    
    result = 0
    shift = 0
    octet = 0
    for c in ip.strip():
        if c == '.':
            result |= (octet << shift)
            shift += 8
            octet = 0
        elif c.isdigit():
            octet = octet * 10 + int(c)
    result |= (octet << shift)
    return result & 0xFFFFFFFF


def format_ip(ip: int) -> str:
    """Format uint32 integer into IPv4 dotted quad string matching C++ format."""
    return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


@dataclass(frozen=True, slots=True)
class FiveTuple:
    """
    Uniquely identifies a connection / flow:
    (src_ip, dst_ip, src_port, dst_port, protocol)
    """
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def reverse(self) -> FiveTuple:
        """Create reverse tuple for matching bidirectional flows."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def to_string(self) -> str:
        proto_str = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else "?")
        return (
            f"{format_ip(self.src_ip)}:{self.src_port} -> "
            f"{format_ip(self.dst_ip)}:{self.dst_port} ({proto_str})"
        )

    def __str__(self) -> str:
        return self.to_string()

    def c_hash(self) -> int:
        """
        Calculates the 64-bit integer hash exactly matching FiveTupleHash in C++ types.h:
        h ^= std::hash(field) + 0x9e3779b9 + (h << 6) + (h >> 2)
        """
        mask64 = 0xFFFFFFFFFFFFFFFF
        h = 0
        for val in (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol):
            # C++ std::hash on integers is typically identity in libstdc++/libc++
            field_hash = val & mask64
            term = (field_hash + 0x9E3779B9 + ((h << 6) & mask64) + (h >> 2)) & mask64
            h = (h ^ term) & mask64
        return h


class AppType(Enum):
    """Application classification enum matching C++ AppType in types.h."""
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications (detected via SNI / Host)
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


_APP_TYPE_NAMES: dict[AppType, str] = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    """Convert AppType enum to display string matching C++ appTypeToString."""
    return _APP_TYPE_NAMES.get(app, "Unknown")


def string_to_app_type(name: str) -> Optional[AppType]:
    """Convert display name or enum name to AppType."""
    name_clean = name.strip()
    for app, str_val in _APP_TYPE_NAMES.items():
        if app == AppType.APP_COUNT:
            continue
        if str_val.lower() == name_clean.lower() or app.name.lower() == name_clean.lower():
            return app
    return None


def sni_to_app_type(sni: str) -> AppType:
    """
    Map SNI or Host domain to application type.
    Replicates the exact search order from src/types.cpp.
    """
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # Google (including google services)
    if any(pat in lower_sni for pat in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # YouTube
    if any(pat in lower_sni for pat in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # Facebook / Meta
    if any(pat in lower_sni for pat in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # Instagram
    if any(pat in lower_sni for pat in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp
    if any(pat in lower_sni for pat in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # Twitter / X
    if any(pat in lower_sni for pat in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    # Netflix
    if any(pat in lower_sni for pat in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Amazon
    if any(pat in lower_sni for pat in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Microsoft
    if any(pat in lower_sni for pat in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Apple
    if any(pat in lower_sni for pat in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(pat in lower_sni for pat in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(pat in lower_sni for pat in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(pat in lower_sni for pat in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM

    # Discord
    if any(pat in lower_sni for pat in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(pat in lower_sni for pat in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(pat in lower_sni for pat in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # If SNI is present but not recognized, still mark as HTTPS
    return AppType.HTTPS


class ConnectionState(Enum):
    """Connection state matching C++ ConnectionState."""
    NEW = auto()
    ESTABLISHED = auto()
    CLASSIFIED = auto()
    BLOCKED = auto()
    CLOSED = auto()


class PacketAction(Enum):
    """Packet action matching C++ PacketAction."""
    FORWARD = auto()
    DROP = auto()
    INSPECT = auto()
    LOG_ONLY = auto()


@dataclass
class Connection:
    """Connection entry tracked per flow matching C++ Connection struct."""
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


@dataclass
class PacketJob:
    """Packet job passed through thread-safe queues matching C++ PacketJob."""
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    ts_sec: int = 0
    ts_usec: int = 0
