"""
Rule Manager for traffic filtering and blocking.
Faithfully porting include/rule_manager.h and src/rule_manager.cpp.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from .types import (
    AppType,
    app_type_to_string,
    format_ip,
    parse_ip,
    string_to_app_type,
)


class BlockReasonType(Enum):
    IP = auto()
    APP = auto()
    DOMAIN = auto()
    PORT = auto()


@dataclass
class BlockReason:
    """Reason for a blocked packet matching BlockReason in rule_manager.h."""
    type: BlockReasonType
    detail: str


@dataclass
class RuleStats:
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


class RuleManager:
    """
    Thread-safe rule manager supporting IP, App, Domain (with wildcards & substring),
    and Port blocking. Also supports INI file persistence.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._blocked_ips: set[int] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: set[str] = set()
        self._domain_patterns: list[str] = []
        self._blocked_ports: set[int] = set()

    # ========== IP Blocking ==========

    def block_ip(self, ip: int | str) -> None:
        ip_val = parse_ip(ip) if isinstance(ip, str) else ip
        with self._lock:
            self._blocked_ips.add(ip_val)

    def unblock_ip(self, ip: int | str) -> None:
        ip_val = parse_ip(ip) if isinstance(ip, str) else ip
        with self._lock:
            self._blocked_ips.discard(ip_val)

    def is_ip_blocked(self, ip: int | str) -> bool:
        ip_val = parse_ip(ip) if isinstance(ip, str) else ip
        with self._lock:
            return ip_val in self._blocked_ips

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return [format_ip(ip) for ip in sorted(self._blocked_ips)]

    # ========== Application Blocking ==========

    def block_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            app_enum = string_to_app_type(app)
            if app_enum is None:
                raise ValueError(f"Unknown application name: {app}")
            app = app_enum
        with self._lock:
            self._blocked_apps.add(app)

    def unblock_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            app_enum = string_to_app_type(app)
            if app_enum is None:
                return
            app = app_enum
        with self._lock:
            self._blocked_apps.discard(app)

    def is_app_blocked(self, app: AppType) -> bool:
        with self._lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> list[AppType]:
        with self._lock:
            return list(self._blocked_apps)

    # ========== Domain Blocking ==========

    def block_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        with self._lock:
            if "*" in domain:
                if domain not in self._domain_patterns:
                    self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)

    def unblock_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        with self._lock:
            if "*" in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)

    @staticmethod
    def domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Check if domain matches pattern (supports *.example.com or substring matching).
        Matches C++ RuleManager::domainMatchesPattern.
        """
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            if domain.endswith(suffix):
                return True
            bare = pattern[2:]
            if domain == bare:
                return True
        elif pattern in domain:
            return True
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        domain_lower = domain.strip().lower()
        with self._lock:
            # Check exact match
            if domain_lower in self._blocked_domains:
                return True

            # Check substring against non-pattern blocked domains
            for d in self._blocked_domains:
                if d in domain_lower:
                    return True

            # Check wildcard patterns
            for pat in self._domain_patterns:
                if self.domain_matches_pattern(domain_lower, pat):
                    return True

        return False

    def get_blocked_domains(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_domains) + list(self._domain_patterns)

    # ========== Port Blocking ==========

    def block_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.add(port)

    def unblock_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    # ========== Combined Check ==========

    def should_block(
        self,
        src_ip: int | str,
        dst_port: int,
        app: AppType,
        domain: str = "",
    ) -> Optional[BlockReason]:
        """
        Combined rule check matching RuleManager::shouldBlock in C++.
        Priority order: IP -> Port -> App -> Domain.
        """
        # Check IP first
        if self.is_ip_blocked(src_ip):
            ip_str = src_ip if isinstance(src_ip, str) else format_ip(src_ip)
            return BlockReason(BlockReasonType.IP, ip_str)

        # Check Port
        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReasonType.PORT, str(dst_port))

        # Check App
        if self.is_app_blocked(app):
            return BlockReason(BlockReasonType.APP, app_type_to_string(app))

        # Check Domain
        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReasonType.DOMAIN, domain)

        return None

    # ========== Persistence ==========

    def save_rules(self, filename: str) -> bool:
        """Save rules to file matching INI format in C++ RuleManager::saveRules."""
        with self._lock:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("[BLOCKED_IPS]\n")
                    for ip_str in self.get_blocked_ips():
                        f.write(f"{ip_str}\n")

                    f.write("\n[BLOCKED_APPS]\n")
                    for app in self.get_blocked_apps():
                        f.write(f"{app_type_to_string(app)}\n")

                    f.write("\n[BLOCKED_DOMAINS]\n")
                    for domain in self.get_blocked_domains():
                        f.write(f"{domain}\n")

                    f.write("\n[BLOCKED_PORTS]\n")
                    for port in sorted(self._blocked_ports):
                        f.write(f"{port}\n")
                return True
            except Exception:
                return False

    def load_rules(self, filename: str) -> bool:
        """Load rules from file matching INI format in C++ RuleManager::loadRules."""
        with self._lock:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    current_section = ""
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line:
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            current_section = line
                            continue

                        if current_section == "[BLOCKED_IPS]":
                            self.block_ip(line)
                        elif current_section == "[BLOCKED_APPS]":
                            app_enum = string_to_app_type(line)
                            if app_enum is not None:
                                self.block_app(app_enum)
                        elif current_section == "[BLOCKED_DOMAINS]":
                            self.block_domain(line)
                        elif current_section == "[BLOCKED_PORTS]":
                            self.block_port(int(line))
                return True
            except Exception:
                return False

    def clear_all(self) -> None:
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._blocked_ports.clear()

    def get_stats(self) -> RuleStats:
        with self._lock:
            return RuleStats(
                blocked_ips=len(self._blocked_ips),
                blocked_apps=len(self._blocked_apps),
                blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
                blocked_ports=len(self._blocked_ports),
            )
