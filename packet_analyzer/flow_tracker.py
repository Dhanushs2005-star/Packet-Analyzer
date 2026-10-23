"""
Stateful connection tracker and flow table.
Faithfully porting include/connection_tracker.h and src/connection_tracker.cpp.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from .parser import TCPFlags
from .types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
    app_type_to_string,
)


class ConnectionTracker:
    """
    Maintains flow table for active connections (per Fast Path worker).
    Tracks TCP state, application classification, and packet/byte counts.
    """

    def __init__(self, fp_id: int = 0, max_connections: int = 100000):
        self.fp_id = fp_id
        self.max_connections = max_connections
        self.connections: dict[FiveTuple, Connection] = {}
        self.total_seen = 0
        self.classified_count = 0
        self.blocked_count = 0

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        """Get existing connection or create a new one."""
        conn = self.connections.get(tuple_)
        if conn is not None:
            return conn

        # Check if table full, evict oldest
        if len(self.connections) >= self.max_connections:
            self._evict_oldest()

        now = time.time()
        conn = Connection(
            tuple=tuple_,
            state=ConnectionState.NEW,
            first_seen=now,
            last_seen=now,
        )
        self.connections[tuple_] = conn
        self.total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        """Lookup connection by 5-tuple, checking reverse tuple if not found."""
        conn = self.connections.get(tuple_)
        if conn is not None:
            return conn
        return self.connections.get(tuple_.reverse())

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool = True) -> None:
        """Update connection byte/packet stats and timestamp."""
        conn.last_seen = time.time()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(self, conn: Connection, app: AppType, sni: str) -> None:
        """Mark connection as classified with detected AppType and SNI/Host."""
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self.classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        """Mark connection as blocked."""
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self.blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        """Mark connection as closed."""
        conn = self.connections.get(tuple_)
        if conn:
            conn.state = ConnectionState.CLOSED

    def update_tcp_state(self, conn: Connection, tcp_flags: int) -> None:
        """
        Update TCP connection state matching FastPathProcessor::updateTCPState in C++.
        """
        if tcp_flags & TCPFlags.SYN:
            if tcp_flags & TCPFlags.ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & TCPFlags.ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & TCPFlags.FIN:
            conn.fin_seen = True

        if tcp_flags & TCPFlags.RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (tcp_flags & TCPFlags.ACK):
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        """Remove connections idle longer than timeout or marked CLOSED."""
        now = time.time()
        stale_keys = []
        for tuple_, conn in self.connections.items():
            age = now - conn.last_seen
            if age > timeout_seconds or conn.state == ConnectionState.CLOSED:
                stale_keys.append(tuple_)

        for k in stale_keys:
            del self.connections[k]

        return len(stale_keys)

    def _evict_oldest(self) -> None:
        if not self.connections:
            return
        oldest_tuple = min(self.connections.keys(), key=lambda k: self.connections[k].last_seen)
        del self.connections[oldest_tuple]

    def get_all_connections(self) -> list[Connection]:
        return list(self.connections.values())

    def get_active_count(self) -> int:
        return len(self.connections)

    def get_stats(self) -> dict[str, int]:
        return {
            "active_connections": len(self.connections),
            "total_connections_seen": self.total_seen,
            "classified_connections": self.classified_count,
            "blocked_connections": self.blocked_count,
        }

    def clear(self) -> None:
        self.connections.clear()


class GlobalConnectionTable:
    """Aggregates statistics from multiple Fast Path trackers."""

    def __init__(self, num_fps: int):
        self.trackers: list[Optional[ConnectionTracker]] = [None] * num_fps

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        if 0 <= fp_id < len(self.trackers):
            self.trackers[fp_id] = tracker

    def get_global_stats(self) -> dict:
        total_active = 0
        total_seen = 0
        app_distribution: dict[AppType, int] = {}
        domain_counts: dict[str, int] = {}

        for tracker in self.trackers:
            if not tracker:
                continue
            stats = tracker.get_stats()
            total_active += stats["active_connections"]
            total_seen += stats["total_connections_seen"]

            for conn in tracker.get_all_connections():
                app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "total_active_connections": total_active,
            "total_connections_seen": total_seen,
            "app_distribution": app_distribution,
            "top_domains": top_domains,
        }

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║               CONNECTION STATISTICS REPORT                    ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Active Connections:     {stats['total_active_connections']:>10}                          ║",
            f"║ Total Connections Seen: {stats['total_connections_seen']:>10}                          ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                    APPLICATION BREAKDOWN                      ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]

        total = sum(stats["app_distribution"].values())
        sorted_apps = sorted(stats["app_distribution"].items(), key=lambda x: x[1], reverse=True)

        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            app_str = app_type_to_string(app)
            lines.append(f"║ {app_str:<20}{count:>10} ({pct:>5.1f}%)           ║")

        if stats["top_domains"]:
            lines.extend([
                "╠══════════════════════════════════════════════════════════════╣",
                "║                      TOP DOMAINS                             ║",
                "╠══════════════════════════════════════════════════════════════╣",
            ])
            for domain, count in stats["top_domains"]:
                disp_domain = domain if len(domain) <= 35 else domain[:32] + "..."
                lines.append(f"║ {disp_domain:<40}{count:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝\n")
        return "\n".join(lines)
