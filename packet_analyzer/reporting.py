"""
ASCII box-drawing and table reporting matching C++ report outputs.
"""

from __future__ import annotations

from typing import Sequence
from .types import AppType, app_type_to_string


def generate_processing_report(
    total_packets: int,
    forwarded: int,
    dropped: int,
    active_flows: int,
    app_stats: dict[AppType, int],
    unique_snis: dict[str, AppType],
    output_file: str,
) -> str:
    """Format processing report matching C++ main_working.cpp."""
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════╗",
        "║                      PROCESSING REPORT                       ║",
        "╠══════════════════════════════════════════════════════════════╣",
        f"║ Total Packets:      {total_packets:>10}                             ║",
        f"║ Forwarded:          {forwarded:>10}                             ║",
        f"║ Dropped:            {dropped:>10}                             ║",
        f"║ Active Flows:       {active_flows:>10}                             ║",
        "╠══════════════════════════════════════════════════════════════╣",
        "║                    APPLICATION BREAKDOWN                     ║",
        "╠══════════════════════════════════════════════════════════════╣",
    ]

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        app_name = app_type_to_string(app)
        lines.append(f"║ {app_name:<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

    lines.append("╚══════════════════════════════════════════════════════════════╝")

    if unique_snis:
        lines.append("\n[Detected Applications/Domains]")
        for sni, app in sorted(unique_snis.items(), key=lambda x: x[0]):
            lines.append(f"  - {sni} -> {app_type_to_string(app)}")

    lines.append(f"\nOutput written to: {output_file}\n")
    return "\n".join(lines)


def generate_mt_report(
    total_packets: int,
    total_bytes: int,
    tcp_packets: int,
    udp_packets: int,
    forwarded: int,
    dropped: int,
    lb_dispatched: Sequence[int],
    fp_processed: Sequence[int],
    app_counts: dict[AppType, int],
    detected_snis: dict[str, AppType],
) -> str:
    """Format processing report matching C++ dpi_mt.cpp / dpi_engine.cpp."""
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════╗",
        "║                      PROCESSING REPORT                        ║",
        "╠══════════════════════════════════════════════════════════════╣",
        f"║ Total Packets:      {total_packets:>12}                           ║",
        f"║ Total Bytes:        {total_bytes:>12}                           ║",
        f"║ TCP Packets:        {tcp_packets:>12}                           ║",
        f"║ UDP Packets:        {udp_packets:>12}                           ║",
        "╠══════════════════════════════════════════════════════════════╣",
        f"║ Forwarded:          {forwarded:>12}                           ║",
        f"║ Dropped:            {dropped:>12}                           ║",
        "╠══════════════════════════════════════════════════════════════╣",
        "║ THREAD STATISTICS                                             ║",
    ]

    for i, count in enumerate(lb_dispatched):
        lines.append(f"║   LB{i} dispatched:   {count:>12}                           ║")

    for i, count in enumerate(fp_processed):
        lines.append(f"║   FP{i} processed:    {count:>12}                           ║")

    lines.extend([
        "╠══════════════════════════════════════════════════════════════╣",
        "║                   APPLICATION BREAKDOWN                       ║",
        "╠══════════════════════════════════════════════════════════════╣",
    ])

    sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0
        bar = "#" * int(pct / 5)
        lines.append(f"║ {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

    lines.append("╚══════════════════════════════════════════════════════════════╝")

    if detected_snis:
        lines.append("\n[Detected Domains/SNIs]")
        for sni, app in sorted(detected_snis.items(), key=lambda x: x[0]):
            lines.append(f"  - {sni} -> {app_type_to_string(app)}")

    return "\n".join(lines)
