"""
Single-threaded DPI engine.
Faithfully porting src/main_working.cpp.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

from ..inspectors import HTTPHostExtractor, SNIExtractor
from ..parser import PacketParser
from ..reader import NativePcapReader, NativePcapWriter
from ..reporting import generate_processing_report
from ..rules import RuleManager
from ..types import (
    AppType,
    FiveTuple,
    app_type_to_string,
    format_ip,
    parse_ip,
    sni_to_app_type,
)


@dataclass
class Flow:
    """Simplified per-flow entry matching Flow in main_working.cpp."""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class SingleThreadedEngine:
    """
    Single-threaded reference DPI Engine matching main_working.cpp.
    """

    def __init__(self, rules: Optional[RuleManager] = None):
        self.rules = rules or RuleManager()

    def process(
        self,
        input_file: str,
        output_file: str,
        verbose: bool = False,
        log_stream=sys.stdout,
    ) -> dict:
        """
        Process an input PCAP file and write allowed traffic to output PCAP file.
        Returns statistics dictionary.
        """
        reader = NativePcapReader(input_file)
        writer = NativePcapWriter(output_file, snaplen=reader.global_header.snaplen)

        flows: dict[FiveTuple, Flow] = {}
        app_stats: dict[AppType, int] = {}
        total_packets = 0
        forwarded = 0
        dropped = 0

        try:
            for raw in reader:
                total_packets += 1
                pkt = PacketParser.parse(raw.data, raw.header.ts_sec, raw.header.ts_usec)
                if not pkt or not pkt.has_ip or (not pkt.has_tcp and not pkt.has_udp):
                    continue

                tuple_ = FiveTuple(
                    src_ip=parse_ip(pkt.src_ip),
                    dst_ip=parse_ip(pkt.dest_ip),
                    src_port=pkt.src_port,
                    dst_port=pkt.dest_port,
                    protocol=pkt.protocol,
                )

                flow = flows.get(tuple_)
                if flow is None:
                    flow = Flow(tuple=tuple_)
                    flows[tuple_] = flow

                flow.packets += 1
                flow.bytes += len(raw.data)

                # Try SNI extraction for HTTPS
                if (
                    flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                    and not flow.sni
                    and pkt.has_tcp
                    and pkt.dest_port == 443
                    and pkt.payload_length > 5
                ):
                    sni = SNIExtractor.extract(pkt.payload_data)
                    if sni:
                        flow.sni = sni
                        flow.app_type = sni_to_app_type(sni)

                # Try HTTP Host extraction
                if (
                    flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
                    and not flow.sni
                    and pkt.has_tcp
                    and pkt.dest_port == 80
                    and pkt.payload_length > 0
                ):
                    host = HTTPHostExtractor.extract(pkt.payload_data)
                    if host:
                        flow.sni = host
                        flow.app_type = sni_to_app_type(host)

                # DNS classification
                if flow.app_type == AppType.UNKNOWN and (pkt.dest_port == 53 or pkt.src_port == 53):
                    flow.app_type = AppType.DNS

                # Port fallback
                if flow.app_type == AppType.UNKNOWN:
                    if pkt.dest_port == 443:
                        flow.app_type = AppType.HTTPS
                    elif pkt.dest_port == 80:
                        flow.app_type = AppType.HTTP

                # Check blocking rules
                if not flow.blocked:
                    flow.blocked = (
                        self.rules.is_ip_blocked(tuple_.src_ip)
                        or self.rules.is_app_blocked(flow.app_type)
                        or (bool(flow.sni) and self.rules.is_domain_blocked(flow.sni))
                    )
                    if flow.blocked and verbose:
                        detail = f": {flow.sni}" if flow.sni else ""
                        print(
                            f"[BLOCKED] {pkt.src_ip} -> {pkt.dest_ip} "
                            f"({app_type_to_string(flow.app_type)}{detail})",
                            file=log_stream,
                        )

                app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

                if flow.blocked:
                    dropped += 1
                else:
                    forwarded += 1
                    writer.write_raw_packet(raw)

        finally:
            reader.close()
            writer.close()

        unique_snis = {f.sni: f.app_type for f in flows.values() if f.sni}
        report = generate_processing_report(
            total_packets=total_packets,
            forwarded=forwarded,
            dropped=dropped,
            active_flows=len(flows),
            app_stats=app_stats,
            unique_snis=unique_snis,
            output_file=output_file,
        )

        return {
            "total_packets": total_packets,
            "forwarded": forwarded,
            "dropped": dropped,
            "active_flows": len(flows),
            "app_stats": app_stats,
            "unique_snis": unique_snis,
            "report": report,
        }
