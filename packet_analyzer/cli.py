"""
Command Line Interfaces matching C++ binaries:
- packet-analyzer (matching main.cpp)
- dpi-engine (matching dpi_mt.cpp and main_dpi.cpp)
"""

from __future__ import annotations

import argparse
import datetime
import sys
from typing import Optional

from .engine import MultiThreadedEngine, SingleThreadedEngine
from .parser import EtherType, PacketParser
from .reader import NativePcapReader, RawPacket
from .rules import RuleManager


def format_hex_preview(data: bytes, max_len: int = 32) -> str:
    preview = data[:max_len]
    hex_str = " ".join(f"{b:02x}" for b in preview)
    if len(data) > max_len:
        hex_str += " ..."
    return hex_str


def print_packet_summary(raw: RawPacket, packet_num: int, out=sys.stdout) -> None:
    pkt = PacketParser.parse(raw.data, raw.header.ts_sec, raw.header.ts_usec)
    if not pkt:
        print(f"Warning: Failed to parse packet #{packet_num}", file=sys.stderr)
        return

    time_dt = datetime.datetime.fromtimestamp(pkt.timestamp_sec)
    time_str = time_dt.strftime("%Y-%m-%d %H:%M:%S") + f".{pkt.timestamp_usec:06d}"

    print(f"\n========== Packet #{packet_num} ==========", file=out)
    print(f"Time: {time_str}\n", file=out)

    # Ethernet
    print("[Ethernet]", file=out)
    print(f"  Source MAC:      {pkt.src_mac}", file=out)
    print(f"  Destination MAC: {pkt.dest_mac}", file=out)
    eth_type_name = ""
    if pkt.ether_type == EtherType.IPv4:
        eth_type_name = " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        eth_type_name = " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        eth_type_name = " (ARP)"
    print(f"  EtherType:       0x{pkt.ether_type:04x}{eth_type_name}\n", file=out)

    # IP
    if pkt.has_ip:
        print(f"[IPv{pkt.ip_version}]", file=out)
        print(f"  Source IP:      {pkt.src_ip}", file=out)
        print(f"  Destination IP: {pkt.dest_ip}", file=out)
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}", file=out)
        print(f"  TTL:            {pkt.ttl}\n", file=out)

    # TCP
    if pkt.has_tcp:
        print("[TCP]", file=out)
        print(f"  Source Port:      {pkt.src_port}", file=out)
        print(f"  Destination Port: {pkt.dest_port}", file=out)
        print(f"  Sequence Number:  {pkt.seq_number}", file=out)
        print(f"  Ack Number:       {pkt.ack_number}", file=out)
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}\n", file=out)

    # UDP
    if pkt.has_udp:
        print("[UDP]", file=out)
        print(f"  Source Port:      {pkt.src_port}", file=out)
        print(f"  Destination Port: {pkt.dest_port}\n", file=out)

    # Payload
    if pkt.payload_length > 0:
        print("[Payload]", file=out)
        print(f"  Length: {pkt.payload_length} bytes", file=out)
        print(f"  Preview: {format_hex_preview(pkt.payload_data)}", file=out)


def run_packet_analyzer(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint matching C++ packet_analyzer in main.cpp."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Packet Analyzer - L2-L4 Protocol Decoder",
    )
    parser.add_argument("pcap_file", help="Path to .pcap file")
    parser.add_argument(
        "max_packets",
        nargs="?",
        type=int,
        default=-1,
        help="Maximum number of packets to display (-1 for all)",
    )

    args = parser.parse_args(argv)

    print("====================================")
    print("     Packet Analyzer v1.0 (Python)")
    print("====================================\n")

    try:
        reader = NativePcapReader(args.pcap_file)
    except Exception as e:
        print(f"Error: Could not open file: {args.pcap_file} ({e})", file=sys.stderr)
        return 1

    print("--- Reading packets ---")
    packet_count = 0
    parse_errors = 0

    try:
        for raw in reader:
            packet_count += 1
            print_packet_summary(raw, packet_count)

            if args.max_packets > 0 and packet_count >= args.max_packets:
                print(f"\n(Stopped after {args.max_packets} packets)")
                break
    finally:
        reader.close()

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")
    return 0


def run_dpi_engine(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint matching C++ dpi_engine in dpi_mt.cpp / main_dpi.cpp."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="dpi-engine",
        description="DPI Engine - Deep Packet Inspection and Traffic Filtering System",
    )
    parser.add_argument("input_pcap", help="Input PCAP file (captured user traffic)")
    parser.add_argument("output_pcap", help="Output PCAP file (filtered traffic to internet)")
    parser.add_argument("--block-ip", action="append", default=[], help="Block source IP (can be repeated)")
    parser.add_argument("--block-app", action="append", default=[], help="Block application (e.g. YouTube, Facebook)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain (supports wildcards: *.facebook.com)")
    parser.add_argument("--rules", help="Path to rules file ([BLOCKED_IPS], etc.)")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads (default: 2)")
    parser.add_argument("--fps", type=int, default=2, help="FP threads per LB (default: 2)")
    parser.add_argument("--single-threaded", action="store_true", help="Run single-threaded engine instead of multi-threaded")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv)

    rules = RuleManager()
    if args.rules:
        if not rules.load_rules(args.rules):
            print(f"Warning: Failed to load rules file '{args.rules}'", file=sys.stderr)

    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for dom in args.block_domain:
        rules.block_domain(dom)

    if args.single_threaded:
        engine = SingleThreadedEngine(rules=rules)
        res = engine.process(args.input_pcap, args.output_pcap, verbose=args.verbose)
    else:
        engine = MultiThreadedEngine(
            num_lbs=args.lbs,
            fps_per_lb=args.fps,
            rules=rules,
        )
        res = engine.process(args.input_pcap, args.output_pcap, verbose=args.verbose)

    print(res["report"])
    return 0
