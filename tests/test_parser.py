"""
Tests for packet reader and parser.
"""

import os
from pathlib import Path

from packet_analyzer.parser import (
    EtherType,
    PacketParser,
    Protocol,
    TCPFlags,
)
from packet_analyzer.reader import NativePcapReader, NativePcapWriter, ScapyPcapReader


def get_test_pcap_path() -> str:
    # d:\Packet_analyzer\test_dpi.pcap
    base_dir = Path(__file__).resolve().parent.parent.parent
    pcap = base_dir / "test_dpi.pcap"
    assert pcap.exists(), f"test_dpi.pcap not found at {pcap}"
    return str(pcap)


def test_native_pcap_reader_packet_count():
    pcap_path = get_test_pcap_path()
    with NativePcapReader(pcap_path) as reader:
        packets = list(reader)
    assert len(packets) == 77
    assert reader.global_header.version_major == 2
    assert reader.global_header.version_minor == 4


def test_scapy_pcap_reader_packet_count():
    pcap_path = get_test_pcap_path()
    with ScapyPcapReader(pcap_path) as reader:
        packets = list(reader)
    assert len(packets) == 77


def test_packet_parsing():
    pcap_path = get_test_pcap_path()
    reader = NativePcapReader(pcap_path)

    tcp_count = 0
    udp_count = 0
    parsed_count = 0

    for raw in reader:
        pkt = PacketParser.parse(raw.data, raw.header.ts_sec, raw.header.ts_usec)
        assert pkt is not None
        parsed_count += 1
        assert pkt.has_ip
        assert pkt.ether_type == EtherType.IPv4
        if pkt.has_tcp:
            tcp_count += 1
            assert pkt.protocol == Protocol.TCP
            assert pkt.src_port > 0 and pkt.dest_port > 0
        elif pkt.has_udp:
            udp_count += 1
            assert pkt.protocol == Protocol.UDP
            assert pkt.dest_port == 53

    reader.close()
    assert parsed_count == 77
    assert tcp_count == 73
    assert udp_count == 4


def test_flags_and_string_helpers():
    flags = TCPFlags.SYN | TCPFlags.ACK
    assert PacketParser.tcp_flags_to_string(flags) == "SYN ACK"
    assert PacketParser.protocol_to_string(6) == "TCP"
    assert PacketParser.protocol_to_string(17) == "UDP"
    assert PacketParser.protocol_to_string(1) == "ICMP"
    assert PacketParser.mac_to_string(b"\x00\x11\x22\x33\x44\x55") == "00:11:22:33:44:55"
    assert PacketParser.ip_to_string(b"\xc0\xa8\x01\x64") == "192.168.1.100"


def test_native_pcap_write_roundtrip(tmp_path):
    pcap_path = get_test_pcap_path()
    reader = NativePcapReader(pcap_path)
    original_packets = list(reader)
    reader.close()

    out_file = str(tmp_path / "roundtrip.pcap")
    with NativePcapWriter(out_file) as writer:
        for p in original_packets:
            writer.write_raw_packet(p)

    with NativePcapReader(out_file) as reader2:
        reread_packets = list(reader2)

    assert len(reread_packets) == len(original_packets)
    for p1, p2 in zip(original_packets, reread_packets):
        assert p1.header.ts_sec == p2.header.ts_sec
        assert p1.header.ts_usec == p2.header.ts_usec
        assert p1.data == p2.data
