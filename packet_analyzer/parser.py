"""
Network Protocol Parser for Ethernet, IPv4, TCP, and UDP.
Faithfully reproduces include/packet_parser.h and src/packet_parser.cpp.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


@dataclass
class ParsedPacket:
    """Parsed packet information matching struct ParsedPacket in packet_parser.h."""
    timestamp_sec: int = 0
    timestamp_usec: int = 0

    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0

    # IP layer
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0

    # Transport layer
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0

    # TCP specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Payload
    payload_length: int = 0
    payload_data: bytes = b""


class PacketParser:
    """Parser for raw packet bytes into ParsedPacket matching C++ PacketParser."""

    @staticmethod
    def mac_to_string(mac_bytes: bytes) -> str:
        """Format 6 MAC bytes to colon-delimited lowercase hex string."""
        return ":".join(f"{b:02x}" for b in mac_bytes[:6])

    @staticmethod
    def ip_to_string(ip_bytes: bytes) -> str:
        """Format 4 IP bytes to dotted-decimal string (network byte order)."""
        return ".".join(str(b) for b in ip_bytes[:4])

    @staticmethod
    def protocol_to_string(proto: int) -> str:
        if proto == Protocol.ICMP:
            return "ICMP"
        if proto == Protocol.TCP:
            return "TCP"
        if proto == Protocol.UDP:
            return "UDP"
        return f"Unknown({proto})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN:
            parts.append("SYN")
        if flags & TCPFlags.ACK:
            parts.append("ACK")
        if flags & TCPFlags.FIN:
            parts.append("FIN")
        if flags & TCPFlags.RST:
            parts.append("RST")
        if flags & TCPFlags.PSH:
            parts.append("PSH")
        if flags & TCPFlags.URG:
            parts.append("URG")
        return " ".join(parts) if parts else "none"

    @classmethod
    def parse(cls, data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> Optional[ParsedPacket]:
        """
        Parse raw bytes of a packet into ParsedPacket.
        Returns None if packet is malformed or too short to contain Ethernet header.
        """
        pkt = ParsedPacket(timestamp_sec=ts_sec, timestamp_usec=ts_usec)
        total_len = len(data)
        offset = 0

        # Ethernet Header (14 bytes)
        if total_len < 14:
            return None

        pkt.dest_mac = cls.mac_to_string(data[0:6])
        pkt.src_mac = cls.mac_to_string(data[6:12])
        pkt.ether_type = struct.unpack(">H", data[12:14])[0]
        offset = 14

        # Parse IPv4
        if pkt.ether_type == EtherType.IPv4:
            if total_len < offset + 20:
                return None

            ver_ihl = data[offset]
            pkt.ip_version = (ver_ihl >> 4) & 0x0F
            ihl = ver_ihl & 0x0F
            if pkt.ip_version != 4:
                return None

            ip_header_len = ihl * 4
            if ip_header_len < 20 or total_len < offset + ip_header_len:
                return None

            ip_data = data[offset : offset + ip_header_len]
            pkt.ttl = ip_data[8]
            pkt.protocol = ip_data[9]
            pkt.src_ip = cls.ip_to_string(ip_data[12:16])
            pkt.dest_ip = cls.ip_to_string(ip_data[16:20])
            pkt.has_ip = True
            offset += ip_header_len

            # Transport layer
            if pkt.protocol == Protocol.TCP:
                if total_len < offset + 20:
                    return None
                src_port, dest_port, seq, ack, data_off_res, flags = struct.unpack(
                    ">HHIIBB", data[offset : offset + 14]
                )
                pkt.src_port = src_port
                pkt.dest_port = dest_port
                pkt.seq_number = seq
                pkt.ack_number = ack
                pkt.tcp_flags = flags
                data_offset = (data_off_res >> 4) & 0x0F
                tcp_header_len = data_offset * 4
                if tcp_header_len < 20 or total_len < offset + tcp_header_len:
                    return None

                pkt.has_tcp = True
                offset += tcp_header_len

            elif pkt.protocol == Protocol.UDP:
                if total_len < offset + 8:
                    return None
                src_port, dest_port = struct.unpack(">HH", data[offset : offset + 4])
                pkt.src_port = src_port
                pkt.dest_port = dest_port
                pkt.has_udp = True
                offset += 8

        # Payload
        if offset < total_len:
            pkt.payload_length = total_len - offset
            pkt.payload_data = data[offset:]
        else:
            pkt.payload_length = 0
            pkt.payload_data = b""

        return pkt
