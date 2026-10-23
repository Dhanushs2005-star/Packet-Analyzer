"""
Unit tests for L7 deep inspection extractors (TLS SNI, HTTP Host, DNS query, QUIC).
"""

from pathlib import Path

from packet_analyzer.inspectors import (
    DNSExtractor,
    HTTPHostExtractor,
    SNIExtractor,
)
from packet_analyzer.parser import PacketParser
from packet_analyzer.reader import NativePcapReader


def get_test_pcap_path() -> str:
    base_dir = Path(__file__).resolve().parent.parent.parent
    return str(base_dir / "test_dpi.pcap")


def test_inspectors_on_test_pcap():
    pcap_path = get_test_pcap_path()
    reader = NativePcapReader(pcap_path)

    extracted_snis = []
    extracted_hosts = []
    extracted_dns = []

    for raw in reader:
        pkt = PacketParser.parse(raw.data)
        if not pkt or not pkt.has_ip:
            continue

        if pkt.has_tcp and pkt.dest_port == 443 and pkt.payload_length > 0:
            sni = SNIExtractor.extract(pkt.payload_data)
            if sni:
                extracted_snis.append(sni)

        elif pkt.has_tcp and pkt.dest_port == 80 and pkt.payload_length > 0:
            host = HTTPHostExtractor.extract(pkt.payload_data)
            if host:
                extracted_hosts.append(host)

        elif pkt.has_udp and (pkt.dest_port == 53 or pkt.src_port == 53) and pkt.payload_length > 0:
            query = DNSExtractor.extract_query(pkt.payload_data)
            if query:
                extracted_dns.append(query)

    reader.close()

    # Verify 16 SNIs extracted from 16 TLS connections
    assert len(extracted_snis) == 16
    expected_snis = [
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "www.instagram.com",
        "twitter.com",
        "www.amazon.com",
        "www.netflix.com",
        "github.com",
        "discord.com",
        "zoom.us",
        "web.telegram.org",
        "www.tiktok.com",
        "open.spotify.com",
        "www.cloudflare.com",
        "www.microsoft.com",
        "www.apple.com",
    ]
    assert extracted_snis == expected_snis

    # Verify 2 HTTP hosts extracted
    assert len(extracted_hosts) == 2
    assert extracted_hosts == ["example.com", "httpbin.org"]

    # Verify 4 DNS queries extracted
    assert len(extracted_dns) == 4
    assert extracted_dns == [
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "api.twitter.com",
    ]
