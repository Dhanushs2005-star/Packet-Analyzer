"""
End-to-end tests comparing Python output with C++ behavior and reference output.pcap.
"""

from pathlib import Path

from packet_analyzer.engine.multi_threaded import MultiThreadedEngine
from packet_analyzer.engine.single_threaded import SingleThreadedEngine
from packet_analyzer.inspectors import SNIExtractor
from packet_analyzer.parser import PacketParser
from packet_analyzer.reader import NativePcapReader
from packet_analyzer.rules import RuleManager
from packet_analyzer.types import AppType


def test_end_to_end_verification_against_reference(tmp_path):
    base_dir = Path(__file__).resolve().parent.parent.parent
    test_pcap = str(base_dir / "test_dpi.pcap")
    ref_output_pcap = str(base_dir / "output.pcap")

    # Read original reference output.pcap
    with NativePcapReader(ref_output_pcap) as ref_reader:
        ref_packets = list(ref_reader)
    assert len(ref_packets) == 69, "Reference output.pcap must contain 69 packets"

    # Run SingleThreadedEngine
    st_out = str(tmp_path / "st_out.pcap")
    rules = RuleManager()
    rules.block_ip("192.168.1.50")
    rules.block_app(AppType.YOUTUBE)
    rules.block_app(AppType.TIKTOK)
    rules.block_domain("facebook")

    st_engine = SingleThreadedEngine(rules=rules)
    st_res = st_engine.process(test_pcap, st_out)

    assert st_res["total_packets"] == 77
    assert st_res["dropped"] == 8
    assert st_res["forwarded"] == 69

    # Run MultiThreadedEngine
    mt_out = str(tmp_path / "mt_out.pcap")
    mt_engine = MultiThreadedEngine(num_lbs=2, fps_per_lb=2, rules=rules)
    mt_res = mt_engine.process(test_pcap, mt_out)

    assert mt_res["total_packets"] == 77
    assert mt_res["dropped"] == 8
    assert mt_res["forwarded"] == 69

    # Inspect generated output PCAP packets
    with NativePcapReader(st_out) as out_reader:
        out_packets = list(out_reader)
    assert len(out_packets) == 69

    # Verify blocked items are nowhere in the output PCAP
    for raw in out_packets:
        pkt = PacketParser.parse(raw.data)
        assert pkt is not None
        # Verify 192.168.1.50 is blocked
        assert pkt.src_ip != "192.168.1.50"

        # Verify SNI for YouTube, Facebook, TikTok are blocked
        if pkt.has_tcp and pkt.dest_port == 443 and pkt.payload_length > 5:
            sni = SNIExtractor.extract(pkt.payload_data)
            if sni:
                assert "youtube" not in sni
                assert "facebook" not in sni
                assert "tiktok" not in sni


def test_cli_execution_end_to_end(tmp_path):
    from packet_analyzer.cli import run_dpi_engine, run_packet_analyzer

    base_dir = Path(__file__).resolve().parent.parent.parent
    test_pcap = str(base_dir / "test_dpi.pcap")
    out_file = str(tmp_path / "cli_out.pcap")

    # Run packet-analyzer CLI
    ret_analyzer = run_packet_analyzer([test_pcap, "5"])
    assert ret_analyzer == 0

    # Run dpi-engine CLI
    ret_engine = run_dpi_engine([
        test_pcap,
        out_file,
        "--block-app", "YouTube",
        "--block-app", "TikTok",
        "--block-ip", "192.168.1.50",
        "--block-domain", "facebook",
    ])
    assert ret_engine == 0

    with NativePcapReader(out_file) as reader:
        assert len(list(reader)) == 69
