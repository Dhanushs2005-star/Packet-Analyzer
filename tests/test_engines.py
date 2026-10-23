"""
Unit and integration tests for SingleThreadedEngine and MultiThreadedEngine.
"""

from pathlib import Path

from packet_analyzer.engine.multi_threaded import MultiThreadedEngine
from packet_analyzer.engine.single_threaded import SingleThreadedEngine
from packet_analyzer.reader import NativePcapReader
from packet_analyzer.rules import RuleManager
from packet_analyzer.types import AppType


def get_test_pcap_path() -> str:
    base_dir = Path(__file__).resolve().parent.parent.parent
    return str(base_dir / "test_dpi.pcap")


def test_single_threaded_engine_filtering(tmp_path):
    pcap_path = get_test_pcap_path()
    out_path = str(tmp_path / "out_st.pcap")

    rules = RuleManager()
    rules.block_ip("192.168.1.50")
    rules.block_app(AppType.YOUTUBE)
    rules.block_app(AppType.TIKTOK)
    rules.block_domain("facebook")

    engine = SingleThreadedEngine(rules=rules)
    res = engine.process(pcap_path, out_path)

    assert res["total_packets"] == 77
    assert res["dropped"] == 8
    assert res["forwarded"] == 69
    # 16 TLS connections * 2 directions (32) + 2 HTTP (2) + 4 DNS (4) + 5 random port blocked IP (5) = 43 flows
    assert res["active_flows"] == 43

    # Verify output PCAP has 69 packets
    with NativePcapReader(out_path) as r:
        pkts = list(r)
        assert len(pkts) == 69


def test_multi_threaded_engine_filtering(tmp_path):
    pcap_path = get_test_pcap_path()
    out_path = str(tmp_path / "out_mt.pcap")

    rules = RuleManager()
    rules.block_ip("192.168.1.50")
    rules.block_app(AppType.YOUTUBE)
    rules.block_app(AppType.TIKTOK)
    rules.block_domain("facebook")

    engine = MultiThreadedEngine(num_lbs=2, fps_per_lb=2, rules=rules)
    res = engine.process(pcap_path, out_path)

    assert res["total_packets"] == 77
    assert res["dropped"] == 8
    assert res["forwarded"] == 69

    # Verify LBs dispatched all 77 packets
    assert sum(res["lb_dispatched"]) == 77
    # Verify FPs processed all 77 packets
    assert sum(res["fp_processed"]) == 77

    # Verify output PCAP has 69 packets
    with NativePcapReader(out_path) as r:
        pkts = list(r)
        assert len(pkts) == 69
