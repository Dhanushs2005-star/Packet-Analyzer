"""
Unit tests for filtering and rule manager.
"""

from packet_analyzer.rules import BlockReasonType, RuleManager
from packet_analyzer.types import AppType, parse_ip


def test_ip_blocking():
    rm = RuleManager()
    rm.block_ip("192.168.1.50")
    assert rm.is_ip_blocked("192.168.1.50")
    assert rm.is_ip_blocked(parse_ip("192.168.1.50"))
    assert not rm.is_ip_blocked("192.168.1.100")

    rm.unblock_ip("192.168.1.50")
    assert not rm.is_ip_blocked("192.168.1.50")


def test_app_blocking():
    rm = RuleManager()
    rm.block_app(AppType.YOUTUBE)
    rm.block_app("TikTok")
    assert rm.is_app_blocked(AppType.YOUTUBE)
    assert rm.is_app_blocked(AppType.TIKTOK)
    assert not rm.is_app_blocked(AppType.GOOGLE)

    rm.unblock_app("YouTube")
    assert not rm.is_app_blocked(AppType.YOUTUBE)


def test_domain_blocking():
    rm = RuleManager()
    rm.block_domain("facebook")
    rm.block_domain("*.tiktok.com")

    assert rm.is_domain_blocked("www.facebook.com")
    assert rm.is_domain_blocked("facebook.com")
    assert rm.is_domain_blocked("video.tiktok.com")
    assert rm.is_domain_blocked("tiktok.com")
    assert not rm.is_domain_blocked("www.google.com")


def test_combined_should_block():
    rm = RuleManager()
    rm.block_ip("192.168.1.50")
    rm.block_port(8080)
    rm.block_app(AppType.YOUTUBE)
    rm.block_domain("*.malicious.org")

    # IP match takes precedence
    reason1 = rm.should_block("192.168.1.50", 443, AppType.GOOGLE, "www.google.com")
    assert reason1 is not None
    assert reason1.type == BlockReasonType.IP

    # Port match
    reason2 = rm.should_block("192.168.1.100", 8080, AppType.UNKNOWN, "")
    assert reason2 is not None
    assert reason2.type == BlockReasonType.PORT

    # App match
    reason3 = rm.should_block("192.168.1.100", 443, AppType.YOUTUBE, "www.youtube.com")
    assert reason3 is not None
    assert reason3.type == BlockReasonType.APP

    # Domain match
    reason4 = rm.should_block("192.168.1.100", 443, AppType.HTTPS, "test.malicious.org")
    assert reason4 is not None
    assert reason4.type == BlockReasonType.DOMAIN

    # Allowed
    assert rm.should_block("192.168.1.100", 443, AppType.GOOGLE, "www.google.com") is None


def test_rules_save_and_load(tmp_path):
    rm1 = RuleManager()
    rm1.block_ip("192.168.1.50")
    rm1.block_app(AppType.YOUTUBE)
    rm1.block_domain("facebook")
    rm1.block_port(8080)

    rules_file = str(tmp_path / "rules.txt")
    assert rm1.save_rules(rules_file)

    rm2 = RuleManager()
    assert rm2.load_rules(rules_file)
    assert rm2.is_ip_blocked("192.168.1.50")
    assert rm2.is_app_blocked(AppType.YOUTUBE)
    assert rm2.is_domain_blocked("www.facebook.com")
    assert rm2.is_port_blocked(8080)
