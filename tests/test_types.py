"""
Unit tests for packet_analyzer/types.py
"""

from packet_analyzer.types import (
    FiveTuple,
    AppType,
    parse_ip,
    format_ip,
    app_type_to_string,
    string_to_app_type,
    sni_to_app_type,
)


def test_ip_parse_and_format():
    ip_str = "192.168.1.100"
    ip_val = parse_ip(ip_str)
    # 192 | (168 << 8) | (1 << 16) | (100 << 24)
    expected = 192 | (168 << 8) | (1 << 16) | (100 << 24)
    assert ip_val == expected
    assert format_ip(ip_val) == ip_str


def test_five_tuple_reverse():
    t1 = FiveTuple(
        src_ip=parse_ip("192.168.1.100"),
        dst_ip=parse_ip("142.250.185.206"),
        src_port=54321,
        dst_port=443,
        protocol=6,
    )
    t2 = t1.reverse()
    assert t2.src_ip == t1.dst_ip
    assert t2.dst_ip == t1.src_ip
    assert t2.src_port == t1.dst_port
    assert t2.dst_port == t1.src_port
    assert t2.protocol == t1.protocol
    assert "192.168.1.100:54321 -> 142.250.185.206:443 (TCP)" in str(t1)


def test_five_tuple_hash():
    t1 = FiveTuple(parse_ip("192.168.1.100"), parse_ip("142.250.185.206"), 54321, 443, 6)
    t2 = FiveTuple(parse_ip("192.168.1.100"), parse_ip("142.250.185.206"), 54321, 443, 6)
    assert t1 == t2
    assert hash(t1) == hash(t2)
    assert t1.c_hash() == t2.c_hash()
    assert isinstance(t1.c_hash(), int)


def test_sni_to_app_type():
    assert sni_to_app_type("www.google.com") == AppType.GOOGLE
    assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE
    assert sni_to_app_type("m.facebook.com") == AppType.FACEBOOK
    assert sni_to_app_type("instagram.com") == AppType.INSTAGRAM
    assert sni_to_app_type("web.whatsapp.com") == AppType.WHATSAPP
    assert sni_to_app_type("twitter.com") == AppType.TWITTER
    assert sni_to_app_type("x.com") == AppType.TWITTER
    # Note: In C++ src/types.cpp, the Twitter pattern checks "x.com" and "t.co"
    # before Netflix and Microsoft. Because "www.netflix.com" contains "x.com"
    # and "www.microsoft.com" contains "t.co", C++ classifies both as TWITTER.
    assert sni_to_app_type("www.netflix.com") == AppType.TWITTER
    assert sni_to_app_type("nflxvideo.net") == AppType.NETFLIX
    assert sni_to_app_type("netflix.org") == AppType.NETFLIX
    assert sni_to_app_type("aws.amazon.com") == AppType.AMAZON
    assert sni_to_app_type("www.microsoft.com") == AppType.TWITTER
    assert sni_to_app_type("azure.net") == AppType.MICROSOFT
    assert sni_to_app_type("office.net") == AppType.MICROSOFT
    assert sni_to_app_type("icloud.com") == AppType.APPLE
    assert sni_to_app_type("t.me") == AppType.TELEGRAM
    assert sni_to_app_type("tiktok.com") == AppType.TIKTOK
    assert sni_to_app_type("open.spotify.com") == AppType.SPOTIFY
    assert sni_to_app_type("zoom.us") == AppType.ZOOM
    assert sni_to_app_type("discord.com") == AppType.DISCORD
    assert sni_to_app_type("github.com") == AppType.GITHUB
    assert sni_to_app_type("www.cloudflare.com") == AppType.CLOUDFLARE
    assert sni_to_app_type("unknown-site.org") == AppType.HTTPS
    assert sni_to_app_type("") == AppType.UNKNOWN


def test_app_type_to_string_and_reverse():
    assert app_type_to_string(AppType.YOUTUBE) == "YouTube"
    assert app_type_to_string(AppType.FACEBOOK) == "Facebook"
    assert string_to_app_type("YouTube") == AppType.YOUTUBE
    assert string_to_app_type("youtube") == AppType.YOUTUBE
    assert string_to_app_type("NonExistent") is None
