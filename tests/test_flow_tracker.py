"""
Unit tests for flow and connection tracking.
"""

from packet_analyzer.flow_tracker import ConnectionTracker, GlobalConnectionTable
from packet_analyzer.parser import TCPFlags
from packet_analyzer.types import AppType, ConnectionState, FiveTuple, PacketAction, parse_ip


def test_connection_lifecycle():
    tracker = ConnectionTracker(fp_id=0, max_connections=10)
    t = FiveTuple(parse_ip("192.168.1.100"), parse_ip("142.250.185.206"), 54321, 443, 6)

    conn = tracker.get_or_create_connection(t)
    assert conn.state == ConnectionState.NEW
    assert tracker.get_active_count() == 1

    # Bidirectional lookup
    assert tracker.get_connection(t) is conn
    assert tracker.get_connection(t.reverse()) is conn

    # Update stats
    tracker.update_connection(conn, packet_size=100, is_outbound=True)
    assert conn.packets_out == 1
    assert conn.bytes_out == 100

    # TCP state tracking
    tracker.update_tcp_state(conn, TCPFlags.SYN)
    assert conn.syn_seen
    assert conn.state == ConnectionState.NEW

    tracker.update_tcp_state(conn, TCPFlags.SYN | TCPFlags.ACK)
    assert conn.syn_ack_seen

    tracker.update_tcp_state(conn, TCPFlags.ACK)
    assert conn.state == ConnectionState.ESTABLISHED

    # Classify
    tracker.classify_connection(conn, AppType.GOOGLE, "www.google.com")
    assert conn.state == ConnectionState.CLASSIFIED
    assert conn.app_type == AppType.GOOGLE
    assert conn.sni == "www.google.com"

    # Block
    tracker.block_connection(conn)
    assert conn.state == ConnectionState.BLOCKED
    assert conn.action == PacketAction.DROP

    # Close
    tracker.update_tcp_state(conn, TCPFlags.RST)
    assert conn.state == ConnectionState.CLOSED

    # Stale cleanup
    removed = tracker.cleanup_stale(timeout_seconds=0)
    assert removed == 1
    assert tracker.get_active_count() == 0


def test_global_connection_table():
    global_table = GlobalConnectionTable(num_fps=2)
    t0 = ConnectionTracker(fp_id=0)
    t1 = ConnectionTracker(fp_id=1)
    global_table.register_tracker(0, t0)
    global_table.register_tracker(1, t1)

    c0 = t0.get_or_create_connection(FiveTuple(1, 2, 10, 443, 6))
    t0.classify_connection(c0, AppType.YOUTUBE, "www.youtube.com")

    c1 = t1.get_or_create_connection(FiveTuple(3, 4, 20, 80, 6))
    t1.classify_connection(c1, AppType.HTTP, "example.com")

    stats = global_table.get_global_stats()
    assert stats["total_active_connections"] == 2
    assert stats["total_connections_seen"] == 2
    assert stats["app_distribution"][AppType.YOUTUBE] == 1
    assert stats["app_distribution"][AppType.HTTP] == 1

    report = global_table.generate_report()
    assert "CONNECTION STATISTICS REPORT" in report
    assert "YouTube" in report
    assert "www.youtube.com" in report
