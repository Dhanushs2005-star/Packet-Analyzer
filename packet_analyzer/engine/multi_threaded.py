"""
Multi-threaded concurrent DPI Engine.
Faithfully porting src/dpi_mt.cpp and include/dpi_engine.h / src/dpi_engine.cpp.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ..inspectors import HTTPHostExtractor, SNIExtractor
from ..parser import PacketParser
from ..reader import NativePcapReader, NativePcapWriter, RawPacket
from ..reporting import generate_mt_report
from ..rules import RuleManager
from ..types import (
    AppType,
    FiveTuple,
    parse_ip,
    sni_to_app_type,
)


@dataclass
class PacketItem:
    """Internal packet job passed between thread queues."""
    id: int
    raw: RawPacket
    tuple: FiveTuple
    tcp_flags: int
    has_tcp: bool
    has_udp: bool
    payload_data: bytes
    payload_length: int


@dataclass
class FlowEntry:
    """Flow state maintained by FastPath worker threads."""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


class EngineStats:
    """Thread-safe statistics tracking across workers."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_counts: dict[AppType, int] = {}
        self.detected_snis: dict[str, AppType] = {}

    def record_app(self, app: AppType, sni: str = "") -> None:
        with self._lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app

    def inc_forwarded(self) -> None:
        with self._lock:
            self.forwarded += 1

    def inc_dropped(self) -> None:
        with self._lock:
            self.dropped += 1


class FastPathWorker:
    """Fast Path processor thread matching FastPath in dpi_mt.cpp."""

    def __init__(
        self,
        fp_id: int,
        rules: RuleManager,
        stats: EngineStats,
        output_queue: queue.Queue,
        queue_size: int = 10000,
    ):
        self.fp_id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.flows: dict[FiveTuple, FlowEntry] = {}
        self.processed = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self._thread = threading.Thread(target=self._run, name=f"FP-{self.fp_id}")
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        self.input_queue.put(None)  # Sentinel
        if self._thread and self._thread.is_alive():
            self._thread.join()

    def _classify_flow(self, item: PacketItem, flow: FlowEntry) -> None:
        # TLS SNI
        if item.tuple.dst_port == 443 and item.payload_length > 5:
            sni = SNIExtractor.extract(item.payload_data)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        # HTTP Host
        if item.tuple.dst_port == 80 and item.payload_length > 0:
            host = HTTPHostExtractor.extract(item.payload_data)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        # DNS
        if item.tuple.dst_port == 53 or item.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        # Fallback
        if item.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif item.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP

    def _run(self) -> None:
        while self.running or not self.input_queue.empty():
            try:
                item = self.input_queue.get(timeout=0.05)
            except queue.Empty:
                continue

            if item is None:
                break

            self.processed += 1
            flow = self.flows.get(item.tuple)
            if flow is None:
                flow = FlowEntry(tuple=item.tuple)
                self.flows[item.tuple] = flow

            flow.packets += 1
            flow.bytes += len(item.raw.data)

            if not flow.classified:
                self._classify_flow(item, flow)

            if not flow.blocked:
                flow.blocked = (
                    self.rules.is_ip_blocked(item.tuple.src_ip)
                    or self.rules.is_app_blocked(flow.app_type)
                    or (bool(flow.sni) and self.rules.is_domain_blocked(flow.sni))
                )

            self.stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self.stats.inc_dropped()
            else:
                self.stats.inc_forwarded()
                self.output_queue.put(item.raw)

            self.input_queue.task_done()


class LoadBalancerWorker:
    """Load balancer thread distributing packets to FP workers matching LoadBalancer in dpi_mt.cpp."""

    def __init__(
        self,
        lb_id: int,
        fps: list[FastPathWorker],
        queue_size: int = 10000,
    ):
        self.lb_id = lb_id
        self.fps = fps
        self.num_fps = len(fps)
        self.input_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.dispatched = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self._thread = threading.Thread(target=self._run, name=f"LB-{self.lb_id}")
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        self.input_queue.put(None)  # Sentinel
        if self._thread and self._thread.is_alive():
            self._thread.join()

    def _run(self) -> None:
        while self.running or not self.input_queue.empty():
            try:
                item = self.input_queue.get(timeout=0.05)
            except queue.Empty:
                continue

            if item is None:
                break

            fp_idx = item.tuple.c_hash() % self.num_fps
            self.fps[fp_idx].input_queue.put(item)
            self.dispatched += 1
            self.input_queue.task_done()


class MultiThreadedEngine:
    """
    Multi-threaded DPI Engine with consistent 5-tuple hash distribution:
    Reader -> LB Threads -> FP Threads -> Output Writer Thread.
    Faithfully ports dpi_mt.cpp and dpi_engine.cpp.
    """

    def __init__(
        self,
        num_lbs: int = 2,
        fps_per_lb: int = 2,
        rules: Optional[RuleManager] = None,
        queue_size: int = 10000,
    ):
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.total_fps = num_lbs * fps_per_lb
        self.rules = rules or RuleManager()
        self.queue_size = queue_size
        self.stats = EngineStats()
        self.output_queue: queue.Queue = queue.Queue(maxsize=queue_size)

        # Create FP workers
        self.fps: list[FastPathWorker] = [
            FastPathWorker(
                fp_id=i,
                rules=self.rules,
                stats=self.stats,
                output_queue=self.output_queue,
                queue_size=queue_size,
            )
            for i in range(self.total_fps)
        ]

        # Create LB workers
        self.lbs: list[LoadBalancerWorker] = []
        for lb in range(num_lbs):
            start = lb * fps_per_lb
            lb_fps = self.fps[start : start + fps_per_lb]
            self.lbs.append(LoadBalancerWorker(lb_id=lb, fps=lb_fps, queue_size=queue_size))

    def process(
        self,
        input_file: str,
        output_file: str,
        verbose: bool = False,
        log_stream=sys.stdout,
    ) -> dict:
        """Process input PCAP concurrently and write output PCAP."""
        reader = NativePcapReader(input_file)
        writer = NativePcapWriter(output_file, snaplen=reader.global_header.snaplen)

        # Start FP and LB workers
        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_running = [True]

        def _output_writer():
            while output_running[0] or not self.output_queue.empty():
                try:
                    raw = self.output_queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                if raw is None:
                    break
                writer.write_raw_packet(raw)
                self.output_queue.task_done()

        writer_thread = threading.Thread(target=_output_writer, name="OutputWriter")
        writer_thread.start()

        # Reader loop
        pkt_id = 0
        try:
            for raw in reader:
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

                item = PacketItem(
                    id=pkt_id,
                    raw=raw,
                    tuple=tuple_,
                    tcp_flags=pkt.tcp_flags,
                    has_tcp=pkt.has_tcp,
                    has_udp=pkt.has_udp,
                    payload_data=pkt.payload_data,
                    payload_length=pkt.payload_length,
                )
                pkt_id += 1

                self.stats.total_packets += 1
                self.stats.total_bytes += len(raw.data)
                if pkt.has_tcp:
                    self.stats.tcp_packets += 1
                elif pkt.has_udp:
                    self.stats.udp_packets += 1

                # Consistent hash dispatch to LB
                lb_idx = tuple_.c_hash() % self.num_lbs
                self.lbs[lb_idx].input_queue.put(item)

        finally:
            reader.close()

            # Drain LBs
            for lb in self.lbs:
                lb.stop()

            # Drain FPs
            for fp in self.fps:
                fp.stop()

            # Stop output writer
            output_running[0] = False
            self.output_queue.put(None)
            writer_thread.join()
            writer.close()

        lb_dispatched = [lb.dispatched for lb in self.lbs]
        fp_processed = [fp.processed for fp in self.fps]

        report = generate_mt_report(
            total_packets=self.stats.total_packets,
            total_bytes=self.stats.total_bytes,
            tcp_packets=self.stats.tcp_packets,
            udp_packets=self.stats.udp_packets,
            forwarded=self.stats.forwarded,
            dropped=self.stats.dropped,
            lb_dispatched=lb_dispatched,
            fp_processed=fp_processed,
            app_counts=self.stats.app_counts,
            detected_snis=self.stats.detected_snis,
        )

        return {
            "total_packets": self.stats.total_packets,
            "total_bytes": self.stats.total_bytes,
            "tcp_packets": self.stats.tcp_packets,
            "udp_packets": self.stats.udp_packets,
            "forwarded": self.stats.forwarded,
            "dropped": self.stats.dropped,
            "lb_dispatched": lb_dispatched,
            "fp_processed": fp_processed,
            "app_counts": self.stats.app_counts,
            "detected_snis": self.stats.detected_snis,
            "report": report,
        }
