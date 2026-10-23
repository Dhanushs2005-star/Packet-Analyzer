"""
PCAP Reader and Writer modules.
Supports both Scapy-backed operations and native binary parsing matching C++ pcap_reader.cpp.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

import scapy.utils


# PCAP Magic numbers
PCAP_MAGIC_NATIVE = 0xA1B2C3D4  # Native byte order
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1  # Swapped byte order


@dataclass(slots=True)
class PcapGlobalHeader:
    """PCAP Global Header (24 bytes) matching struct PcapGlobalHeader in pcap_reader.h."""
    magic_number: int = PCAP_MAGIC_NATIVE
    version_major: int = 2
    version_minor: int = 4
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 65535
    network: int = 1  # 1 = Ethernet


@dataclass(slots=True)
class PcapPacketHeader:
    """PCAP Packet Header (16 bytes) matching struct PcapPacketHeader in pcap_reader.h."""
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass(slots=True)
class RawPacket:
    """Raw packet matching struct RawPacket in pcap_reader.h."""
    header: PcapPacketHeader
    data: bytes


class NativePcapReader:
    """
    Direct binary PCAP reader matching the exact behavior of C++ PcapReader.
    Handles native and swapped endianness without any external dependencies.
    """

    def __init__(self, filename: Optional[str] = None):
        self.filename = filename
        self._file = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self.needs_byte_swap = False
        if filename:
            self.open(filename)

    def open(self, filename: str) -> bool:
        self.close()
        self.filename = filename
        try:
            self._file = open(filename, "rb")
            gh_data = self._file.read(24)
            if len(gh_data) < 24:
                self.close()
                return False

            magic = struct.unpack("=I", gh_data[0:4])[0]
            if magic == PCAP_MAGIC_NATIVE:
                endian = "="
                self.needs_byte_swap = False
            elif magic == PCAP_MAGIC_SWAPPED:
                # Swapped endianness
                endian = ">" if struct.unpack("=I", b"\x01\x00\x00\x00")[0] == 1 else "<"
                self.needs_byte_swap = True
            else:
                self.close()
                raise ValueError(f"Invalid PCAP magic number: 0x{magic:08x}")

            magic, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack(
                f"{endian}IHHiIII", gh_data
            )
            self.global_header = PcapGlobalHeader(
                magic_number=magic,
                version_major=v_maj,
                version_minor=v_min,
                thiszone=thiszone,
                sigfigs=sigfigs,
                snaplen=snaplen,
                network=network,
            )
            self._endian = endian
            return True
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None

    def __enter__(self) -> NativePcapReader:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read next packet, returns None on EOF."""
        if not self._file or self._file.closed:
            return None

        ph_data = self._file.read(16)
        if len(ph_data) < 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self._endian}IIII", ph_data)
        if incl_len > (self.global_header.snaplen if self.global_header else 65535) or incl_len > 65535:
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            return None

        header = PcapPacketHeader(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
        )
        return RawPacket(header=header, data=data)

    def __iter__(self) -> Iterator[RawPacket]:
        while True:
            pkt = self.read_next_packet()
            if pkt is None:
                break
            yield pkt


class NativePcapWriter:
    """
    Direct binary PCAP writer matching C++ output writing.
    Writes standard 24-byte global header followed by 16-byte packet headers and payload.
    """

    def __init__(self, filename: str, snaplen: int = 65535, network: int = 1):
        self.filename = filename
        self.snaplen = snaplen
        self.network = network
        self._file = open(filename, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        gh = struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_NATIVE,
            2,
            4,
            0,
            0,
            self.snaplen,
            self.network,
        )
        self._file.write(gh)

    def write_packet(self, data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> None:
        pkt_len = len(data)
        ph = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self._file.write(ph)
        self._file.write(data)

    def write_raw_packet(self, packet: RawPacket) -> None:
        self.write_packet(packet.data, packet.header.ts_sec, packet.header.ts_usec)

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    def __enter__(self) -> NativePcapWriter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class ScapyPcapReader:
    """Scapy-backed PCAP reader."""

    def __init__(self, filename: str):
        self.filename = filename
        self._reader = scapy.utils.PcapReader(filename)

    def __iter__(self):
        return iter(self._reader)

    def close(self) -> None:
        self._reader.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class ScapyPcapWriter:
    """Scapy-backed PCAP writer."""

    def __init__(self, filename: str, append: bool = False, sync: bool = False):
        self.filename = filename
        self._writer = scapy.utils.PcapWriter(filename, append=append, sync=sync)

    def write(self, pkt) -> None:
        self._writer.write(pkt)

    def close(self) -> None:
        self._writer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
