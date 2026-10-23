"""
DNS Query Extractor matching DNSExtractor in sni_extractor.h / sni_extractor.cpp.
"""

from __future__ import annotations

import struct
from typing import Optional


class DNSExtractor:
    """Extracts queried domain names from DNS request payloads."""

    @classmethod
    def is_dns_query(cls, payload: bytes) -> bool:
        if len(payload) < 12:
            return False

        # Byte 2 bit 7 is QR (0 for query, 1 for response)
        flags = payload[2]
        if (flags & 0x80) != 0:
            return False

        # QDCOUNT (bytes 4-5) should be > 0
        qdcount = struct.unpack(">H", payload[4:6])[0]
        return qdcount > 0

    @classmethod
    def extract_query(cls, payload: bytes) -> Optional[str]:
        """
        Extract the first queried domain from DNS query payload.
        Matches C++ DNSExtractor::extractQuery.
        """
        if not cls.is_dns_query(payload):
            return None

        offset = 12
        length = len(payload)
        labels = []

        while offset < length:
            label_len = payload[offset]
            if label_len == 0:
                break
            if label_len > 63:
                # Compression pointer or invalid
                break

            offset += 1
            if offset + label_len > length:
                break

            label = payload[offset : offset + label_len].decode("ascii", errors="replace")
            labels.append(label)
            offset += label_len

        if not labels:
            return None
        return ".".join(labels)
