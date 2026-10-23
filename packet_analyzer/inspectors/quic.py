"""
QUIC Initial packet SNI Extractor matching QUICSNIExtractor in sni_extractor.h / sni_extractor.cpp.
"""

from __future__ import annotations

from typing import Optional
from .tls import SNIExtractor


class QUICSNIExtractor:
    """Extracts SNI from QUIC Initial packets (simplified search matching C++)."""

    @classmethod
    def is_quic_initial(cls, payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        # Long header form has bit 7 set
        first_byte = payload[0]
        return (first_byte & 0x80) != 0

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """Search for embedded TLS Client Hello within QUIC payload."""
        if not cls.is_quic_initial(payload):
            return None

        # Search for Client Hello handshake pattern (type 0x01)
        length = len(payload)
        for i in range(5, length - 50):
            if payload[i] == 0x01:  # Client Hello
                candidate = payload[i - 5 :]
                res = SNIExtractor.extract(candidate)
                if res:
                    return res
        return None
