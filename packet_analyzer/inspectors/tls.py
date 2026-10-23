"""
TLS SNI Extractor matching SNIExtractor in sni_extractor.h / sni_extractor.cpp.
"""

from __future__ import annotations

import struct
from typing import Optional


class SNIExtractor:
    """
    Parses TLS Client Hello to extract Server Name Indication (SNI).
    Direct port of C++ DPI::SNIExtractor.
    """

    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @classmethod
    def is_tls_client_hello(cls, payload: bytes) -> bool:
        """Check if payload begins with a TLS Handshake Client Hello record."""
        length = len(payload)
        if length < 9:
            return False

        # Byte 0: Content Type (should be 0x16 = Handshake)
        if payload[0] != cls.CONTENT_TYPE_HANDSHAKE:
            return False

        # Bytes 1-2: TLS Version (0x0300 through 0x0304)
        version = struct.unpack(">H", payload[1:3])[0]
        if version < 0x0300 or version > 0x0304:
            return False

        # Bytes 3-4: Record length
        record_length = struct.unpack(">H", payload[3:5])[0]
        if record_length > length - 5:
            return False

        # Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if payload[5] != cls.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """
        Extract SNI hostname from a TLS Client Hello packet payload.
        Returns the hostname string if found, otherwise None.
        """
        if not cls.is_tls_client_hello(payload):
            return None

        length = len(payload)
        # Skip TLS record header (5 bytes)
        offset = 5

        # Skip handshake header:
        # Byte 0: Handshake type (0x01)
        # Bytes 1-3: 24-bit Length
        if offset + 4 > length:
            return None
        handshake_len = (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3]
        offset += 4

        # Client Hello body:
        # Bytes 0-1: Client version (skip 2)
        # Bytes 2-33: Random 32 bytes (skip 32)
        offset += 34
        if offset >= length:
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > length:
            return None

        # Cipher suites
        cipher_suites_len = struct.unpack(">H", payload[offset : offset + 2])[0]
        offset += 2 + cipher_suites_len
        if offset >= length:
            return None

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > length:
            return None

        # Extensions
        extensions_len = struct.unpack(">H", payload[offset : offset + 2])[0]
        offset += 2

        extensions_end = min(offset + extensions_len, length)

        # Parse extensions to find SNI (0x0000)
        while offset + 4 <= extensions_end:
            ext_type, ext_data_len = struct.unpack(">HH", payload[offset : offset + 4])
            offset += 4

            if offset + ext_data_len > extensions_end:
                break

            if ext_type == cls.EXTENSION_SNI:
                # Structure:
                # SNI List Length (2 bytes)
                # SNI Type (1 byte) - 0x00 for hostname
                # SNI Length (2 bytes)
                # SNI Value (variable)
                if ext_data_len < 5:
                    break

                sni_list_len = struct.unpack(">H", payload[offset : offset + 2])[0]
                if sni_list_len < 3:
                    break

                sni_type = payload[offset + 2]
                sni_len = struct.unpack(">H", payload[offset + 3 : offset + 5])[0]

                if sni_type != cls.SNI_TYPE_HOSTNAME:
                    break
                if sni_len > ext_data_len - 5:
                    break

                hostname_bytes = payload[offset + 5 : offset + 5 + sni_len]
                try:
                    return hostname_bytes.decode("ascii")
                except UnicodeDecodeError:
                    return hostname_bytes.decode("latin1", errors="replace")

            offset += ext_data_len

        return None
