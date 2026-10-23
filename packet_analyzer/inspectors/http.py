"""
HTTP Host Header Extractor matching HTTPHostExtractor in sni_extractor.h / sni_extractor.cpp.
"""

from __future__ import annotations

from typing import Optional


class HTTPHostExtractor:
    """Extracts Host header from plaintext HTTP requests matching C++ HTTPHostExtractor."""

    COMMON_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        prefix = payload[:4]
        return any(prefix.startswith(m) for m in cls.COMMON_METHODS)

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """
        Search for Host header in HTTP request payload and return host string (excluding port).
        Matches C++ HTTPHostExtractor::extract.
        """
        if not cls.is_http_request(payload):
            return None

        length = len(payload)
        host_header = b"host:"
        host_header_len = 5

        # Search case-insensitively for host:
        lower_payload = payload.lower()
        idx = 0
        while idx + host_header_len < length:
            pos = lower_payload.find(host_header, idx)
            if pos == -1:
                break

            # Ensure host is at start of line or preceded by newline
            if pos == 0 or payload[pos - 1] in (10, 13):  # '\n', '\r'
                start = pos + host_header_len
                # Skip spaces/tabs
                while start < length and payload[start] in (32, 9):  # ' ', '\t'
                    start += 1

                end = start
                while end < length and payload[end] not in (10, 13):
                    end += 1

                if end > start:
                    host_str = payload[start:end].decode("ascii", errors="replace").strip()
                    # Remove port if present
                    if ":" in host_str:
                        host_str = host_str.split(":", 1)[0]
                    return host_str

            idx = pos + 1

        return None
