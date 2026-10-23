# DPI Engine & Packet Analyzer (Python Implementation)

A high-fidelity Python port of the C++ Deep Packet Inspection (DPI) system and Packet Analyzer. This implementation preserves the entire functional surface of the original C++ codebase while leveraging clean Python modules, strict type annotations, robust error handling, Scapy integration, and full automated test coverage.

The original C++ project in the parent directory remains **completely unmodified**.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features & C++ Mapping](#features--c-mapping)
4. [Installation & Requirements](#installation--requirements)
5. [CLI Usage Examples](#cli-usage-examples)
6. [Supported Applications & Rules](#supported-applications--rules)
7. [Testing & Verification](#testing--verification)
8. [C++ Implementation Findings & Nuances](#c-implementation-findings--nuances)
9. [Limitations & Differences](#limitations--differences)

---

## Overview

Network packets pass through layered protocol encapsulation: Ethernet (L2) → IPv4 (L3) → TCP/UDP (L4) → Application Payload (L7). Even when traffic is encrypted via TLS/HTTPS, the initial client handshake (`Client Hello`) sends the requested destination domain in plaintext within the Server Name Indication (SNI) extension.

This DPI engine inspects network streams in real time or from PCAP capture files, extracts application domains, maintains stateful connection tracking, matches customizable blocking rules, and writes allowed traffic to an output PCAP file.

```
Incoming Traffic (PCAP) ──► [ DPI Engine ] ──► Filtered Traffic (PCAP)
                                    │
                                    ├── Protocol Decoding (L2-L4)
                                    ├── Stateful Flow Tracking (TCP FSM)
                                    ├── Deep Packet Inspection (TLS SNI, HTTP Host, DNS)
                                    ├── Multi-Criteria Blocking (IP, App, Domain, Port)
                                    └── Rich Statistical Reports
```

---

## Architecture

The Python implementation mirrors both engine variants found in the C++ project:

### 1. Multi-Threaded Engine (`packet_analyzer.engine.multi_threaded`)
Faithfully ports the concurrency architecture of `dpi_mt.cpp` and `dpi_engine.cpp`:

```
                       ┌──────────────────────┐
                       │    PCAP Reader       │
                       └──────────┬───────────┘
                                  │
                                  │ hash(5-tuple) % num_lbs
                                  ▼
                    ┌────────────────────────────┐
                    │    Load Balancers (LBs)    │
                    │      LB0          LB1      │
                    └──────┬─────────────┬───────┘
                           │             │
        hash(5-tuple) % fps│             │ hash(5-tuple) % fps
                           ▼             ▼
             ┌─────────────────┐     ┌─────────────────┐
             │ Fast Paths (FP) │     │ Fast Paths (FP) │
             │   FP0     FP1   │     │   FP2     FP3   │
             └────────┬────────┘     └────────┬────────┘
                      │                       │
                      │  - L7 Inspection      │
                      │  - Connection Table   │
                      │  - Rule Matching      │
                      │                       │
                      ▼                       ▼
            [DROP (Blocked)]        [FORWARD (Allowed)]
                                              │
                                              ▼
                                  ┌───────────────────────┐
                                  │     Output Queue      │
                                  └───────────┬───────────┘
                                              │
                                              ▼
                                  ┌───────────────────────┐
                                  │  Output Writer Thread │
                                  │ (Writes filtered PCAP)│
                                  └───────────────────────┘
```

- **Consistent 5-Tuple Hashing**: Ensures all packets belonging to the same flow are routed to the same worker thread so connection state, TCP flags, and classification remain coherent without global lock contention.
- **Thread-Safe Queues**: Uses standard `queue.Queue` with timeout and graceful shutdown semantics.

### 2. Single-Threaded Engine (`packet_analyzer.engine.single_threaded`)
Faithfully ports `src/main_working.cpp` for deterministic, zero-concurrency testing and lightweight execution on small capture files.

---

## Features & C++ Mapping

| Feature | Original C++ Component | Python Module |
| :--- | :--- | :--- |
| **5-Tuple & Core Types** | `include/types.h`, `src/types.cpp` | `packet_analyzer.types` |
| **PCAP I/O** | `include/pcap_reader.h`, `src/pcap_reader.cpp` | `packet_analyzer.reader` (Native + Scapy) |
| **L2-L4 Packet Parser** | `include/packet_parser.h`, `src/packet_parser.cpp` | `packet_analyzer.parser` |
| **TLS SNI Extraction** | `include/sni_extractor.h`, `src/sni_extractor.cpp` | `packet_analyzer.inspectors.tls` |
| **HTTP Host Extraction** | `include/sni_extractor.h`, `src/sni_extractor.cpp` | `packet_analyzer.inspectors.http` |
| **DNS Query Extraction** | `include/sni_extractor.h`, `src/sni_extractor.cpp` | `packet_analyzer.inspectors.dns` |
| **QUIC Initial SNI** | `include/sni_extractor.h`, `src/sni_extractor.cpp` | `packet_analyzer.inspectors.quic` |
| **Flow & TCP State Machine** | `include/connection_tracker.h`, `src/connection_tracker.cpp` | `packet_analyzer.flow_tracker` |
| **Filtering & Rule Engine** | `include/rule_manager.h`, `src/rule_manager.cpp` | `packet_analyzer.rules` |
| **Multi-Threaded Engine** | `src/dpi_mt.cpp`, `src/dpi_engine.cpp` | `packet_analyzer.engine.multi_threaded` |
| **Single-Threaded Engine** | `src/main_working.cpp` | `packet_analyzer.engine.single_threaded` |
| **CLI Tools** | `src/main.cpp`, `src/main_dpi.cpp` | `packet_analyzer.cli` |
| **Reporting & ASCII Output**| `src/main_working.cpp`, `src/dpi_mt.cpp` | `packet_analyzer.reporting` |

---

## Installation & Requirements

### Prerequisites
- Python 3.10+
- `scapy >= 2.5.0`
- `pytest >= 7.0.0` (for testing)

### Setup Virtual Environment
```bash
# Navigate to the python-version directory
cd python-version

# Create and activate virtual environment
python -m venv .venv

# On Windows:
.\.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies and the package in editable mode
pip install -e .
```

---

## CLI Usage Examples

The package provides two primary console commands matching the C++ binaries:

### 1. `packet-analyzer` (Matches C++ `packet_analyzer`)
Decodes Ethernet, IPv4, TCP, UDP layers, and prints packet hex previews.

```bash
# Inspect all packets in a capture
packet-analyzer ../test_dpi.pcap

# Inspect only the first 5 packets
packet-analyzer ../test_dpi.pcap 5
```

### 2. `dpi-engine` (Matches C++ `dpi_engine`)
Filters network traffic according to rules using the multi-threaded or single-threaded engine.

```bash
# Basic processing (no blocking rules)
dpi-engine ../test_dpi.pcap output_allowed.pcap

# Block specific applications
dpi-engine ../test_dpi.pcap output_filtered.pcap --block-app YouTube --block-app TikTok

# Block source IP and domain patterns (with wildcard)
dpi-engine ../test_dpi.pcap output_filtered.pcap \
    --block-ip 192.168.1.50 \
    --block-domain "*.facebook.com"

# Configure multi-threaded concurrency (4 Load Balancers, 4 Fast Paths per LB = 16 worker threads)
dpi-engine ../test_dpi.pcap output_filtered.pcap --lbs 4 --fps 4

# Run in single-threaded mode (matching main_working.cpp)
dpi-engine ../test_dpi.pcap output_filtered.pcap --single-threaded --block-app YouTube

# Load rules from persistent configuration file
dpi-engine ../test_dpi.pcap output_filtered.pcap --rules rules.txt
```

---

## Supported Applications & Rules

### Application Signatures
The engine recognizes 22 application types including:
- **Google**, **YouTube**, **Facebook**, **Instagram**, **WhatsApp**, **Twitter/X**, **Netflix**, **Amazon**, **Microsoft**, **Apple**, **Telegram**, **TikTok**, **Spotify**, **Zoom**, **Discord**, **GitHub**, **Cloudflare**, and generic **HTTP**, **HTTPS**, **DNS**, **TLS**, and **QUIC**.

### Rule File Format
Rules can be persisted and loaded from text files using section headers matching the C++ INI structure:

```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
facebook
*.malicious-domain.com

[BLOCKED_PORTS]
8080
```

---

## Testing & Verification

The suite includes 22 automated unit and end-to-end integration tests covering all features and verifying parity against the original C++ capture files.

### Running Automated Tests
```bash
cd python-version
python -m pytest -v tests
```

### Verification Against C++ Sample PCAP Files
The test suite validates against `test_dpi.pcap` (77 packets) and verifies the exact 69 forwarded packets and 8 dropped packets:
1. 5 packets with source IP `192.168.1.50` dropped.
2. 1 YouTube TLS Client Hello packet dropped.
3. 1 Facebook TLS Client Hello packet dropped.
4. 1 TikTok TLS Client Hello packet dropped.

```
Total Packets:     77
Forwarded Packets: 69
Dropped Packets:    8
Total Bytes:     5738
TCP Packets:       73
UDP Packets:        4
```

---

## C++ Implementation Findings & Nuances

During the inspection and porting of the C++ codebase, the following behavioral characteristics and edge cases were identified:

1. **Twitter Substring Matching (`x.com` and `t.co`)**:
   In `src/types.cpp`, the Twitter pattern checks `"x.com"` and `"t.co"` before Netflix and Microsoft. Because `"www.netflix.com"` contains the substring `"x.com"` (`netfli` + `x.com`) and `"www.microsoft.com"` contains `"t.co"` (`microsof` + `t.co` + `m`), the C++ code classifies both domains as `TWITTER`. The Python implementation preserves this exact matching sequence to remain 100% faithful to the C++ logic.
2. **Flow Cardinality (`flows[tuple]`)**:
   In `src/main_working.cpp`, client-to-server and server-to-client packets have opposite source and destination addresses and ports. Because `main_working.cpp` indexes `flows[tuple]` directly without canonicalizing or checking `tuple.reverse()`, each bidirectional conversation generates two entries in the flow table (yielding 43 active flows on the 77-packet test capture). The Python `SingleThreadedEngine` preserves this accounting.
3. **Endianness Representation in Integer IPs**:
   The C++ `parseIP()` function shifts the first dotted octet into the lowest 8 bits (`octet << shift`), representing `192.168.1.100` as little-endian in a 32-bit integer. The Python implementation provides `parse_ip` and `format_ip` matching this exact integer layout.

---

## Limitations & Differences

1. **Raw Performance**:
   While the C++ implementation achieves millions of packets per second, Python's GIL limits CPU-bound multi-threading throughput. For very high packet rates, Python `multiprocessing` or native C extensions would be preferred. The multi-threaded pipeline here is designed for architectural fidelity to the C++ LB/FP design.
2. **Platform Dependency Free**:
   The Python implementation includes both native binary PCAP parsing and Scapy-backed PCAP parsing. It operates with zero C compiler or system library requirements across Windows, Linux, and macOS.
3. **Windows Console Encoding**:
   The CLI automatically configures standard output to UTF-8 on Windows to display Unicode box-drawing characters without encoding errors.
