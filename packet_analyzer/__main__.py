"""
Main module entry point for packet_analyzer package.
"""

import sys
from .cli import run_dpi_engine, run_packet_analyzer


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        sys.exit(run_packet_analyzer(sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == "dpi":
        sys.exit(run_dpi_engine(sys.argv[2:]))
    else:
        # Default to dpi engine
        sys.exit(run_dpi_engine(sys.argv[1:]))


if __name__ == "__main__":
    main()
