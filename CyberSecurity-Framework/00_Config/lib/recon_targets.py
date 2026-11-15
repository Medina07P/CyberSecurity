"""Parse ping-sweep targets into concrete destination IPs.

No I/O: this module only validates and expands target expressions.
"""
from __future__ import annotations

import sys
from typing import Tuple


def _clean(value: str) -> bool:
    if not isinstance(value, str) or value == "":
        return False
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7f or ord(ch) > 0x7e:
            return False
    return True


def _valid_octet(token: str) -> bool:
    if not _clean(token):
        return False
    if not token.isdigit():
        return False
    if len(token) > 1 and token[0] == "0":
        return False
    try:
        number = int(token)
    except ValueError:
        return False
    return 0 <= number <= 255


def _valid_range_part(token: str) -> bool:
    return _valid_octet(token)


def parse_ping_targets(network: str, range_text: str = "1-254") -> Tuple[str, ...]:
    if not _clean(network):
        raise ValueError("invalid network")
    if network.startswith("-") or network.startswith("+"):
        raise ValueError("invalid network")

    # /24 form: four octets followed by /24.
    if "/" in network:
        slash_parts = network.split("/")
        if len(slash_parts) != 2:
            raise ValueError("invalid network")
        left, suffix = slash_parts
        if suffix != "24":
            raise ValueError("invalid network")
        octets = left.split(".")
        if len(octets) != 4 or not all(_valid_octet(o) for o in octets):
            raise ValueError("invalid network")
        base = ".".join(octets[:3])
        return _expand_range(base, range_text)

    octets = network.split(".")
    # Single IP: four octets. Range is ignored.
    if len(octets) == 4:
        if not all(_valid_octet(o) for o in octets):
            raise ValueError("invalid network")
        return (network,)

    # Prefix: three octets.
    if len(octets) == 3:
        if not all(_valid_octet(o) for o in octets):
            raise ValueError("invalid network")
        base = ".".join(octets)
        return _expand_range(base, range_text)

    # Two octets or anything else is rejected.
    raise ValueError("invalid network")


def _expand_range(base: str, range_text: str) -> Tuple[str, ...]:
    if not _clean(range_text):
        raise ValueError("invalid range")
    if range_text.startswith("-") or range_text.startswith("+"):
        raise ValueError("invalid range")
    if range_text.count("-") != 1:
        raise ValueError("invalid range")
    left, right = range_text.split("-")
    if not _valid_range_part(left) or not _valid_range_part(right):
        raise ValueError("invalid range")
    start = int(left)
    end = int(right)
    if start > end:
        raise ValueError("invalid range")
    return tuple(f"{base}.{i}" for i in range(start, end + 1))


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        print("Uso: recon_targets.py <red> [rango]", file=sys.stderr)
        return 2
    network = argv[0]
    range_text = argv[1] if len(argv) == 2 else "1-254"
    try:
        destinations = parse_ping_targets(network, range_text)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for destination in destinations:
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
