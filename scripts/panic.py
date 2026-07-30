#!/usr/bin/env python3
"""Botón de pánico: revierte el firewall/kill switch de la VPN y apaga todo,
incondicionalmente. Para cuando algo quedó a medias y querés tu PC normal ya."""

import sys

from _common import build_orchestrator, print_result


def main() -> int:
    o = build_orchestrator()
    print("[SecureCenter] PÁNICO: revirtiendo todo y apagando...")
    return print_result(o.execute(o.plan_panic(), "panic"))


if __name__ == "__main__":
    sys.exit(main())
