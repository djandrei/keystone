"""Management CLI: `python -m keystone_api.cli [bootstrap|seed]`."""
from __future__ import annotations

import sys

from . import services
from .db import init_db, session_scope


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    init_db()

    if cmd == "bootstrap":
        with session_scope() as s:
            print(services.bootstrap(s))
        return 0
    if cmd == "seed":
        with session_scope() as s:
            services.seed_demo(s)
        print("seeded")
        return 0

    print("usage: python -m keystone_api.cli [bootstrap|seed]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
