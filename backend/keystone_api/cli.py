"""Management CLI: `python -m keystone_api.cli [bootstrap|seed|prune-binaries]`."""

from __future__ import annotations

import argparse
import sys

from . import services
from .db import init_db, session_scope


def _prune(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="prune-binaries", description="Delete binaries + all attached rows/objects/files.")
    sel = p.add_mutually_exclusive_group(required=True)
    sel.add_argument(
        "--max-bytes", type=int, metavar="N", help="delete binaries with size <= N (e.g. 256 for stubs)"
    )
    sel.add_argument(
        "--id", type=int, action="append", dest="ids", metavar="ID", help="delete this binary id (repeatable)"
    )
    p.add_argument("--dry-run", action="store_true", help="show what would be deleted; change nothing")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = p.parse_args(argv)

    from .config import get_settings
    from .prune import prune_binaries
    from .storage import get_object_store

    sample_dir = get_settings().sample_dir
    store = get_object_store()
    with session_scope() as s:
        preview = prune_binaries(
            s, store, sample_dir, max_bytes=args.max_bytes, ids=args.ids, dry_run=True
        )
        if not preview["matched"]:
            print("no binaries match — nothing to do")
            return 0
        for m in preview["matched"]:
            print(f"  #{m['id']} {m['filename']} ({m['size']} B)")
        print(f"-> {preview['binaries']} binaries + {preview['analyses']} analyses")
        if args.dry_run:
            return 0
        if not args.yes:
            reply = input("delete these? [y/N] ").strip().lower()
            if reply != "y":
                print("aborted")
                return 1
        result = prune_binaries(s, store, sample_dir, max_bytes=args.max_bytes, ids=args.ids)
    print(
        f"deleted {result['binaries']} binaries, {result['analyses']} analyses, "
        f"{result['objects']} objects, {result['samples']} sample files"
    )
    return 0


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
    if cmd == "prune-binaries":
        return _prune(argv[1:])

    print("usage: python -m keystone_api.cli [bootstrap|seed|prune-binaries]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
