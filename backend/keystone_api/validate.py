"""Upload-time analyzability guard.

Some files pass the magic-byte sniff yet Ghidra can't load them — a bare ELF/PE
header, a truncated download, an unrecognized format. Without this check they are
accepted, stored, and only fail deep in the analysis pipeline as an opaque Ghidra
500. `check_analyzable` rejects them at upload with a plain-language reason, so the
failure is immediate and actionable and no junk row is created.

Reads only — the sample is never executed."""

from __future__ import annotations

import struct

# An ELF64 header alone is 64 bytes and a PE's headers a few hundred; a real
# program is far larger. Anything at/below this is a header stub, not a binary.
MIN_ANALYZABLE_BYTES = 256


def check_analyzable(data: bytes, info: dict) -> str | None:
    """Return a human-readable reason the file can't be analyzed, or None if it
    looks loadable. `info` is the output of `sniff.sniff`."""
    fmt = info.get("format")
    if fmt in (None, "unknown"):
        return (
            "unrecognized format — Keystone analyzes ELF, PE, or Mach-O binaries, "
            "and this file matches none of them"
        )
    if len(data) <= MIN_ANALYZABLE_BYTES:
        return (
            f"only {len(data)} bytes — too small to be a real program "
            "(this looks like a bare header or a truncated stub)"
        )
    if fmt == "ELF":
        return _elf_truncation(data)
    return None


def _elf_truncation(data: bytes) -> str | None:
    """For ELF, verify the program/section header tables the file declares actually
    lie within the file. A truncated binary declares tables that run past EOF."""
    if len(data) < 64:
        return "truncated ELF — the header itself is incomplete"
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    try:
        if is64:
            e_phoff = struct.unpack(end + "Q", data[32:40])[0]
            e_shoff = struct.unpack(end + "Q", data[40:48])[0]
            e_phentsize, e_phnum = struct.unpack(end + "HH", data[54:58])
            e_shentsize, e_shnum = struct.unpack(end + "HH", data[58:62])
        else:
            e_phoff = struct.unpack(end + "I", data[28:32])[0]
            e_shoff = struct.unpack(end + "I", data[32:36])[0]
            e_phentsize, e_phnum = struct.unpack(end + "HH", data[42:46])
            e_shentsize, e_shnum = struct.unpack(end + "HH", data[46:50])
    except struct.error:
        return "malformed ELF header"
    if e_phnum and e_phoff + e_phnum * e_phentsize > len(data):
        return "truncated ELF — the program header table extends past the end of the file"
    if e_shnum and e_shoff + e_shnum * e_shentsize > len(data):
        return "truncated ELF — the section header table extends past the end of the file"
    return None
