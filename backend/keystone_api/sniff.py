"""Best-effort binary format/arch/platform sniffing from magic bytes.

Reads only — the uploaded sample is NEVER executed. Enough to label a row and
feed platform classification; deep truth comes from Ghidra."""

from __future__ import annotations

import struct

_ELF_MACHINES = {0x03: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "aarch64", 0x08: "mips"}
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "arm", 0xAA64: "aarch64"}


def sniff(data: bytes) -> dict:
    """Return {format, arch, platform} — any may be None/'unknown'."""
    if data[:4] == b"\x7fELF":
        arch = None
        if len(data) >= 20:
            little = data[5] == 1
            machine = struct.unpack("<H" if little else ">H", data[18:20])[0]
            arch = _ELF_MACHINES.get(machine)
        return {"format": "ELF", "arch": arch, "platform": "linux"}

    if data[:2] == b"MZ":
        arch = None
        if len(data) >= 0x40:
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            if len(data) >= e_lfanew + 6 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                machine = struct.unpack("<H", data[e_lfanew + 4 : e_lfanew + 6])[0]
                arch = _PE_MACHINES.get(machine)
        return {"format": "PE", "arch": arch, "platform": "windows"}

    magic = data[:4]
    if magic in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
    ):
        return {"format": "Mach-O", "arch": None, "platform": "apple"}
    if magic in (b"\xca\xfe\xba\xbe",):  # Mach-O fat (also Java class — ambiguous)
        return {"format": "Mach-O", "arch": "universal", "platform": "apple"}

    return {"format": "unknown", "arch": None, "platform": "unknown"}
