"""The upload analyzability guard: reject stubs/truncated/unknown, pass real."""

from __future__ import annotations

import struct

from keystone_api.sniff import sniff
from keystone_api.validate import MIN_ANALYZABLE_BYTES, _elf_truncation, check_analyzable


def _elf64(*, body: int = 1024, e_shoff: int = 0, e_shnum: int = 0, e_shentsize: int = 64) -> bytes:
    """A little-endian x86-64 ELF64 header, optionally declaring a section table."""
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # ELFCLASS64
    hdr[5] = 1  # little-endian
    hdr[6] = 1  # version
    hdr[16:18] = struct.pack("<H", 2)  # e_type ET_EXEC
    hdr[18:20] = struct.pack("<H", 0x3E)  # e_machine x86-64
    hdr[40:48] = struct.pack("<Q", e_shoff)  # e_shoff
    hdr[58:60] = struct.pack("<H", e_shentsize)  # e_shentsize
    hdr[60:62] = struct.pack("<H", e_shnum)  # e_shnum
    return bytes(hdr) + b"\x00" * body


def test_rejects_unknown_format():
    reason = check_analyzable(b"\x00" * 4096, sniff(b"\x00" * 4096))
    assert reason and "unrecognized" in reason


def test_rejects_bare_header_stub():
    # exactly the 64-byte truncated ELF that triggered the report
    stub = _elf64(body=0)
    assert len(stub) == 64
    reason = check_analyzable(stub, sniff(stub))
    assert reason and "too small" in reason


def test_rejects_at_the_floor_boundary():
    data = _elf64(body=MIN_ANALYZABLE_BYTES - 64)  # length == floor
    assert len(data) == MIN_ANALYZABLE_BYTES
    assert check_analyzable(data, sniff(data)) is not None


def test_rejects_truncated_section_table():
    # a full-size file whose declared section table runs past EOF
    data = _elf64(body=512, e_shoff=100_000, e_shnum=10)
    reason = check_analyzable(data, sniff(data))
    assert reason and "section header table" in reason


def test_accepts_plausible_elf():
    data = _elf64(body=4096)  # >floor, no declared tables past EOF
    assert check_analyzable(data, sniff(data)) is None


def test_accepts_plausible_pe():
    pe = (
        b"MZ"
        + b"\x00" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * (0x80 - 0x40)
        + b"PE\x00\x00"
        + struct.pack("<H", 0x8664)
    ) + b"\x00" * 1024
    assert check_analyzable(pe, sniff(pe)) is None


def test_elf_truncation_incomplete_header():
    # reached only via the helper (the size floor catches short files first)
    assert _elf_truncation(b"\x7fELF\x02\x01") == "truncated ELF — the header itself is incomplete"


def test_elf32_truncated_section_table():
    hdr = bytearray(52)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 1  # ELFCLASS32
    hdr[5] = 1  # little-endian
    hdr[18:20] = struct.pack("<H", 0x03)  # e_machine x86
    hdr[32:36] = struct.pack("<I", 100_000)  # e_shoff past EOF
    hdr[46:48] = struct.pack("<H", 40)  # e_shentsize
    hdr[48:50] = struct.pack("<H", 3)  # e_shnum
    data = bytes(hdr) + b"\x00" * 300
    reason = check_analyzable(data, sniff(data))
    assert reason and "section header table" in reason


def test_elf_truncated_program_table():
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # ELFCLASS64
    hdr[5] = 1
    hdr[18:20] = struct.pack("<H", 0x3E)
    hdr[32:40] = struct.pack("<Q", 100_000)  # e_phoff past EOF
    hdr[54:56] = struct.pack("<H", 56)  # e_phentsize
    hdr[56:58] = struct.pack("<H", 2)  # e_phnum
    data = bytes(hdr) + b"\x00" * 300
    reason = check_analyzable(data, sniff(data))
    assert reason and "program header table" in reason


def test_pe_below_floor_rejected():
    pe = b"MZ" + b"\x00" * 100  # sniffs PE, but under the size floor
    reason = check_analyzable(pe, sniff(pe))
    assert reason and "too small" in reason
