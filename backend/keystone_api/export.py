"""Report export: Markdown, a JSON bundle, and a dependency-free minimal PDF.

The PDF writer emits a valid single-page Type1/Courier document — enough to hand a
reviewer a portable artifact without pulling in a heavy PDF toolchain."""

from __future__ import annotations

import json


def report_json_bundle(
    analysis: dict, re_result: dict | None, findings: list[dict], report_md: str
) -> bytes:
    bundle = {
        "analysis": analysis,
        "re_result": re_result,
        "findings": findings,
        "report_markdown": report_md,
    }
    return json.dumps(bundle, indent=2).encode("utf-8")


def _escape_pdf_text(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def text_to_pdf(text: str, *, max_lines: int = 58, width: int = 95) -> bytes:
    """Render text as a valid single-page PDF (Courier 10pt). Long content is
    wrapped and clipped to one page — a portable summary, not a typesetter."""
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw:
            lines.append("")
            continue
        while raw:
            lines.append(raw[:width])
            raw = raw[width:]
    lines = lines[:max_lines] or [""]

    content = ["BT", "/F1 10 Tf", "50 740 Td", "12 TL"]
    for i, line in enumerate(lines):
        content.append(f"({_escape_pdf_text(line)}) Tj")
        if i < len(lines) - 1:
            content.append("T*")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1", "replace")

    objects: list[bytes] = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
        b"/Resources<</Font<</F1 5 0 R>>>>>>",
        b"<</Length " + str(len(stream)).encode() + b">>\nstream\n" + stream + b"\nendstream",
        b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"

    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<</Size {len(objects) + 1}/Root 1 0 R>>\nstartxref\n{xref_pos}\n%%EOF".encode()
    )
    return bytes(out)
