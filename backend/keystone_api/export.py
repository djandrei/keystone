"""Report export: Markdown, a JSON bundle, and a dependency-free minimal PDF.

The PDF writer emits a valid multi-page Type1/Courier document — enough to hand a
reviewer a portable artifact without pulling in a heavy PDF toolchain."""

from __future__ import annotations

import json


def report_json_bundle(
    analysis: dict,
    re_result: dict | None,
    findings: list[dict],
    report_md: str,
    rule_sets: list[dict] | None = None,
    functions: list[dict] | None = None,
) -> bytes:
    bundle = {
        "analysis": analysis,
        "re_result": re_result,
        "findings": findings,
        "report_markdown": report_md,
        # The rule set versions this analysis ran, each with its attribution.
        # An exported bundle is a redistributed artifact; the credit goes with it.
        "rule_sets": rule_sets or [],
        # The functions the analyst chose to show, as structured data.
        "functions": functions or [],
    }
    return json.dumps(bundle, indent=2).encode("utf-8")


def functions_section(functions: list[dict]) -> str:
    """A Markdown inventory of the functions the analyst kept.

    The original Ghidra symbol and the address are printed beside every friendly
    name. A suggested name is model output derived from attacker-controlled code —
    a binary can try to induce a reassuring one — so the report never presents it
    as the identity.
    """
    kept = [f for f in functions if f.get("included")]
    if not kept:
        return ""
    lines = ["## Functions", ""]
    for f in kept:
        friendly = f.get("suggested_name")
        original = f.get("original_name") or "?"
        address = f.get("address")
        head = f"- **{friendly}** `{original}`" if friendly else f"- `{original}`"
        lines.append(f"{head} @ {address}" if address else head)
        if f.get("purpose"):
            lines.append(f"  {f['purpose']}")
    lines.append("")
    return "\n".join(lines)


def with_functions(report_md: str, functions: list[dict]) -> str:
    """Append the function inventory to a report.

    Appended, not inserted under the title where attribution goes: attribution is
    provenance the reader needs before the findings, while this is a reference
    list they consult afterwards. Composed at read time, so the report can never
    be stale relative to the selection — there is nothing to regenerate.
    """
    section = functions_section(functions)
    if not section:
        return report_md
    body = report_md if report_md.endswith("\n") else report_md + "\n"
    return f"{body}\n{section}"


def attribution_section(rule_sets: list[dict]) -> str:
    """A Markdown provenance block naming the rule set versions the scan ran and,
    for imported ones, who wrote them.

    Placed near the TOP of an exported report rather than the bottom: the PDF
    writer paginates now, but a credit that can be scrolled past is still worth
    less than one that sits with the result it produced. It is also provenance —
    which rules found this — as much as it is a licence notice.
    """
    if not rule_sets:
        return ""
    lines = ["## Rule sets", ""]
    for rs in rule_sets:
        count = rs.get("rule_count")
        detail = f" — {count} rules" if count else ""
        lines.append(f"- **{rs['name']}** v{rs['version_no']}{detail}")
        credit = rs.get("attribution") or {}
        if credit.get("author"):
            bits = [f"Rules by {credit['author']}"]
            if credit.get("license"):
                bits.append(credit["license"])
            if credit.get("url"):
                url = credit["url"]
                commit = credit.get("commit")
                bits.append(f"{url}" + (f" @ {commit[:7]}" if commit else ""))
            lines.append(f"  {' · '.join(bits)}")
    lines.append("")
    return "\n".join(lines)


def with_attribution(report_md: str, rule_sets: list[dict]) -> str:
    """Insert the provenance block after the report's title, or at the top if it
    has none. Every export format is built from this one string, so Markdown, PDF
    and the JSON bundle's `report_markdown` all carry the same credit."""
    section = attribution_section(rule_sets)
    if not section:
        return report_md
    lines = report_md.splitlines()
    if lines and lines[0].startswith("# "):
        head, rest = lines[:1], lines[1:]
        return "\n".join([*head, "", section, *rest]) + "\n"
    return section + "\n" + report_md


def _escape_pdf_text(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


# A real report runs well past one page. Clipping used to drop the tail silently —
# and would now drop an attribution block with it — so the writer paginates.
MAX_PAGES = 40


def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw:
            lines.append("")
            continue
        while raw:
            lines.append(raw[:width])
            raw = raw[width:]
    return lines


def _page_stream(lines: list[str]) -> bytes:
    content = ["BT", "/F1 10 Tf", "50 740 Td", "12 TL"]
    for i, line in enumerate(lines):
        content.append(f"({_escape_pdf_text(line)}) Tj")
        if i < len(lines) - 1:
            content.append("T*")
    content.append("ET")
    return "\n".join(content).encode("latin-1", "replace")


def text_to_pdf(text: str, *, lines_per_page: int = 58, width: int = 95) -> bytes:
    """Render text as a valid multi-page PDF (Courier 10pt).

    Content is wrapped to `width` and flowed across pages, capped at `MAX_PAGES` so
    a runaway report cannot produce an unbounded document."""
    lines = _wrap(text, width) or [""]
    pages = [lines[i : i + lines_per_page] for i in range(0, len(lines), lines_per_page)][
        :MAX_PAGES
    ]

    # Object layout: 1 catalog, 2 pages tree, 3 font, then per page a Page object
    # followed by its Contents stream.
    n = len(pages)
    page_ids = [4 + 2 * i for i in range(n)]
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)

    objects: list[bytes] = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        f"<</Type/Pages/Kids[{kids}]/Count {n}>>".encode(),
        b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>",
    ]
    for i, page_lines in enumerate(pages):
        stream = _page_stream(page_lines)
        objects.append(
            f"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents {page_ids[i] + 1} 0 R"
            f"/Resources<</Font<</F1 3 0 R>>>>>>".encode()
        )
        objects.append(
            b"<</Length " + str(len(stream)).encode() + b">>\nstream\n" + stream + b"\nendstream"
        )

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
