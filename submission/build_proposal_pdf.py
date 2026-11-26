#!/usr/bin/env python3
"""Render PROPOSAL.md to a one-page A4 PDF using a CJK font.

The contest requires the final proposal to be written by the human entrant.
This script only formats the approved Markdown; it does not generate prose.
"""
from pathlib import Path
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, KeepTogether

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "PROPOSAL.md"
DEFAULT_OUT = ROOT / "submission" / "PROPOSAL.pdf"


def clean_markdown(text: str) -> str:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = text.replace("**", "").replace("`", "")
    return text


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))

    title = ParagraphStyle(
        "Title",
        fontName="STSong-Light",
        fontSize= 13,
        leading= 16,
        textColor=colors.HexColor("#111111"),
        spaceAfter=4,
    )
    heading = ParagraphStyle(
        "Heading",
        fontName="STSong-Light",
        fontSize=9.2,
        leading=11.2,
        textColor=colors.HexColor("#111111"),
        spaceBefore=3,
        spaceAfter=1.5,
    )
    body = ParagraphStyle(
        "Body",
        fontName="STSong-Light",
        fontSize=8.2,
        leading=10.4,
        textColor=colors.HexColor("#222222"),
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    small = ParagraphStyle(
        "Small",
        fontName="STSong-Light",
        fontSize=7.4,
        leading=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=1,
    )

    lines = clean_markdown(SOURCE.read_text(encoding="utf-8")).splitlines()
    story = []
    for raw in lines:
        line = raw.strip()
        if not line:
            story.append(Spacer(1, 1.5))
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(re.fullmatch(r":?-+:?", c or "") for c in cells):
                continue
            story.append(Paragraph("　".join(cells), small))
            continue
        if line.startswith("# "):
            story.append(Paragraph(line[2:], title))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], heading))
        elif line.startswith("- "):
            story.append(Paragraph("• " + line[2:], body))
        else:
            story.append(Paragraph(line, body))

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="MoonForge RE Workbench 项目申报书",
        author="陈勇润",
    )
    doc.build(story)
    print(out)


if __name__ == "__main__":
    main()
