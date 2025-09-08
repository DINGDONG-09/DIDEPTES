
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Flowable, KeepTogether
)
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from collections import defaultdict, Counter

# ---------------------------
#  Palette & helpers
# ---------------------------
BG_DARK = colors.HexColor("#0b1020")
CARD_DARK = colors.HexColor("#121832")
TEXT = colors.HexColor("#0b0f1a")
MUTED = colors.HexColor("#475569")
BORDER = colors.HexColor("#e2e8f0")
ACCENT1 = colors.HexColor("#6ee7f3")
ACCENT2 = colors.HexColor("#a78bfa")

SEV_COLORS = {
    "high": colors.HexColor("#ef4444"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#10b981"),
    "info": colors.HexColor("#64748b"),
}

def sev_bucket(score: int) -> str:
    if score <= 0: return "info"
    if 1 <= score <= 2: return "low"
    if 3 <= score <= 5: return "medium"
    return "high"

def dot(radius=2, fill=colors.black):
    # returns a tiny Flowable circle used inside pills
    class Dot(Flowable):
        def __init__(self): super().__init__(); self.w = self.h = radius*2
        def draw(self):
            self.canv.setFillColor(fill)
            self.canv.circle(radius, radius, radius, fill=1, stroke=0)
    return Dot()

class Pill(Flowable):
    """Rounded label 'pill' with colored dot."""
    def __init__(self, text, color=colors.HexColor("#64748b"),
                 txt_color=TEXT, padding=3, r=5):
        super().__init__()
        self.text = text
        self.color = color
        self.txt_color = txt_color
        self.padding = padding
        self.r = r
        # width approx: text + paddings + dot
        self.font = ("Helvetica", 8)
        self._w = len(text)*4.2 + 28
        self._h = 14

    def wrap(self, availWidth, availHeight):
        return self._w, self._h

    def draw(self):
        c = self.canv
        w, h, r = self._w, self._h, self.r
        # pill background
        c.setFillColor(colors.HexColor("#eef2ff"))
        c.setStrokeColor(BORDER)
        c.roundRect(0, 0, w, h, r, fill=1, stroke=1)
        # text
        c.setFillColor(self.txt_color)
        c.setFont(*self.font)
        c.drawString(6, 4, self.text)
        # colored dot
        c.saveState()
        c.translate(w-10, h/2 - 2)
        c.setFillColor(self.color)
        c.circle(2, 2, 2, stroke=0, fill=1)
        c.restoreState()

# ---------------------------
#  Background / header / footer painters
# ---------------------------
def draw_header_footer(canvas: pdfcanvas.Canvas, doc):
    # Footer: page number
    page = canvas.getPageNumber()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(doc.pagesize[0]-15*mm, 12*mm, f"Page {page}")

def draw_cover(canvas: pdfcanvas.Canvas, doc, title, subtitle, meta):
    W, H = doc.pagesize
    canvas.saveState()

    # faux-gradient background using two translucent shapes
    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, W, H, stroke=0, fill=1)

    canvas.setFillColor(ACCENT1)
    canvas.setFillAlpha(0.12)
    canvas.circle(0.15*W, 1.05*H, 0.6*W, stroke=0, fill=1)

    canvas.setFillColor(ACCENT2)
    canvas.setFillAlpha(0.12)
    canvas.circle(0.85*W, 1.05*H, 0.6*W, stroke=0, fill=1)

    canvas.setFillAlpha(1)

    # Title block card
    x, y, w, h = 20*mm, H-70*mm, W-40*mm, 50*mm
    canvas.setFillColor(colors.white)
    canvas.setStrokeColor(BORDER)
    canvas.roundRect(x, y, w, h, 8, stroke=1, fill=1)

    # Badge
    canvas.setFillColor(colors.HexColor("#f1f5f9"))
    canvas.setStrokeColor(BORDER)
    canvas.roundRect(x+8, y+h-16, 60, 14, 7, stroke=1, fill=1)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(MUTED)
    canvas.drawString(x+14, y+h-12, "Mini-OWASP Scanner")

    # Headings
    canvas.setFont("Helvetica-Bold", 22)
    canvas.setFillColor(TEXT)
    canvas.drawString(x+14, y+h-34, title)

    canvas.setFont("Helvetica", 11)
    canvas.setFillColor(MUTED)
    canvas.drawString(x+14, y+h-50, subtitle)

    # Meta
    canvas.setFont("Helvetica", 10)
    yy = y+h-70
    for line in meta:
        canvas.setFillColor(MUTED)
        canvas.drawString(x+14, yy, line)
        yy -= 14

    # Accent bar
    canvas.setFillColor(ACCENT1)
    canvas.rect(x+14, y+16, w-28, 3, stroke=0, fill=1)

    canvas.restoreState()

# ---------------------------
#  Core renderer
# ---------------------------
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=14, textColor=TEXT, spaceAfter=4))
    ss.add(ParagraphStyle(name="H3", fontName="Helvetica-Bold", fontSize=12, textColor=TEXT, spaceAfter=2))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9.7, textColor=TEXT, leading=13))
    ss.add(ParagraphStyle(name="Muted", fontName="Helvetica", fontSize=9, textColor=MUTED))
    ss.add(ParagraphStyle(name="TOCHead", fontName="Helvetica-Bold", fontSize=11, textColor=TEXT))
    return ss

def _card_table(rows, col_widths=None, bg=colors.white):
    t = Table(rows, colWidths=col_widths or [30*mm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("BOX", (0,0), (-1,-1), 0.6, BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.3, BORDER),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    return t

def _stat_card(value, label):
    # a small 1x1 table styled as a card
    tbl = Table([[Paragraph(f"<b>{value}</b>", ParagraphStyle("snum", fontName="Helvetica-Bold", fontSize=16, textColor=TEXT)),
                  Paragraph(label, ParagraphStyle("slbl", fontName="Helvetica", fontSize=9, textColor=MUTED))]],
                colWidths=[None, None])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("BOX", (0,0), (-1,-1), 0.6, BORDER),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    return tbl

def to_pdf(findings: list, generated_at: str, pdf_path: str, title="Security Assessment Report"):
    # Normalize data
    fin = []
    for f in findings or []:
        f = dict(f)
        f.setdefault("type","unknown"); f.setdefault("url",""); f.setdefault("param","")
        f.setdefault("severity_score",0); f.setdefault("evidence",""); f.setdefault("payload","")
        f.setdefault("recommendation","Follow OWASP best practices.")
        fin.append(f)

    by_bucket = Counter(sev_bucket(x["severity_score"]) for x in fin)
    by_type = Counter(x["type"] for x in fin)
    grouped = defaultdict(list)
    for x in fin:
        grouped[x["type"]].append(x)

    # Document setup
    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=16*mm, rightMargin=16*mm,
                            topMargin=18*mm, bottomMargin=16*mm)
    story = []
    styles = _styles()

    # Cover (drawn manually), then intro page content
    def on_first_page(c, d):
        human = datetime.fromisoformat(generated_at.replace("Z","+00:00")).strftime("%d %b %Y %H:%M UTC") if generated_at else datetime.utcnow().strftime("%d %b %Y %H:%M UTC")
        meta = [f"Generated: {human}", f"Total Findings: {len(fin)}"]
        draw_cover(c, d, title, "Dynamic scan summary with OWASP-aligned checks", meta)

    # Intro gap so cover isn't overlapped
    story.append(Spacer(1, 120*mm))

    # Stats cards
    stats_table = Table([
        [_stat_card(len(fin), "Total Findings"),
         _stat_card(by_bucket.get("high",0), "High"),
         _stat_card(by_bucket.get("medium",0), "Medium"),
         _stat_card(by_bucket.get("info",0), "Info/Config")]
    ], colWidths=[43*mm, 43*mm, 43*mm, 43*mm])
    stats_table.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("ALIGN",(0,0),(-1,-1),"CENTER")]))
    story += [stats_table, Spacer(1, 10*mm)]

    # TOC
    story += [Paragraph("Findings Overview", styles["TOCHead"]), Spacer(1, 2*mm)]
    if by_type:
        toc_rows = [["Type", "Count", "Severity Hint"]]
        for t, n in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])):
            # severity hint = worst bucket found in that type
            worst = "info"
            if grouped[t]:
                worst = max((sev_bucket(x["severity_score"]) for x in grouped[t]),
                            key=lambda b: ["info","low","medium","high"].index(b))
            pill = Pill(worst.capitalize(), SEV_COLORS.get(worst, SEV_COLORS["info"]))
            toc_rows.append([Paragraph(t, styles["Body"]), Paragraph(str(n), styles["Body"]), pill])
        toc_tbl = Table(toc_rows, colWidths=[90*mm, 20*mm, None])
        toc_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR",(0,0),(-1,0), TEXT),
            ("BOX",(0,0),(-1,-1), 0.6, BORDER),
            ("INNERGRID",(0,0),(-1,-1), 0.3, BORDER),
            ("LEFTPADDING",(0,0),(-1,-1),8),
            ("RIGHTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        story += [toc_tbl]
    else:
        story += [Paragraph("No findings to list.", styles["Muted"])]
    story += [Spacer(1, 8*mm), PageBreak()]

    # Sections per exact type
    for t, items in sorted(grouped.items(), key=lambda kv: (-max(x.get("severity_score",0) for x in kv[1]), kv[0])):
        # Section header
        story += [Paragraph(t, styles["H2"]), Spacer(1, 1*mm),
                  Paragraph(f"{len(items)} finding(s)", styles["Muted"]), Spacer(1, 2*mm)]

        for it in items:
            sev = sev_bucket(it["severity_score"])
            pills = [
                Pill(sev.capitalize(), SEV_COLORS.get(sev, SEV_COLORS["info"])),
                Pill(f"Score {it['severity_score']}", SEV_COLORS["info"])
            ]
            pills_tbl = Table([pills])
            pills_tbl.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),0)]))

            rows = [
                ["URL", Paragraph(it.get("url") or "-", styles["Body"])],
                ["Param", Paragraph(it.get("param") or "-", styles["Body"])],
                ["Payload", Paragraph(it.get("payload") or "-", styles["Body"])],
                ["Evidence", Paragraph(it.get("evidence") or "-", styles["Body"])],
                ["Recommendation", Paragraph(it.get("recommendation") or "Follow OWASP best practices.", styles["Body"])],
            ]
            card = _card_table(rows)
            story.append(KeepTogether([pills_tbl, Spacer(1, 2*mm), card, Spacer(1, 6*mm)]))

        story.append(Spacer(1, 6*mm))

    # Build
    doc.build(story, onFirstPage=lambda c,d: [draw_header_footer(c,d), on_first_page(c,d)][-1],
                    onLaterPages=draw_header_footer)
