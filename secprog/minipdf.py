"""A tiny dependency-free PDF writer: text lines and filled bars on A4/Letter pages.

Enough for an executive report. Output is deterministic (no timestamps, fixed object order).
Only Latin-1 text is supported; other characters are replaced with '?'.
"""
from __future__ import annotations

PAGE_W, PAGE_H = 612, 792  # US Letter in points


def _esc(s: str) -> str:
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Doc:
    def __init__(self) -> None:
        self.pages: list[list[str]] = [[]]
        self.y = PAGE_H - 50

    def _need(self, h: float) -> None:
        if self.y - h < 50:
            self.pages.append([])
            self.y = PAGE_H - 50

    def text(self, s: str, size: int = 10, bold: bool = False) -> None:
        self._need(size + 4)
        font = "F2" if bold else "F1"
        self.pages[-1].append(f"BT /{font} {size} Tf 50 {self.y:.1f} Td ({_esc(s)}) Tj ET")
        self.y -= size + 4

    def bar(self, label: str, value: float, maximum: float, note: str = "", rgb=(0.2, 0.4, 0.7)) -> None:
        """One horizontal bar: label on the left, bar scaled to maximum, note on the right."""
        self._need(16)
        width = 0 if maximum <= 0 else max(0.0, min(1.0, value / maximum)) * 250
        r, g, b = rgb
        p = self.pages[-1]
        p.append(f"BT /F1 9 Tf 50 {self.y:.1f} Td ({_esc(label[:34])}) Tj ET")
        p.append(f"{r} {g} {b} rg 230 {self.y - 2:.1f} {width:.1f} 10 re f 0 0 0 rg")
        p.append(f"BT /F1 9 Tf 490 {self.y:.1f} Td ({_esc(note)}) Tj ET")
        self.y -= 16

    def gap(self, h: float = 8) -> None:
        self.y -= h

    def to_bytes(self) -> bytes:
        objs: list[bytes] = []
        n_pages = len(self.pages)
        # 1 catalog, 2 pages, 3 font regular, 4 font bold, then (page, content) pairs
        kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(n_pages))
        objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        for i, ops in enumerate(self.pages):
            stream = "\n".join(ops).encode("latin-1", "replace")
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                        f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {6 + 2 * i} 0 R >>".encode())
            objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for i, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


def page_count(pdf: bytes) -> int:
    return pdf.count(b"/Type /Page ")
