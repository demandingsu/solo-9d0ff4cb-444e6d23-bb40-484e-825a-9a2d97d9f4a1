"""示例附件：供附件核查页演示各种真实/异常情况。

覆盖场景：
- 正常 PDF / ZIP（可被文件头识别、结构完整）；
- 共享附件（同一网址被多条公告引用，核查端应只下载一次）；
- HTML 登录页伪装成 .pdf；
- 404 附件；
- 损坏的 ZIP、截断的 PDF；
- 超过 10 MiB 的 ZIP；
- 站外跳转；
- 下载超时（慢响应）。
"""

from __future__ import annotations

import io
import zipfile

OFFSITE_URL = "https://example.invalid/offsite/采购需求.pdf"
SLOW_DELAY_SECONDS = 12
HUGE_SIZE = 10 * 1024 * 1024 + 512 * 1024  # 10.5 MiB，超过核查端 10 MiB 上限


def _pdf(title: str) -> bytes:
    """生成一个结构完整的最小 PDF（含 xref 与 %%EOF）。"""
    text = f"BT /F1 14 Tf 72 760 Td ({title}) Tj ET".encode("ascii")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_at).encode() + b"\n%%EOF\n"
    )
    return bytes(out)


def _zip(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _huge_zip() -> bytes:
    """超过上限的合法 ZIP（存储不压缩，确保真实字节数超限）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("drawings/README.txt", b"large attachment demo\n")
        zf.writestr("drawings/full-drawing-set.dwg", b"0" * HUGE_SIZE)
    return buf.getvalue()


def _html_login() -> bytes:
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>请登录</title></head>
<body>
  <h1>请先登录</h1>
  <form action="/login" method="post">
    <label>账号 <input name="user"></label>
    <label>密码 <input name="password" type="password"></label>
    <button type="submit">登录后下载附件</button>
  </form>
</body>
</html>""".encode("utf-8")


FILES: dict[str, bytes] = {
    "prj001-tender.pdf": _pdf("Municipal Road Tender Document"),
    "prj001-boq.zip": _zip("工程量清单.txt", "市政道路改造工程量清单示例".encode("utf-8")),
    "prj001-correction.pdf": _pdf("Correction Notice"),
    "prj003-spec.pdf": _pdf("Technical Specification"),
    "prj003-login.pdf": _html_login(),  # 扩展名是 pdf，内容却是登录页
    "prj003-broken.zip": b"PK\x03\x04" + b"\x00" * 64,  # ZIP 文件头但结构损坏
    "prj003-truncated.pdf": b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n",  # 缺少 %%EOF
    "prj003-huge.zip": _huge_zip(),
    "prj004-qualification.pdf": _pdf("Qualification Documents"),
    "prj005-needs.pdf": _pdf("Procurement Requirements"),
    "prj003-slow.pdf": _pdf("Slow Attachment"),
    # 供站外跳转演示：真实内容永远不会被访问
    "prj005-redirect.pdf": b"",
}

# 详情页附件链接：同一网址可被多条公告引用（共享附件）
NOTICE_ATTACHMENTS: dict[str, list[dict[str, str]]] = {
    "NT-2026-0001": [
        {"label": "招标文件.pdf", "href": "/files/prj001-tender.pdf"},
        {"label": "工程量清单.zip", "href": "/files/prj001-boq.zip"},
    ],
    "NT-2026-0002": [
        {"label": "招标文件（更正后沿用）.pdf", "href": "/files/prj001-tender.pdf"},
        {"label": "更正说明.pdf", "href": "/files/prj001-correction.pdf"},
    ],
    "NT-2026-0005": [
        {"label": "技术规格书.pdf", "href": "/files/prj003-spec.pdf"},
        {"label": "投标人须知.pdf", "href": "/files/prj003-login.pdf"},
        {"label": "图纸.pdf", "href": "/files/prj003-missing.pdf"},
    ],
    "NT-2026-0006": [
        {"label": "技术规格书（沿用）.pdf", "href": "/files/prj003-spec.pdf"},
        {"label": "技术参数表.zip", "href": "/files/prj003-broken.zip"},
    ],
    "NT-2026-0007": [
        {"label": "补充说明.pdf", "href": "/files/prj003-truncated.pdf"},
        {"label": "完整图纸包.zip", "href": "/files/prj003-huge.zip"},
        {"label": "扫描件.pdf", "href": "/files/prj003-slow.pdf"},
    ],
    "NT-2026-0008": [
        {"label": "资格文件.pdf", "href": "/files/prj004-qualification.pdf"},
    ],
    "NT-2026-0009": [
        {"label": "采购需求.pdf", "href": "/files/prj005-needs.pdf"},
    ],
    "NT-2026-0010": [
        {"label": "采购需求（更正）.pdf", "href": "/files/prj005-needs.pdf"},
        {"label": "外部参考.pdf", "href": "https://example.invalid/prj005-external.pdf"},
        {"label": "代理机构附件.pdf", "href": "/files/prj005-redirect.pdf"},
    ],
}
