"""附件核查逻辑测试：文件头识别、页面解析、状态判定与端到端抓取。"""

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import attachments
import attachments_data
import data

# ---------- 单元测试：文件头与完整性 ----------


def test_sniff_pdf_zip_html_and_other():
    assert attachments.sniff_file_type(attachments_data.FILES["prj001-tender.pdf"]) == "pdf"
    assert attachments.sniff_file_type(attachments_data.FILES["prj001-boq.zip"]) == "zip"
    assert attachments.sniff_file_type(attachments_data.FILES["prj003-login.pdf"]) == "html"
    assert attachments.sniff_file_type(b"plain text") == "other"
    assert attachments.sniff_file_type(b"") == "other"


def test_validate_valid_pdf_and_zip_are_usable():
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj001-tender.pdf"], ".pdf")
    assert (status, actual) == (attachments.STATUS_USABLE, "pdf")
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj001-boq.zip"], ".zip")
    assert (status, actual) == (attachments.STATUS_USABLE, "zip")


def test_validate_truncated_pdf_is_unusable():
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj003-truncated.pdf"], ".pdf")
    assert status == attachments.STATUS_UNUSABLE
    assert "不完整" in reason


def test_validate_broken_zip_is_unusable():
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj003-broken.zip"], ".zip")
    assert status == attachments.STATUS_UNUSABLE
    assert "损坏" in reason


def test_validate_html_masquerading_as_pdf_is_unusable():
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj003-login.pdf"], ".pdf")
    assert status == attachments.STATUS_UNUSABLE
    assert actual == "html"
    assert "登录" in reason


def test_validate_extension_mismatch_is_flagged():
    # 内容是 PDF，扩展名写 .zip：按真实类型核定为可用，但原因中提示不一致
    status, reason, actual = attachments.validate_content(attachments_data.FILES["prj001-tender.pdf"], ".zip")
    assert status == attachments.STATUS_USABLE
    assert "不一致" in reason


def test_validate_empty_is_unusable():
    status, reason, actual = attachments.validate_content(b"", ".pdf")
    assert status == attachments.STATUS_UNUSABLE


# ---------- 单元测试：附件链接解析 ----------


DETAIL_HTML = """<html><body>
<div class="notice" data-notice-type="tender">
  <h2>示例</h2>
  <div id="project-no" hidden>PRJ-2026-001</div>
  <ul class="attachments">
    <li><a href="/files/a.pdf">招标文件</a></li>
    <li><a href="/files/a.pdf">重复链接</a></li>
    <li><a href="https://other.example/b.zip">站外附件</a></li>
    <li><a href="/files/c.docx">Word 文件</a></li>
    <li><a href="/files/d.zip#frag">带锚点</a></li>
  </ul>
</div>
</body></html>"""


def test_parse_attachment_links_dedup_pdf_zip_keeps_offsite_for_flagging():
    refs = attachments.parse_attachment_links(DETAIL_HTML, "http://example.com/detail/N1.html")
    assert [r.url for r in refs] == [
        "http://example.com/files/a.pdf",
        "https://other.example/b.zip",
        "http://example.com/files/d.zip",
    ]
    assert refs[0].label == "招标文件"


def test_parse_attachment_links_falls_back_to_detail_container():
    html = DETAIL_HTML.replace('class="attachments"', 'class="other"')
    refs = attachments.parse_attachment_links(html, "http://example.com/detail/N1.html")
    assert [r.url for r in refs] == [
        "http://example.com/files/a.pdf",
        "https://other.example/b.zip",
        "http://example.com/files/d.zip",
    ]


# ---------- 端到端：本地 HTTP 服务器 ----------


class _Handler(BaseHTTPRequestHandler):
    routes = {}
    hits = {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        type(self).hits[path] = type(self).hits.get(path, 0) + 1
        route = type(self).routes.get(path)

        if route is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>404</h1>")
            return

        kind = route["kind"]
        body = route.get("body", b"")

        if kind == "redirect_offsite":
            self.send_response(302)
            self.send_header("Location", route["location"])
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if kind == "redirect_local":
            self.send_response(302)
            self.send_header("Location", route["location"])
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if kind == "slow":
            head_only = route.get("head_only", False)
            first_chunk = route.get("first_chunk", 0)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if head_only:
                self.wfile.flush()
                time.sleep(route.get("delay", 2))
                return
            if first_chunk:
                self.wfile.write(body[:first_chunk])
                self.wfile.flush()
            time.sleep(route.get("delay", 2))
            try:
                self.wfile.write(body[first_chunk:])
            except BrokenPipeError:
                pass
            return

        self.send_response(200)
        self.send_header("Content-Type", route.get("content_type", "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if route.get("truncate"):
            self.wfile.write(body[: route["truncate"]])
        else:
            self.wfile.write(body)


@pytest.fixture()
def site():
    handler = type("Handler", (_Handler,), {"routes": {}, "hits": {}, "protocol_version": "HTTP/1.1"})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    yield base, handler
    server.shutdown()
    server.server_close()


def _client(timeout, follow_redirects):
    import httpx

    return httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=follow_redirects)


def _detail_html(project_no, notice_type="tender", notice_no=None, attachments_html=""):
    notice_no = notice_no or f"NT-{project_no}"
    target = (
        f'<div id="target-notice">NT-TARGET</div>'
        if notice_type in ("correction", "cancellation")
        else ""
    )
    deadline = '<div id="deadline">2026-11-20 17:00</div>' if notice_type != "cancellation" else ""
    att = f'<ul class="attachments">{attachments_html}</ul>' if attachments_html else ""
    return f"""<html><body>
<div class="notice" data-notice-type="{notice_type}">
  <h2>公告 {project_no}</h2>
  <div id="project-no">{project_no}</div>
  <div id="notice-no">{notice_no}</div>
  <div id="publish-time">2026-11-01 09:00</div>
  {deadline}
  {target}
  {att}
</div></body></html>"""


def _attach_routes(handler, base):
    routes = handler.routes
    pages = sorted(
        (a["publish_time"], a["notice_no"]) for a in data.ANNOUNCEMENTS
    )
    routes["/list.html"] = {
        "kind": "static",
        "content_type": "text/html; charset=utf-8",
        "body": (
            "<html><body><ul class='notice-list'>"
            + "".join(
                f'<li><a href="/detail/{a["notice_no"]}.html">{a["notice_no"]}</a></li>'
                for a in data.ANNOUNCEMENTS
            )
            + "</ul></body></html>"
        ).encode(),
    }
    for a in data.ANNOUNCEMENTS:
        links = "".join(
            f'<li><a href="{f["href"]}">{f["label"]}</a></li>'
            for f in attachments_data.NOTICE_ATTACHMENTS.get(a["notice_no"], [])
        )
        routes[f'/detail/{a["notice_no"]}.html'] = {
            "kind": "static",
            "content_type": "text/html; charset=utf-8",
            "body": _detail_html(a["project_no"], a["type"], a["notice_no"], links).encode(),
        }
    routes["/files/prj001-tender.pdf"] = {"kind": "static", "content_type": "application/pdf", "body": attachments_data.FILES["prj001-tender.pdf"]}
    routes["/files/prj001-correction.pdf"] = {"kind": "static", "content_type": "application/pdf", "body": attachments_data.FILES["prj001-correction.pdf"]}
    routes["/files/prj001-boq.zip"] = {"kind": "static", "content_type": "application/zip", "body": attachments_data.FILES["prj001-boq.zip"]}
    return routes


def test_end_to_end_all_usable_and_shared_link_downloaded_once(site):
    base, handler = site
    _attach_routes(handler, base)
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-2026-001")

    assert report.overall == attachments.OVERALL_ALL_OK
    assert report.usable_count == 3
    assert {a.filename for a in report.attachments} == {
        "prj001-tender.pdf",
        "prj001-correction.pdf",
        "prj001-boq.zip",
    }
    # 三条公告引用了 4 个链接，其中招标文件被两条公告共享
    assert sum(len(a.references) for a in report.attachments) == 4
    tender = next(a for a in report.attachments if a.filename == "prj001-tender.pdf")
    assert len(tender.references) == 2
    # 每个唯一附件只请求一次
    assert handler.hits["/files/prj001-tender.pdf"] == 1


def test_end_to_end_mixed_failures_and_pending(site):
    base, handler = site
    routes = _attach_routes(handler, base)
    routes["/files/prj003-spec.pdf"] = {"kind": "static", "content_type": "application/pdf", "body": attachments_data.FILES["prj003-spec.pdf"]}
    routes["/files/prj003-login.pdf"] = {"kind": "static", "content_type": "application/pdf", "body": attachments_data.FILES["prj003-login.pdf"]}
    routes["/files/prj003-broken.zip"] = {"kind": "static", "content_type": "application/zip", "body": attachments_data.FILES["prj003-broken.zip"]}
    routes["/files/prj003-truncated.pdf"] = {"kind": "static", "content_type": "application/pdf", "body": attachments_data.FILES["prj003-truncated.pdf"]}
    routes["/files/prj003-huge.zip"] = {"kind": "static", "content_type": "application/zip", "body": b"PK\x03\x04" + b"0" * (11 * 1024 * 1024)}
    routes["/files/prj003-slow.pdf"] = {"kind": "slow", "body": attachments_data.FILES["prj003-spec.pdf"], "delay": 2}

    report = attachments.check_project_attachments(
        f"{base}/list.html", "PRJ-2026-003",
        client=_client(timeout=1.0, follow_redirects=False), timeout=1.0,
    )

    by_name = {a.filename: a for a in report.attachments}
    assert by_name["prj003-spec.pdf"].status == attachments.STATUS_USABLE
    assert by_name["prj003-login.pdf"].status == attachments.STATUS_UNUSABLE
    assert "HTML" in by_name["prj003-login.pdf"].reason
    assert by_name["prj003-broken.zip"].status == attachments.STATUS_UNUSABLE
    assert by_name["prj003-truncated.pdf"].status == attachments.STATUS_UNUSABLE
    assert by_name["prj003-huge.zip"].status == attachments.STATUS_PENDING
    assert "超过" in by_name["prj003-huge.zip"].reason
    assert by_name["prj003-slow.pdf"].status == attachments.STATUS_PENDING
    assert "超时" in by_name["prj003-slow.pdf"].reason
    assert report.overall == attachments.OVERALL_UNUSABLE
    assert "不能判定" in report.overall_reason


def test_end_to_end_404_is_unusable(site):
    base, handler = site
    _attach_routes(handler, base)
    handler.routes["/files/prj004-qualification.pdf"] = {"kind": "static", "body": attachments_data.FILES["prj004-qualification.pdf"]}
    # prj003-missing.pdf 未注册 → 404
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-2026-003")
    by_name = {a.filename: a for a in report.attachments}
    assert by_name["prj003-missing.pdf"].status == attachments.STATUS_UNUSABLE
    assert "404" in by_name["prj003-missing.pdf"].reason


def test_end_to_end_offsite_redirect_is_unusable_without_following(site):
    base, handler = site
    _attach_routes(handler, base)
    handler.routes["/files/prj005-redirect.pdf"] = {"kind": "redirect_offsite", "location": "https://example.invalid/x.pdf"}
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-2026-005")
    redirect = next(a for a in report.attachments if a.filename == "prj005-redirect.pdf")
    assert redirect.status == attachments.STATUS_UNUSABLE
    assert "站外" in redirect.reason


def test_end_to_end_list_redirect_offsite_is_not_followed(site):
    base, handler = site
    _attach_routes(handler, base)
    handler.routes["/offsite-list.html"] = {
        "kind": "redirect_offsite", "location": "https://example.invalid/list.html"
    }
    report = attachments.check_project_attachments(f"{base}/offsite-list.html", "PRJ-2026-001")
    assert report.overall == attachments.OVERALL_PENDING
    assert any("站外" in i.reason for i in report.issues)
    # 站外目标不应被请求（测试服务器从未收到该路径）
    assert "/list.html" not in handler.hits


def test_end_to_end_same_origin_redirect_is_followed(site):
    base, handler = site
    _attach_routes(handler, base)
    handler.routes["/entry.html"] = {"kind": "redirect_local", "location": "/list.html"}
    report = attachments.check_project_attachments(f"{base}/entry.html", "PRJ-2026-001")
    assert report.overall == attachments.OVERALL_ALL_OK
    assert report.usable_count == 3


def test_end_to_end_detail_failure_makes_overall_pending(site):
    base, handler = site
    _attach_routes(handler, base)
    # 让一条无关详情解析失败，仍然不能判定全部可用
    handler.routes["/detail/NT-2026-0004.html"] = {"kind": "static", "body": b"<h1>500</h1>"}
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-2026-001")
    assert report.issues
    assert report.overall == attachments.OVERALL_PENDING
    assert "不能判定" in report.overall_reason


def test_end_to_end_project_not_found(site):
    base, handler = site
    _attach_routes(handler, base)
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-NOT-EXIST")
    assert report.overall == attachments.OVERALL_NOT_FOUND
    assert report.matched_details == []


def test_end_to_end_no_attachments_project(site):
    base, handler = site
    _attach_routes(handler, base)
    report = attachments.check_project_attachments(f"{base}/list.html", "PRJ-2026-002")
    assert report.matched_details
    assert report.attachments == []
    assert report.overall == attachments.OVERALL_NOT_FOUND


def test_invalid_inputs_raise():
    with pytest.raises(attachments.AttachmentURLInvalid):
        attachments.check_project_attachments("ftp://example.com/list", "P1")
    with pytest.raises(attachments.AttachmentURLInvalid):
        attachments.check_project_attachments("http://example.com/list", "  ")
