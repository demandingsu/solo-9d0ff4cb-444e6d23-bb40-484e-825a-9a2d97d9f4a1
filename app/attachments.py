"""项目附件核查：沿公告目录的同源分页与详情页，核对 PDF / ZIP 附件。

核查规则：
- 只跟随与公告目录同源的分页、详情和附件链接；
- 同一附件网址只下载一次（多个公告引用时合并引用，逐公告保留来源）；
- 附件按流式读取，最多 10 MiB（超过即“待核实”，不再继续读取）；
- 以文件头（magic bytes）识别真实类型，不信任扩展名与 Content-Type；
- 站外跳转、HTTP 404、损坏文件、HTML 伪装 → “不可用”；
- 超时、超限、详情页失败 → “待核实”；
- 只要有关联详情无法读取，或任一附件无法核定，整体就不能判定“全部可用”。

页面解析约定（与示例公告站一致）：
- 列表页：公告链接 ul.notice-list a[href]；分页 nav.pagination a[href]
- 详情页：div.notice[data-notice-type]，附件链接 ul.attachments a[href]
  （没有 ul.attachments 时，回退为详情内指向 .pdf/.zip 的链接）
"""

from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass, field
from urllib.parse import unquote, urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from scraper import ScrapeError, parse_detail, same_origin

# ---------- 限额与超时 ----------

MAX_BYTES = 10 * 1024 * 1024  # 每个附件最多读取 10 MiB
MAX_REDIRECTS = 5
MAX_LIST_PAGES = 50
MAX_DETAIL_PAGES = 500
MAX_ATTACHMENTS = 200
REQUEST_TIMEOUT = float(os.environ.get("ATTACHMENT_TIMEOUT", "10"))
USER_AGENT = "bid-attachment-checker/1.0"

SUPPORTED_EXTENSIONS = {".pdf", ".zip"}

# ---------- 状态 ----------

STATUS_USABLE = "usable"
STATUS_UNUSABLE = "unusable"
STATUS_PENDING = "pending"

STATUS_LABELS = {
    STATUS_USABLE: "可用",
    STATUS_UNUSABLE: "不可用",
    STATUS_PENDING: "待核实",
}

OVERALL_ALL_OK = "all_ok"
OVERALL_UNUSABLE = "unusable"
OVERALL_PENDING = "pending"
OVERALL_NOT_FOUND = "not_found"

OVERALL_LABELS = {
    OVERALL_ALL_OK: "全部可用",
    OVERALL_UNUSABLE: "存在不可用附件",
    OVERALL_PENDING: "不能判定全部可用",
    OVERALL_NOT_FOUND: "无法核定",
}

TYPE_LABELS = {"pdf": "PDF", "zip": "ZIP", "html": "HTML", "other": "其他"}

PDF_MAGIC = b"%PDF-"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
HTML_PREFIXES = (b"<!doctype html", b"<html", b"<head", b"<body")


class AttachmentURLInvalid(ValueError):
    """输入参数不合法（不是可抓取的 http(s) 网址 / 项目编号为空）。"""


# ---------- 数据结构 ----------


@dataclass
class AttachmentRef:
    """某条公告对某个附件网址的一次引用。"""

    url: str
    label: str
    notice_no: str
    detail_url: str
    declared_ext: str


@dataclass
class AttachmentCheck:
    """一个唯一附件网址的核查结果（references 为逐公告引用）。"""

    url: str
    declared_ext: str
    status: str
    reason: str
    actual_type: str | None = None
    size: int = 0
    content_type: str = ""
    final_url: str = ""
    references: list[AttachmentRef] = field(default_factory=list)

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]

    @property
    def actual_type_label(self) -> str:
        return TYPE_LABELS.get(self.actual_type or "", "未知")

    @property
    def filename(self) -> str:
        path = unquote(urlparse(self.url).path)
        return path.rsplit("/", 1)[-1] or self.url


@dataclass
class DetailIssue:
    """列表页 / 详情页无法读取或解析（关联范围无法核定）。"""

    url: str
    reason: str


@dataclass
class AttachmentReport:
    project_no: str
    directory_url: str
    list_pages: list[str] = field(default_factory=list)
    scanned_details: int = 0
    matched_details: list[dict] = field(default_factory=list)
    attachments: list[AttachmentCheck] = field(default_factory=list)
    issues: list[DetailIssue] = field(default_factory=list)
    overall: str = OVERALL_NOT_FOUND
    overall_reason: str = ""

    @property
    def overall_label(self) -> str:
        return OVERALL_LABELS[self.overall]

    @property
    def usable_count(self) -> int:
        return sum(a.status == STATUS_USABLE for a in self.attachments)

    @property
    def unusable_count(self) -> int:
        return sum(a.status == STATUS_UNUSABLE for a in self.attachments)

    @property
    def pending_count(self) -> int:
        return sum(a.status == STATUS_PENDING for a in self.attachments)

    @property
    def download_count(self) -> int:
        return len(self.attachments)


# ---------- 基础工具 ----------


def _normalize(href: str, base: str) -> str:
    url, _frag = urldefrag(urljoin(base, href))
    return url


def _is_http(url: str) -> bool:
    p = urlparse(url)
    return p.scheme in ("http", "https") and bool(p.hostname)


def _is_supported(href: str) -> bool:
    ext = os.path.splitext(unquote(urlparse(href).path))[1].lower()
    return ext in SUPPORTED_EXTENSIONS


def _ext(href: str) -> str:
    return os.path.splitext(unquote(urlparse(href).path))[1].lower()


def _filename_from_url(url: str) -> str:
    path = unquote(urlparse(url).path)
    return path.rsplit("/", 1)[-1] or url


# ---------- 文件头识别与完整性校验 ----------


def sniff_file_type(data: bytes) -> str:
    """按文件头识别真实类型：pdf / zip / html / other。"""
    if data[:4] in ZIP_MAGICS:
        return "zip"
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(PDF_MAGIC):
        return "pdf"
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(HTML_PREFIXES) or head.startswith(b"<!--"):
        return "html"
    return "other"


def validate_content(data: bytes, declared_ext: str = "", content_type: str = "") -> tuple[str, str, str | None]:
    """校验附件内容，返回 (status, reason, actual_type)。

    只有 PDF / ZIP 文件头是权威判定；HTML 另外结合 Content-Type 兜底识别。
    """
    if not data:
        return STATUS_UNUSABLE, "文件内容为空，无法识别", "other"

    actual = sniff_file_type(data)
    if actual == "other" and "text/html" in content_type.lower():
        actual = "html"
    mismatch = ""
    if declared_ext and actual in ("pdf", "zip") and declared_ext != f".{actual}":
        mismatch = f"扩展名 {declared_ext} 与实际类型 {actual.upper()} 不一致；"

    if actual == "pdf":
        if b"%%EOF" not in data[-4096:]:
            return STATUS_UNUSABLE, f"{mismatch}文件头为 PDF，但内容不完整（缺少 %%EOF），疑似损坏", actual
        return STATUS_USABLE, f"{mismatch}文件头识别为 PDF，结构完整（{len(data)} 字节）", actual

    if actual == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                entries = len(zf.namelist())
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            return STATUS_UNUSABLE, f"{mismatch}ZIP 文件头存在，但压缩包结构损坏：{exc}", actual
        return STATUS_USABLE, f"{mismatch}文件头识别为 ZIP，结构完整（{entries} 个条目，{len(data)} 字节）", actual

    if actual == "html":
        preview = data[:2048].decode("utf-8", "ignore").lower()
        kind = "登录页" if ("登录" in preview or "login" in preview) else "页面"
        return STATUS_UNUSABLE, f"{mismatch}返回的是 HTML {kind}，不是 PDF/ZIP（常为登录页或错误页伪装）", actual

    return STATUS_UNUSABLE, f"{mismatch}文件头无法识别为 PDF/ZIP（实际类型为其他）", actual


# ---------- 页面解析 ----------


def parse_attachment_links(html: str, detail_url: str) -> list[AttachmentRef]:
    """从详情页提取 PDF/ZIP 附件链接（同一详情内按网址去重）。"""
    soup = BeautifulSoup(html, "html.parser")
    anchors = soup.select("ul.attachments a[href]")
    if not anchors:
        # 兼容没有 ul.attachments 的页面：只看详情容器内扩展名为 pdf/zip 的链接
        anchors = soup.select("div.notice a[href]")

    refs: list[AttachmentRef] = []
    seen: set[str] = set()
    for a in anchors:
        href = (a.get("href") or "").strip()
        if not href:
            continue
        url = _normalize(href, detail_url)
        if not _is_http(url) or not _is_supported(url) or url in seen:
            continue
        seen.add(url)
        label = a.get_text(strip=True) or _filename_from_url(url)
        refs.append(
            AttachmentRef(
                url=url,
                label=label,
                notice_no="",  # 由调用方按所属公告补齐
                detail_url=detail_url,
                declared_ext=_ext(url),
            )
        )
    return refs


# ---------- 网络读取 ----------


class _PageError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _fetch_page(client: httpx.Client, url: str, origin_url: str) -> str:
    """读取列表/详情页 HTML；跳转到站外、超时或非 2xx 均视为该页无法核定。

    只手动跟随同源重定向，绝不向站外目标发起请求。
    """
    current = url
    visited = {current}
    for _attempt in range(MAX_REDIRECTS + 1):
        try:
            resp = client.get(current, follow_redirects=False)
        except httpx.TimeoutException:
            raise _PageError(f"请求超时：{current}") from None
        except httpx.HTTPError as exc:
            raise _PageError(f"请求失败：{exc}") from exc

        if 300 <= resp.status_code < 400:
            target = _redirect_target(resp, current)
            if target is None:
                raise _PageError(f"HTTP {resp.status_code} 重定向但缺少 Location")
            if not same_origin(target, origin_url):
                raise _PageError(f"页面跳转到站外地址，未读取：{target}")
            if target in visited:
                raise _PageError(f"重定向循环：{target}")
            visited.add(target)
            current = target
            continue
        if resp.status_code >= 400:
            raise _PageError(f"HTTP {resp.status_code}")
        if not same_origin(str(resp.url), origin_url):
            raise _PageError(f"页面跳转到站外地址，未读取：{resp.url}")
        return resp.text

    raise _PageError(f"重定向次数超过 {MAX_REDIRECTS} 次")


def _redirect_target(resp: httpx.Response, current: str) -> str | None:
    location = resp.headers.get("location")
    if not location:
        return None
    return _normalize(location, current)


def _check_one_attachment(
    client: httpx.Client,
    url: str,
    refs: list[AttachmentRef],
    origin_url: str,
    max_bytes: int,
) -> AttachmentCheck:
    declared_ext = _ext(url)
    common = {"url": url, "declared_ext": declared_ext, "references": refs}

    if not _is_http(url):
        return AttachmentCheck(status=STATUS_UNUSABLE, reason="附件网址不是 http(s) 网址", **common)
    if not same_origin(url, origin_url):
        return AttachmentCheck(status=STATUS_UNUSABLE, reason="附件指向站外地址，未读取（按同源规则不可用）", **common)

    current = url
    visited = {current}
    for _attempt in range(MAX_REDIRECTS + 1):
        try:
            with client.stream("GET", current, follow_redirects=False) as resp:
                content_type = resp.headers.get("content-type", "")

                if 300 <= resp.status_code < 400:
                    target = _redirect_target(resp, current)
                    if target is None:
                        return AttachmentCheck(
                            status=STATUS_UNUSABLE,
                            reason=f"HTTP {resp.status_code} 重定向但缺少 Location",
                            content_type=content_type,
                            final_url=current,
                            **common,
                        )
                    if not same_origin(target, origin_url):
                        return AttachmentCheck(
                            status=STATUS_UNUSABLE,
                            reason=f"站外跳转：{current} → {target}（未读取站外内容）",
                            content_type=content_type,
                            final_url=target,
                            **common,
                        )
                    if target in visited:
                        return AttachmentCheck(
                            status=STATUS_UNUSABLE,
                            reason=f"重定向循环：{target}",
                            content_type=content_type,
                            final_url=current,
                            **common,
                        )
                    visited.add(target)
                    current = target
                    continue

                if resp.status_code == 404:
                    return AttachmentCheck(
                        status=STATUS_UNUSABLE,
                        reason=f"HTTP 404，附件不存在：{current}",
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )
                if resp.status_code in (401, 403):
                    return AttachmentCheck(
                        status=STATUS_UNUSABLE,
                        reason=f"HTTP {resp.status_code}，需要登录或没有访问权限",
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )
                if 400 <= resp.status_code < 500:
                    return AttachmentCheck(
                        status=STATUS_UNUSABLE,
                        reason=f"HTTP {resp.status_code}，附件无法访问",
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )
                if resp.status_code >= 500:
                    return AttachmentCheck(
                        status=STATUS_PENDING,
                        reason=f"HTTP {resp.status_code}，暂时无法确认附件",
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )

                # 先看声明大小，避免明知超限还继续下载
                declared_len = resp.headers.get("content-length")
                if declared_len:
                    try:
                        if int(declared_len) > max_bytes:
                            return AttachmentCheck(
                                status=STATUS_PENDING,
                                reason=f"文件声明大小 {int(declared_len)} 字节，超过 {max_bytes // (1024 * 1024) or 0} MiB 上限",
                                content_type=content_type,
                                final_url=current,
                                **common,
                            )
                    except ValueError:
                        pass

                data = bytearray()
                try:
                    for chunk in resp.iter_bytes():
                        data.extend(chunk)
                        if len(data) > max_bytes:
                            return AttachmentCheck(
                                status=STATUS_PENDING,
                                reason=f"读取超过 {max_bytes} 字节上限（已读取 {len(data)} 字节），未继续下载",
                                size=len(data),
                                content_type=content_type,
                                final_url=current,
                                **common,
                            )
                except httpx.TimeoutException:
                    return AttachmentCheck(
                        status=STATUS_PENDING,
                        reason=f"下载超时（已读取 {len(data)} 字节）",
                        size=len(data),
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )
                except httpx.HTTPError as exc:
                    return AttachmentCheck(
                        status=STATUS_PENDING,
                        reason=f"读取附件失败：{exc}",
                        size=len(data),
                        content_type=content_type,
                        final_url=current,
                        **common,
                    )

                status, reason, actual = validate_content(bytes(data), declared_ext, content_type)
                return AttachmentCheck(
                    status=status,
                    reason=reason,
                    actual_type=actual,
                    size=len(data),
                    content_type=content_type,
                    final_url=current,
                    **common,
                )
        except httpx.TimeoutException:
            return AttachmentCheck(
                status=STATUS_PENDING,
                reason=f"请求超时：{current}",
                final_url=current,
                **common,
            )
        except httpx.HTTPError as exc:
            return AttachmentCheck(
                status=STATUS_PENDING,
                reason=f"请求失败：{exc}",
                final_url=current,
                **common,
            )

    return AttachmentCheck(
        status=STATUS_UNUSABLE,
        reason=f"重定向次数超过 {MAX_REDIRECTS} 次",
        final_url=current,
        **common,
    )


# ---------- 主流程 ----------


def _set_overall(report: AttachmentReport) -> None:
    unusable = report.unusable_count
    pending = report.pending_count
    issues = len(report.issues)

    if unusable:
        report.overall = OVERALL_UNUSABLE
        extra = f"，另有 {issues} 个列表页/详情页无法核定" if issues else ""
        report.overall_reason = f"{unusable} 个附件不可用{extra}，不能判定项目附件全部可用"
    elif issues:
        report.overall = OVERALL_PENDING
        report.overall_reason = f"{issues} 个关联列表页/详情页无法核定，不能判定项目附件全部可用"
    elif pending:
        report.overall = OVERALL_PENDING
        report.overall_reason = f"{pending} 个附件待核实，不能判定项目附件全部可用"
    elif not report.matched_details:
        report.overall = OVERALL_NOT_FOUND
        report.overall_reason = "未找到该项目编号对应的公告，无法核定附件"
    elif not report.attachments:
        report.overall = OVERALL_NOT_FOUND
        report.overall_reason = "项目公告中未找到 PDF/ZIP 附件，无法核定"
    else:
        report.overall = OVERALL_ALL_OK
        report.overall_reason = f"{report.usable_count} 个附件均可用，且关联详情均已读取"


def check_project_attachments(
    directory_url: str,
    project_no: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = REQUEST_TIMEOUT,
    max_bytes: int = MAX_BYTES,
) -> AttachmentReport:
    """沿公告目录同源分页/详情读取指定项目的 PDF/ZIP 附件并核查。

    参数 client / timeout / max_bytes 主要便于测试注入；默认使用真实 HTTP。
    """
    directory_url = (directory_url or "").strip()
    project_no = (project_no or "").strip()
    if not _is_http(directory_url):
        raise AttachmentURLInvalid("公告目录 URL 必须是 http(s) 网址")
    if not project_no:
        raise AttachmentURLInvalid("项目编号不能为空")

    owns_client = client is None
    if owns_client:
        client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    report = AttachmentReport(project_no=project_no, directory_url=directory_url)
    try:
        _scan(client, directory_url, project_no, report, max_bytes)
    finally:
        if owns_client:
            client.close()
    _set_overall(report)
    return report


def _scan(
    client: httpx.Client,
    directory_url: str,
    project_no: str,
    report: AttachmentReport,
    max_bytes: int,
) -> None:
    # 1) 遍历同源分页，收集同源详情链接
    queue = [directory_url]
    visited_lists: set[str] = set()
    detail_urls: list[str] = []
    seen_details: set[str] = set()

    while queue:
        url = queue.pop(0)
        if url in visited_lists:
            continue
        if len(visited_lists) >= MAX_LIST_PAGES:
            report.issues.append(DetailIssue(url, f"列表页数量超过上限 {MAX_LIST_PAGES}，未继续读取"))
            break
        try:
            html = _fetch_page(client, url, directory_url)
        except _PageError as exc:
            report.issues.append(DetailIssue(url, exc.reason))
            visited_lists.add(url)
            continue

        soup = BeautifulSoup(html, "html.parser")
        items = soup.select("ul.notice-list a[href]")
        nav_links = soup.select("nav.pagination a[href]")
        if not items and not nav_links:
            report.issues.append(
                DetailIssue(url, "页面结构不符：未找到公告列表（ul.notice-list）或分页导航（nav.pagination）")
            )

        for a in items:
            href = _normalize(a["href"], url)
            # 按同源规则只读取本站详情；站外详情链接不跟随
            if same_origin(href, directory_url) and href not in seen_details:
                seen_details.add(href)
                detail_urls.append(href)

        visited_lists.add(url)
        report.list_pages.append(url)
        for a in nav_links:
            href = _normalize(a["href"], url)
            if same_origin(href, directory_url) and href not in visited_lists and href not in queue:
                queue.append(href)

    # 2) 逐个读取详情，筛出目标项目，收集附件引用
    refs_by_url: dict[str, list[AttachmentRef]] = {}
    for index, detail_url in enumerate(detail_urls):
        if index >= MAX_DETAIL_PAGES:
            report.issues.append(DetailIssue(detail_url, f"详情页数量超过上限 {MAX_DETAIL_PAGES}，未继续读取"))
            break
        try:
            html = _fetch_page(client, detail_url, directory_url)
        except _PageError as exc:
            # 不知道失败详情属于哪个项目，因此整体不能判定全部可用
            report.issues.append(DetailIssue(detail_url, f"详情读取失败：{exc.reason}"))
            continue

        try:
            announcement = parse_detail(html, detail_url)
        except ScrapeError as exc:
            report.issues.append(DetailIssue(detail_url, f"详情解析失败：{exc.message}"))
            continue

        report.scanned_details += 1
        if announcement.project_no != project_no:
            continue

        report.matched_details.append(
            {
                "notice_no": announcement.notice_no,
                "title": announcement.title,
                "type_label": announcement.type_label,
                "publish_time": announcement.publish_time,
                "url": detail_url,
            }
        )

        for link in parse_attachment_links(html, detail_url):
            link.notice_no = announcement.notice_no
            group = refs_by_url.setdefault(link.url, [])
            if len(group) >= MAX_ATTACHMENTS:
                report.issues.append(
                    DetailIssue(detail_url, f"附件数量超过上限 {MAX_ATTACHMENTS}，部分附件未纳入核查")
                )
                continue
            # 同一公告对同一网址只保留一条引用
            if any(r.notice_no == link.notice_no and r.detail_url == link.detail_url for r in group):
                continue
            group.append(link)

    # 3) 每个唯一网址只下载一次，引用合并保留
    for url, refs in refs_by_url.items():
        report.attachments.append(
            _check_one_attachment(client, url, refs, directory_url, max_bytes)
        )
