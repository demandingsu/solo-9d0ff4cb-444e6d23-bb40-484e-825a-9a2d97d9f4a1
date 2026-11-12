"""截标时间核对工具（FastAPI 网页）。

用法：输入与示例公告站同结构的列表网址，点击“开始抓取”，系统抓取同源
分页与全部详情页，按项目串起公告链，给出每个项目的最终截标时间与状态。
另提供“项目附件核查”页：按公告目录 + 项目编号核对 PDF/ZIP 附件是否真实可用。
"""

import os
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import analysis
import attachments
import db
import scraper

DEFAULT_START_URL = os.environ.get("DEFAULT_START_URL", "http://sample-site:8000/list.html?page=1")
# 展示层网址改写：容器内部地址 → 浏览器可访问地址（可选）
URL_REWRITE_FROM = os.environ.get("URL_REWRITE_FROM", "")
URL_REWRITE_TO = os.environ.get("URL_REWRITE_TO", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="截标时间核对工具", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")


def public_url(url: str) -> str:
    """把采集用的内部网址改写成浏览器可访问的网址（未配置时原样返回）。"""
    if URL_REWRITE_FROM and URL_REWRITE_TO and url.startswith(URL_REWRITE_FROM):
        return URL_REWRITE_TO + url[len(URL_REWRITE_FROM) :]
    return url


templates.env.filters["public_url"] = public_url


@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str = ""):
    rounds = db.get_rounds()
    latest_ok = db.get_latest_success_round()
    projects = None
    if latest_ok is not None:
        projects = analysis.build_projects(db.get_announcements(latest_ok["id"]))
    last_round = rounds[0] if rounds else None
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "default_start_url": DEFAULT_START_URL,
            "msg": msg,
            "last_round": last_round,
            "latest_ok": latest_ok,
            "projects": projects,
            "rounds": rounds,
        },
    )


@app.post("/scrape")
def do_scrape(start_url: str = Form(...)):
    start_url = start_url.strip()
    round_id = db.create_round(start_url)
    try:
        result = scraper.scrape(start_url)
    except scraper.ScrapeError as exc:
        # 任一页面失败：记录出错网址，本轮不产生数据，页面仍展示上一轮结果
        db.finish_round_failed(round_id, exc.url, exc.message)
        msg = f"第 {round_id} 轮抓取失败：{exc.url}（{exc.message}）。已保留上一轮结果。"
        return RedirectResponse(f"/?msg={quote(msg)}", status_code=303)
    except Exception as exc:  # 兜底，避免未预期异常丢轮次
        db.finish_round_failed(round_id, start_url, f"未预期错误：{exc!r}")
        msg = f"第 {round_id} 轮抓取失败：{start_url}（{exc!r}）。已保留上一轮结果。"
        return RedirectResponse(f"/?msg={quote(msg)}", status_code=303)

    db.finish_round_success(round_id, result.announcements, len(result.list_pages), len(result.detail_pages))
    msg = (
        f"第 {round_id} 轮抓取成功：{len(result.list_pages)} 个列表页、"
        f"{len(result.detail_pages)} 个详情页，共 {len(result.announcements)} 条公告。"
    )
    return RedirectResponse(f"/?msg={quote(msg)}", status_code=303)


def _render_attachment_page(
    request: Request,
    *,
    report: attachments.AttachmentReport | None = None,
    error: str = "",
    project_no: str = "",
    directory_url: str = "",
):
    banner_class = "ok"
    if report is not None:
        banner_class = {
            attachments.OVERALL_ALL_OK: "ok",
            attachments.OVERALL_UNUSABLE: "err",
            attachments.OVERALL_PENDING: "warn",
            attachments.OVERALL_NOT_FOUND: "warn",
        }[report.overall]
    return templates.TemplateResponse(
        request,
        "attachments.html",
        {
            "default_start_url": directory_url or DEFAULT_START_URL,
            "project_no": project_no,
            "report": report,
            "error": error,
            "banner_class": banner_class,
        },
    )


@app.get("/attachments", response_class=HTMLResponse)
def attachments_page(request: Request):
    return _render_attachment_page(request)


@app.post("/attachments/check", response_class=HTMLResponse)
def check_attachments(
    request: Request,
    directory_url: str = Form(...),
    project_no: str = Form(...),
):
    directory_url = directory_url.strip()
    project_no = project_no.strip()
    try:
        report = attachments.check_project_attachments(directory_url, project_no)
    except attachments.AttachmentURLInvalid as exc:
        return _render_attachment_page(
            request, error=str(exc), project_no=project_no, directory_url=directory_url
        )
    except Exception as exc:  # 兜底，避免页面对未预期异常直接 500
        return _render_attachment_page(
            request, error=f"核查未完成：{exc!r}", project_no=project_no, directory_url=directory_url
        )
    return _render_attachment_page(request, report=report, project_no=project_no)
