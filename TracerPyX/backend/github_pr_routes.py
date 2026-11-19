"""GitHub App OAuth, repository/PR discovery, asynchronous PR jobs, and optional review publishing."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from backend import pr_storage
from backend.github_pr_analysis import JobCancelled, analyze_pull_request, normalize_changed_files
from integrations.github_app import (ANALYZER_VERSION, GitHubAPIError, GitHubAppClient,
                                     GitHubCoverageError, app_configured, app_slug,
                                     authorization_url, exchange_code)

log = logging.getLogger("tracerpyx.github_pr_api")
router = APIRouter(prefix="/api/github", tags=["GitHub PR analysis"])
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tracerpyx-pr")
_cookie_secure = os.getenv("GITHUB_COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE = "tracerpyx_github_session"
STATE_COOKIE = "tracerpyx_github_state"
STAGE_ORDER = ["fetching_repository", "resolving_commits", "detecting_changed_files", "building_project_context",
               "base_parsing_python_files", "base_building_call_graph", "base_running_vulnerability_detection",
               "base_running_reachability_analysis", "head_parsing_python_files", "head_building_call_graph",
               "head_running_vulnerability_detection", "head_running_reachability_analysis",
               "comparing_base_and_head", "generating_final_report", "complete"]


class AnalyzePRRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=300)
    number: int = Field(gt=0)
    force_refresh: bool = False


class PublishRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=200)
    publish_summary: bool = True


class JobTimeout(Exception):
    pass


def _fernet() -> Fernet:
    key = os.getenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError("GitHub credential encryption is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("GitHub credential encryption configuration is invalid") from exc


def _configuration_ready() -> bool:
    if not app_configured():
        return False
    try:
        _fernet()
        return True
    except RuntimeError:
        return False


def _cookie(response: Response, name: str, value: str, *, max_age: int, path: str = "/") -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, secure=_cookie_secure, samesite="lax", path=path)


def _frontend_url() -> str:
    return os.getenv("GITHUB_FRONTEND_URL", "http://localhost:3000").rstrip("/")


def _encrypt_credentials(credentials: dict) -> str:
    return _fernet().encrypt(json.dumps(credentials, separators=(",", ":")).encode()).decode("ascii")


def _decrypt_credentials(ciphertext: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(ciphertext.encode("ascii")))
    except (InvalidToken, ValueError, UnicodeEncodeError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "GitHub credentials could not be read; reconnect the GitHub account.") from exc


def _session_hash(request: Request) -> str:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(401, "Connect GitHub before using this endpoint.")
    digest = pr_storage.hash_session(raw)
    if not pr_storage.get_session(digest):
        raise HTTPException(401, "GitHub connection expired. Reconnect the GitHub account.")
    return digest


def _verify_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    expected = urlparse(os.getenv("TRACERPYX_FRONTEND_ORIGIN", "http://localhost:3000")).netloc
    scheme = urlparse(os.getenv("TRACERPYX_FRONTEND_ORIGIN", "http://localhost:3000")).scheme
    if not origin or urlparse(origin).netloc != expected or urlparse(origin).scheme != scheme:
        raise HTTPException(403, "Request origin is not allowed.")


def _user_credentials(session_hash: str) -> dict:
    row = pr_storage.get_session(session_hash)
    if not row:
        raise HTTPException(401, "GitHub connection expired. Reconnect the GitHub account.")
    credentials = _decrypt_credentials(row["token_ciphertext"])
    expires_at = credentials.get("expires_at")
    if expires_at and expires_at <= time.time() + 60:
        refresh_token = credentials.get("refresh_token")
        if not refresh_token or (credentials.get("refresh_expires_at") and credentials["refresh_expires_at"] <= time.time()):
            pr_storage.delete_session(session_hash)
            raise HTTPException(401, "GitHub authorization expired. Reconnect the GitHub account.")
        try:
            credentials = GitHubAppClient().refresh_user_token(refresh_token)
        except GitHubAPIError as exc:
            if exc.status in {401, 403}:
                pr_storage.delete_session(session_hash)
                raise HTTPException(401, "GitHub authorization expired or was revoked. Reconnect the GitHub account.") from exc
            raise HTTPException(503, exc.reason) from exc
        pr_storage.put_session(session_hash, _encrypt_credentials(credentials), row["login"])
    return credentials


def _user_token(session_hash: str) -> str:
    token = _user_credentials(session_hash).get("access_token")
    if not token:
        pr_storage.delete_session(session_hash)
        raise HTTPException(401, "GitHub authorization expired. Reconnect the GitHub account.")
    return token


def _client_error(exc: Exception, session_hash: str | None = None) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, GitHubAPIError):
        if exc.status == 401:
            if session_hash:
                pr_storage.delete_session(session_hash)
            return HTTPException(401, "GitHub authorization expired or was revoked. Reconnect the GitHub account.")
        status = 429 if exc.status == 429 or exc.status == 403 and "rate limit" in exc.reason.lower() else exc.status
        return HTTPException(status if 400 <= status < 500 else 503, exc.reason)
    if isinstance(exc, GitHubCoverageError):
        return HTTPException(413, str(exc))
    return HTTPException(503, "GitHub request could not be completed. Retry shortly.")


def _job_view(row: dict) -> dict:
    result = json.loads(row["result_json"]) if row.get("result_json") else None
    return {"job_id": row["job_id"], "status": row["status"], "stage": row["stage"], "stage_order": STAGE_ORDER,
            "created_at": row["created_at"], "updated_at": row["updated_at"], "error": row.get("error"),
            "result_available": row["status"] == "complete", "result": result if row["status"] == "complete" else None}


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    if isinstance(exc, GitHubAPIError):
        if exc.status == 401:
            return "GitHub authorization expired or was revoked. Reconnect the GitHub account."
        return exc.reason
    if isinstance(exc, GitHubCoverageError):
        return str(exc)
    if isinstance(exc, JobTimeout):
        return "Analysis exceeded the 30-minute job time limit. Reduce repository scope or split the pull request and retry."
    return "Analysis could not be completed. Check the repository permissions and try again."


def _run_job(job: dict) -> None:
    job_id, session_hash = job["job_id"], job["session_hash"]
    started = time.monotonic()
    try:
        def check_cancel() -> bool:
            if pr_storage.cancelled(job_id):
                raise JobCancelled()
            if time.monotonic() - started > 30 * 60:
                raise JobTimeout()
            return False
            return False

        def stage(name: str) -> None:
            check_cancel()
            pr_storage.update_job(job_id, status="running", stage=name)
            log.info("github_pr_stage job_id=%s repository=%s stage=%s", job_id, job["full_name"], name)

        stage("fetching_repository")
        user_token = _user_credentials(session_hash)["access_token"]
        client = GitHubAppClient()
        base_repo = client.get_json(f"/repos/{quote(job['full_name'], safe='/')}", token=client.repository_token(job["full_name"], user_token))
        stage("resolving_commits")
        pull = client.pull_request(job["full_name"], int(job["pr_number"]), user_token)
        if pull.get("base", {}).get("sha") != job["base_sha"] or pull.get("head", {}).get("sha") != job["head_sha"]:
            raise GitHubCoverageError("The PR commits changed after analysis was queued. Start a new analysis to pin the current commit pair.")
        stage("detecting_changed_files")
        file_items = client.pull_request_files(job["full_name"], int(job["pr_number"]), user_token)
        current_pull = client.pull_request(job["full_name"], int(job["pr_number"]), user_token)
        if current_pull.get("base", {}).get("sha") != job["base_sha"] or current_pull.get("head", {}).get("sha") != job["head_sha"]:
            raise GitHubCoverageError("The PR commits changed while diff metadata was fetched. Start a new analysis to pin the current commit pair.")
        report = analyze_pull_request(client, user_token, base_repo, pull, file_items, stage, check_cancel)
        pr_storage.update_job(job_id, status="complete", stage="complete", result=report, cache_key=job["cache_key"])
        log.info("github_pr_complete job_id=%s repository=%s base=%s head=%s findings=%d", job_id, job["full_name"], job["base_sha"], job["head_sha"], len(report.get("findings", [])))
    except JobCancelled:
        pr_storage.update_job(job_id, status="cancelled", stage="cancelled", error="Analysis was cancelled.")
    except Exception as exc:
        pr_storage.update_job(job_id, status="failed", stage="failed", error=_safe_error(exc))
        if isinstance(exc, GitHubAPIError) and exc.status == 401:
            pr_storage.delete_session(session_hash)
        log.error("github_pr_failed job_id=%s repository=%s error_type=%s", job_id, job.get("full_name"), type(exc).__name__)


@router.get("/auth/status")
def github_auth_status(request: Request):
    configured = _configuration_ready()
    raw = request.cookies.get(SESSION_COOKIE)
    connected, login = False, None
    if raw:
        row = pr_storage.get_session(pr_storage.hash_session(raw))
        if row:
            connected, login = True, row["login"]
    slug = app_slug()
    return {"configured": configured, "connected": connected, "login": login,
            "app_install_url": f"https://github.com/apps/{quote(slug)}/installations/new" if slug else None,
            "required_permissions": {"metadata": "read", "contents": "read", "pull_requests": "read and write for optional review publishing"},
            "configuration_message": None if configured else "Configure the GitHub App credentials and TRACERPYX_GITHUB_ENCRYPTION_KEY on the backend."}


@router.get("/auth/start")
def github_auth_start():
    if not _configuration_ready():
        raise HTTPException(503, "GitHub App connection is not configured on the backend.")
    state = secrets.token_urlsafe(32)
    response = RedirectResponse(authorization_url(state), status_code=302)
    _cookie(response, STATE_COOKIE, state, max_age=600, path="/api/github/auth")
    return response


@router.get("/auth/callback")
def github_auth_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    frontend = _frontend_url()
    expected = request.cookies.get(STATE_COOKIE)
    if error or not code or not state or not expected or not secrets.compare_digest(state, expected):
        response = RedirectResponse(f"{frontend}/?github=error&reason=authorization", status_code=303)
        response.delete_cookie(STATE_COOKIE, path="/api/github/auth")
        return response
    if not _configuration_ready():
        response = RedirectResponse(f"{frontend}/?github=error&reason=configuration", status_code=303)
        response.delete_cookie(STATE_COOKIE, path="/api/github/auth")
        return response
    try:
        credentials = exchange_code(code)
        viewer = GitHubAppClient().viewer(credentials["access_token"])
        session = secrets.token_urlsafe(32)
        pr_storage.put_session(pr_storage.hash_session(session), _encrypt_credentials(credentials), viewer.get("login", "GitHub user"))
        response = RedirectResponse(f"{frontend}/?github=connected", status_code=303)
        _cookie(response, SESSION_COOKIE, session, max_age=60 * 60 * 24 * 30)
    except Exception:
        response = RedirectResponse(f"{frontend}/?github=error&reason=exchange", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/api/github/auth")
    return response


@router.post("/auth/disconnect")
def github_auth_disconnect(request: Request, response: Response):
    _verify_origin(request)
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        session_hash = pr_storage.hash_session(raw)
        row = pr_storage.get_session(session_hash)
        if row:
            try:
                credentials = _decrypt_credentials(row["token_ciphertext"])
                GitHubAppClient().revoke_user_token(credentials["access_token"])
            except Exception:
                pass
            pr_storage.delete_session(session_hash)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"connected": False, "message": "GitHub connection removed."}


@router.get("/repositories")
def github_repositories(request: Request, q: str = Query(default="", max_length=200)):
    session_hash = _session_hash(request)
    try:
        repos = GitHubAppClient().list_repositories(_user_token(session_hash), q)
    except Exception as exc:
        raise _client_error(exc, session_hash) from exc
    return {"repositories": [{"id": r.get("id"), "full_name": r.get("full_name"), "private": bool(r.get("private")),
                               "html_url": r.get("html_url"), "default_branch": r.get("default_branch"),
                               "description": r.get("description"), "permissions": r.get("permissions"),
                               "installed": bool(r.get("_tracerpyx_installation_id"))} for r in repos]}


@router.get("/repositories/{owner}/{repo}/pull-requests")
def github_pull_requests(owner: str, repo: str, request: Request,
                         state: str = Query(default="open", pattern="^(open|closed|all)$")):
    session_hash = _session_hash(request)
    if not _valid_repository(f"{owner}/{repo}"):
        raise HTTPException(422, "Repository must use the owner/repository format.")
    try:
        pulls = GitHubAppClient().list_pull_requests(f"{owner}/{repo}", _user_token(session_hash), state=state)
    except Exception as exc:
        raise _client_error(exc, session_hash) from exc
    return {"pull_requests": [{"number": p.get("number"), "title": p.get("title"), "state": p.get("state"),
                               "draft": p.get("draft"), "html_url": p.get("html_url"),
                               "author": (p.get("user") or {}).get("login"),
                               "base_branch": (p.get("base") or {}).get("ref"),
                               "head_branch": (p.get("head") or {}).get("ref"),
                               "base_sha": (p.get("base") or {}).get("sha"),
                               "head_sha": (p.get("head") or {}).get("sha"),
                               "head_repository": (p.get("head") or {}).get("repo", {}).get("full_name")}
                              for p in pulls]}


@router.get("/repositories/{owner}/{repo}/pull-requests/{number}")
def github_pull_request_detail(owner: str, repo: str, number: int, request: Request):
    session_hash = _session_hash(request)
    full_name = f"{owner}/{repo}"
    if not _valid_repository(full_name):
        raise HTTPException(422, "Repository must use the owner/repository format.")
    try:
        client = GitHubAppClient()
        user_token = _user_token(session_hash)
        pull = client.pull_request(full_name, number, user_token)
        files = client.pull_request_files(full_name, number, user_token)
        changed, _added, _deleted, warnings = normalize_changed_files(files)
    except Exception as exc:
        raise _client_error(exc, session_hash) from exc
    return {"number": number, "title": pull.get("title"), "body": pull.get("body"), "state": pull.get("state"),
            "draft": pull.get("draft"), "html_url": pull.get("html_url"), "author": (pull.get("user") or {}).get("login"),
            "base_branch": pull["base"].get("ref"), "base_sha": pull["base"].get("sha"),
            "head_branch": pull["head"].get("ref"), "head_sha": pull["head"].get("sha"),
            "head_repository": (pull.get("head", {}).get("repo") or {}).get("full_name"),
            "changed_files": changed, "diff_warnings": warnings}


def _valid_repository(value: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value))


@router.post("/analyze")
def analyze_pr(payload: AnalyzePRRequest, request: Request):
    _verify_origin(request)
    session_hash = _session_hash(request)
    if not _configuration_ready():
        raise HTTPException(503, "GitHub App connection is not configured on the backend.")
    if not _valid_repository(payload.repository):
        raise HTTPException(422, "Repository must use the owner/repository format.")
    try:
        client = GitHubAppClient()
        user_token = _user_token(session_hash)
        repo = client.get_json(f"/repos/{quote(payload.repository, safe='/')}", token=client.repository_token(payload.repository, user_token))
        pull = client.pull_request(payload.repository, payload.number, user_token)
    except Exception as exc:
        raise _client_error(exc, session_hash) from exc
    base_sha, head_sha = pull.get("base", {}).get("sha"), pull.get("head", {}).get("sha")
    if not base_sha or not head_sha:
        raise HTTPException(502, "GitHub did not return pinned base and head commit SHAs.")
    cache_key = hashlib.sha256(f"{repo.get('id')}:{payload.number}:{base_sha}:{head_sha}:{ANALYZER_VERSION}".encode()).hexdigest()
    row, reused = pr_storage.create_job(session_hash=session_hash, cache_key=cache_key, repo_id=int(repo["id"]),
                                        full_name=payload.repository, pr_number=payload.number, base_sha=base_sha,
                                        head_sha=head_sha, force_refresh=payload.force_refresh)
    if row["status"] == "complete" and row.get("result_json"):
        cached_report = json.loads(row["result_json"])
        cached_report["pull_request"].update({"title": pull.get("title"), "body": pull.get("body"),
                                              "state": pull.get("state"), "draft": pull.get("draft"),
                                              "html_url": pull.get("html_url"), "author": (pull.get("user") or {}).get("login"),
                                              "base_branch": (pull.get("base") or {}).get("ref"),
                                              "head_branch": (pull.get("head") or {}).get("ref"),
                                              "head_repository": (pull.get("head", {}).get("repo") or {}).get("full_name")})
        pr_storage.update_job(row["job_id"], result=cached_report)
        row["result_json"] = json.dumps(cached_report, ensure_ascii=False, separators=(",", ":"))
    if row["status"] == "queued" and not reused:
        _executor.submit(_run_job, row)
    return {"job_id": row["job_id"], "status": row["status"], "stage": row["stage"],
            "reused": reused, "base_sha": base_sha, "head_sha": head_sha}


@router.get("/jobs/{job_id}")
def github_job_status(job_id: str, request: Request):
    row = pr_storage.get_job(job_id, _session_hash(request))
    if not row:
        raise HTTPException(404, "Analysis job not found.")
    return _job_view(row)


@router.get("/jobs/{job_id}/result")
def github_job_result(job_id: str, request: Request):
    row = pr_storage.get_job(job_id, _session_hash(request))
    if not row:
        raise HTTPException(404, "Analysis job not found.")
    if row["status"] != "complete" or not row.get("result_json"):
        raise HTTPException(409, "Analysis result is not ready.")
    return json.loads(row["result_json"])


@router.get("/jobs/{job_id}/comparison")
def github_job_comparison(job_id: str, request: Request):
    row = pr_storage.get_job(job_id, _session_hash(request))
    if not row:
        raise HTTPException(404, "Analysis job not found.")
    if row["status"] != "complete" or not row.get("result_json"):
        raise HTTPException(409, "Base-versus-head comparison is not ready.")
    report = json.loads(row["result_json"])
    findings = report.get("findings", [])
    return {"base_sha": report["base_sha"], "head_sha": report["head_sha"],
            "summary": report.get("summary", {}),
            "introduced": [item for item in findings if item.get("classification") == "introduced"],
            "worsened": [item for item in findings if item.get("classification") == "worsened"],
            "pre_existing": [item for item in findings if item.get("classification") == "pre_existing"],
            "uncertain_attribution": [item for item in findings if item.get("classification") == "uncertain_attribution"],
            "fixed": report.get("fixed_findings", []),
            "dependency_changes": report.get("dependency_changes", {})}


@router.post("/jobs/{job_id}/cancel")
def github_job_cancel(job_id: str, request: Request):
    _verify_origin(request)
    if not pr_storage.request_cancel(job_id, _session_hash(request)):
        raise HTTPException(409, "Analysis is complete, failed, cancelled, or could not be cancelled.")
    return {"job_id": job_id, "status": "cancellation_requested"}


def _clean_comment(value: str, limit: int = 2500) -> str:
    value = " ".join(value.replace("```", "''' ").replace("`", "'").replace("@", "＠").splitlines())
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = value.replace("*", "\\*").replace("[", "\\[").replace("]", "\\]")
    return value[:limit]


def _remediation(finding: dict) -> str:
    text = (finding.get("title", "") + " " + " ".join(finding.get("cwe") or [])).lower()
    if "89" in text or "sql" in text:
        return "Use parameterized SQL with bound values; do not concatenate untrusted data into query text."
    if "95" in text or "dynamic code" in text:
        return "Remove eval/exec for untrusted input; use a strict parser and an explicit allowlist of supported operations."
    if "78" in text or "subprocess" in text:
        return "Pass an argument list to subprocess with shell=False and validate each argument."
    if "502" in text or "deserial" in text:
        return "Use a safe data format or a restricted loader; never deserialize attacker-controlled objects."
    if "22" in text or "path" in text:
        return "Resolve the requested path under an approved root and reject paths that escape it."
    if "79" in text or "template" in text:
        return "Render a fixed template with escaped values; do not compile user-controlled template source."
    return "Validate the input at the boundary and use the safe API recommended by the relevant advisory."


@router.post("/jobs/{job_id}/publish")
def github_publish(job_id: str, payload: PublishRequest, request: Request):
    _verify_origin(request)
    session_hash = _session_hash(request)
    row = pr_storage.get_job(job_id, session_hash)
    if not row or row["status"] != "complete" or not row.get("result_json"):
        raise HTTPException(404, "Completed analysis job not found.")
    report = json.loads(row["result_json"])
    selected = set(payload.finding_ids)
    findings = [f for f in report.get("findings", []) if f.get("finding_id") in selected]
    if selected - {f.get("finding_id") for f in findings}:
        raise HTTPException(422, "One or more selected findings are unavailable in this report.")
    inline = []
    for finding in findings:
        if not finding.get("review_commentable") or not finding.get("file") or not isinstance(finding.get("line"), int):
            continue
        marker = f"<!-- tracerpyx:finding:{finding['finding_id']} -->"
        evidence = "\n".join(f"- {_clean_comment(str(item), 500)}" for item in finding.get("evidence", [])[:4])
        if not evidence:
            evidence = "- Static analyzer finding; review the evidence and reachability fields in TracerPyX."
        body = (f"{marker}\n**{_clean_comment(finding.get('severity', 'unknown').upper(), 40)} · "
                f"{_clean_comment(finding.get('title', 'Security finding'))}**\n\n"
                f"**Classification:** {_clean_comment(finding.get('classification', 'uncertain_attribution'), 80)}. "
                f"{_clean_comment(finding.get('classification_explanation', ''), 500)}\n\n"
                f"**Confidence:** pattern { _clean_comment(str(finding.get('confidence', 'unknown')), 30) }; "
                f"reachability { _clean_comment(str(finding.get('reachability_confidence', 'unknown')), 30) }.\n\n"
                f"**Reachability:** {_clean_comment(finding.get('reachability', 'uncertain'), 80)}. "
                f"{_clean_comment(finding.get('reachability_explanation', ''), 500)}\n\n"
                f"**Call path:** {_clean_comment(' → '.join(finding.get('call_path') or []) or 'Not established', 1000)}\n\n"
                f"**Evidence**\n{evidence}\n\n**Suggested remediation:** {_remediation(finding)}\n\n"
                "Taint flow and exploitability were not established by the current analyzer.")
        recommendation = finding.get("remediation")
        example = finding.get("remediation_example")
        if recommendation:
            body = body.replace(_remediation(finding), _clean_comment(recommendation, 1000))
        if example:
            body += "\n\n**Example:**\n```python\n" + str(example).replace("```", "")[:1000] + "\n```"
        inline.append({"path": finding["file"], "line": finding["line"], "side": "RIGHT", "body": body})
    summary_lines = ["## TracerPyX security analysis", "",
                     f"Repository: `{report['repository']['full_name']}` · PR #{report['pull_request']['number']}",
                     f"Base `{report['base_sha'][:12]}` → head `{report['head_sha'][:12]}`", "",
                     f"Findings: {report['summary']['total_findings']} · introduced {report['summary']['introduced']} · worsened {report['summary']['worsened']} · fixed {report['summary']['fixed']} · pre-existing {report['summary']['pre_existing']} · uncertain attribution {report['summary']['uncertain_attribution']}",
                     "", "TracerPyX is a static heuristic analyzer. Call-graph reachability does not prove attacker-controlled input or exploitability."]
    if report.get("findings"):
        summary_lines.extend(["", "### Findings at the PR head"])
        for finding in report["findings"][:25]:
            location = f"{finding['file']}:{finding['line']}" if finding.get("file") and finding.get("line") else f"{finding.get('package', 'dependency')} {finding.get('declared_version', '')}".strip()
            summary_lines.append(f"- **{_clean_comment(str(finding.get('severity', 'unknown')).upper(), 24)} · {_clean_comment(str(finding.get('classification', 'uncertain_attribution')), 40)}** `{_clean_comment(location, 300)}` — {_clean_comment(str(finding.get('title', 'Security finding')), 300)}; reachability: {_clean_comment(str(finding.get('reachability', 'uncertain')), 60)}.")
            if finding.get("evidence"):
                summary_lines.append(f"  - Evidence: {_clean_comment(str(finding['evidence'][0]), 400)}")
            if finding.get("remediation"):
                summary_lines.append(f"  - Suggested fix: {_clean_comment(str(finding['remediation']), 400)}")
        if len(report["findings"]) > 25:
            summary_lines.append(f"- {len(report['findings']) - 25} additional head findings are listed in the TracerPyX report.")
    if report.get("fixed_findings"):
        summary_lines.extend(["", "### Findings absent at the PR head"])
        for finding in report["fixed_findings"][:15]:
            location = f"{finding['file']}:{finding['line']}" if finding.get("file") and finding.get("line") else finding.get("package", "dependency")
            summary_lines.append(f"- **{_clean_comment(str(finding.get('classification', 'uncertain_attribution')), 40)}** `{_clean_comment(location, 300)}` — {_clean_comment(str(finding.get('title', 'Security finding')), 300)}. {_clean_comment(str(finding.get('classification_explanation', '')), 400)}")
        if len(report["fixed_findings"]) > 15:
            summary_lines.append(f"- {len(report['fixed_findings']) - 15} additional base findings are listed in the TracerPyX report.")
    if report.get("analysis_warnings"):
        summary_lines.extend(["", "Coverage notes:", *[f"- {_clean_comment(w, 300)}" for w in report["analysis_warnings"][:20]]])
    summary = "\n".join(summary_lines) if payload.publish_summary else None
    if summary is None and not inline:
        raise HTTPException(422, "Select at least one valid diff finding or enable the PR summary comment.")
    try:
        client = GitHubAppClient()
        current = client.pull_request(row["full_name"], int(row["pr_number"]), _user_token(session_hash))
        if (current.get("head", {}).get("sha") != report["head_sha"] or
                current.get("base", {}).get("sha") != report["base_sha"]):
            raise HTTPException(409, "The PR base or head changed after analysis. Rerun analysis before publishing comments.")
        published = client.create_or_update_review(row["full_name"], int(row["pr_number"]), _user_token(session_hash),
                                                   report["head_sha"], summary, inline,
                                                   resolved_comments=[item for item in report.get("fixed_findings", [])
                                                                      if item.get("classification") == "fixed"])
    except HTTPException:
        raise
    except Exception as exc:
        raise _client_error(exc, session_hash) from exc
    return {"published": True, **published,
            "inline_skipped": len([f for f in findings if not f.get("review_commentable")])}
