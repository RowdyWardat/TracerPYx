"""Minimal GitHub App REST client. Secrets and installation tokens stay server-side."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from urllib.parse import quote, urlencode, urlparse

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


API = "https://api.github.com"
WEB = "https://github.com"
ANALYZER_VERSION = "tracerpyx-pr-2"
MAX_PAGES = 1000


class GitHubAPIError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class GitHubCoverageError(Exception):
    pass


def app_configured() -> bool:
    required = (os.getenv("GITHUB_APP_ID"), os.getenv("GITHUB_CLIENT_ID"), os.getenv("GITHUB_APP_SLUG"),
                os.getenv("GITHUB_CLIENT_SECRET"), os.getenv("GITHUB_APP_PRIVATE_KEY_PEM") or
                os.getenv("GITHUB_APP_PRIVATE_KEY_PATH"))
    if not all(required):
        return False
    try:
        return isinstance(load_private_key(), rsa.RSAPrivateKey)
    except Exception:
        # Connection status must not claim the App can mint installation tokens
        # when its signing key is missing, unreadable, or invalid.
        return False


def app_slug() -> str:
    return os.getenv("GITHUB_APP_SLUG", "")


def callback_url() -> str:
    return os.getenv("GITHUB_CALLBACK_URL", "http://localhost:8000/api/github/auth/callback")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_private_key():
    pem = os.getenv("GITHUB_APP_PRIVATE_KEY_PEM")
    if not pem:
        key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
        if not key_path:
            raise RuntimeError("GitHub App signing key is not configured")
        with open(key_path, "rb") as handle:
            pem_bytes = handle.read()
    else:
        pem_bytes = pem.replace("\\n", "\n").encode("utf-8")
    return serialization.load_pem_private_key(pem_bytes, password=None)


def app_jwt(now: int | None = None) -> str:
    issued = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": issued - 60, "exp": issued + 540,
                                "iss": os.environ["GITHUB_APP_ID"]}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = load_private_key().sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def authorization_url(state: str) -> str:
    params = {"client_id": os.environ["GITHUB_CLIENT_ID"], "redirect_uri": callback_url(), "state": state}
    return f"{WEB}/login/oauth/authorize?{urlencode(params)}"


def exchange_code(code: str) -> dict:
    try:
        response = httpx.post(f"{WEB}/login/oauth/access_token", data={
            "client_id": os.environ["GITHUB_CLIENT_ID"],
            "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
            "code": code,
        }, headers={"Accept": "application/json"}, timeout=15)
    except httpx.HTTPError as exc:
        raise GitHubAPIError(503, "GitHub authentication service is unavailable") from exc
    if response.status_code >= 400:
        raise GitHubAPIError(502, "GitHub authentication could not be completed")
    try:
        data = response.json()
    except ValueError as exc:
        raise GitHubAPIError(502, "GitHub returned an invalid authentication response") from exc
    token = data.get("access_token")
    if not token:
        raise GitHubAPIError(401, "GitHub authorization was denied or expired")
    now = time.time()
    return {"access_token": token, "refresh_token": data.get("refresh_token"),
            "expires_at": now + int(data["expires_in"]) if data.get("expires_in") else None,
            "refresh_expires_at": now + int(data["refresh_token_expires_in"]) if data.get("refresh_token_expires_in") else None}


class GitHubAppClient:
    def __init__(self, *, timeout: float = 20, transport=None):
        self.timeout = timeout
        self.transport = transport
        self._install_tokens: dict[int, tuple[str, float]] = {}
        self._repo_installations: dict[str, tuple[dict[str, int], float]] = {}

    def _request(self, method: str, url_or_path: str, *, token: str | None = None,
                 params: dict | None = None, json_body: dict | None = None,
                 accept: str = "application/vnd.github+json") -> httpx.Response:
        url = url_or_path if url_or_path.startswith("https://") else API + url_or_path
        if urlparse(url).netloc != "api.github.com":
            raise GitHubAPIError(400, "GitHub pagination returned an unexpected destination")
        headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in range(3):
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=False, transport=self.transport) as client:
                    response = client.request(method, url, params=params, json=json_body, headers=headers)
            except httpx.HTTPError as exc:
                if attempt < 2:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise GitHubAPIError(503, "Network error while contacting GitHub") from exc
            if response.status_code in {429, 502, 503, 504} or (response.status_code == 403 and (response.headers.get("X-RateLimit-Remaining") == "0" or response.headers.get("Retry-After"))):
                if attempt < 2:
                    retry = response.headers.get("Retry-After")
                    delay = min(max(float(retry), 0), 2) if retry and retry.isdigit() else 0.25 * (attempt + 1)
                    time.sleep(delay)
                    continue
            if response.status_code >= 400:
                rate_limited = response.status_code == 403 and (response.headers.get("X-RateLimit-Remaining") == "0" or response.headers.get("Retry-After"))
                reason = {
                    401: "GitHub authorization expired or was revoked",
                    403: "GitHub API rate limit reached" if rate_limited else "GitHub denied this request; check App installation permissions",
                    404: "GitHub repository, pull request, or commit was not found or is not accessible",
                    422: "GitHub could not process this request",
                    429: "GitHub API rate limit reached",
                }.get(response.status_code, "GitHub API request failed")
                if response.status_code >= 500:
                    reason = "GitHub service is temporarily unavailable"
                raise GitHubAPIError(response.status_code, reason)
            return response
        raise GitHubAPIError(503, "GitHub request could not be completed after retries")

    def get_json(self, path: str, *, token: str | None = None, params: dict | None = None) -> dict:
        response = self._request("GET", path, token=token, params=params)
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubAPIError(502, "GitHub returned an invalid response") from exc

    def post_json(self, path: str, *, token: str, body: dict) -> dict:
        response = self._request("POST", path, token=token, json_body=body)
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubAPIError(502, "GitHub returned an invalid response") from exc

    def paginate(self, path: str, *, token: str | None = None, params: dict | None = None) -> list[dict]:
        query = dict(params or {})
        query.setdefault("per_page", 100)
        query.setdefault("page", 1)
        items: list[dict] = []
        url: str | None = path
        for _ in range(MAX_PAGES):
            response = self._request("GET", url or path, token=token, params=query if url == path else None)
            try:
                page = response.json()
            except ValueError as exc:
                raise GitHubAPIError(502, "GitHub returned an invalid paginated response") from exc
            if not isinstance(page, list):
                if isinstance(page, dict) and any(k in page for k in ("items", "installations", "repositories")):
                    page = page.get("items", page.get("installations", page.get("repositories", [])))
                else:
                    raise GitHubAPIError(502, "GitHub returned an unexpected paginated response")
            items.extend(page)
            link = response.headers.get("Link", "")
            next_url = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part[part.find("<") + 1:part.find(">")]
                    break
            if not next_url:
                return items
            if urlparse(next_url).netloc != "api.github.com":
                raise GitHubAPIError(400, "GitHub pagination returned an unexpected destination")
            url, query = next_url, {}
        raise GitHubCoverageError("GitHub pagination exceeded the configured page safety limit; results are incomplete")

    def viewer(self, user_token: str) -> dict:
        return self.get_json("/user", token=user_token)

    def refresh_user_token(self, refresh_token: str) -> dict:
        try:
            response = httpx.post(f"{WEB}/login/oauth/access_token", data={
                "client_id": os.environ["GITHUB_CLIENT_ID"],
                "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                "grant_type": "refresh_token", "refresh_token": refresh_token,
            }, headers={"Accept": "application/json"}, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise GitHubAPIError(503, "GitHub authentication service is unavailable") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise GitHubAPIError(502, "GitHub returned an invalid token refresh response") from exc
        if response.status_code >= 400 or not data.get("access_token"):
            raise GitHubAPIError(401, "GitHub authorization expired or was revoked")
        now = time.time()
        return {"access_token": data["access_token"], "refresh_token": data.get("refresh_token"),
                "expires_at": now + int(data["expires_in"]) if data.get("expires_in") else None,
                "refresh_expires_at": now + int(data["refresh_token_expires_in"]) if data.get("refresh_token_expires_in") else None}

    def revoke_user_token(self, user_token: str) -> None:
        try:
            response = httpx.request("DELETE", f"{API}/applications/{os.environ['GITHUB_CLIENT_ID']}/grant",
                                     auth=(os.environ["GITHUB_CLIENT_ID"], os.environ["GITHUB_CLIENT_SECRET"]),
                                     json={"access_token": user_token}, timeout=self.timeout)
        except (httpx.HTTPError, KeyError) as exc:
            raise GitHubAPIError(503, "GitHub authorization could not be revoked remotely") from exc
        if response.status_code not in {204, 404} and response.status_code >= 400:
            raise GitHubAPIError(response.status_code, "GitHub authorization could not be revoked remotely")

    def installations(self, user_token: str) -> list[dict]:
        return self.paginate("/user/installations", token=user_token, params={"per_page": 100})

    def installed_repositories(self, user_token: str) -> list[dict]:
        results = []
        for installation in self.installations(user_token):
            installation_id = installation.get("id")
            if not installation_id:
                continue
            repos = self.paginate(f"/user/installations/{installation_id}/repositories", token=user_token, params={"per_page": 100})
            for repo in repos:
                repo["_tracerpyx_installation_id"] = installation_id
                results.append(repo)
        return results

    def installation_token(self, installation_id: int) -> str:
        now = time.time()
        cached = self._install_tokens.get(installation_id)
        if cached and cached[1] > now + 60:
            return cached[0]
        jwt = app_jwt()
        data = self.post_json(f"/app/installations/{installation_id}/access_tokens", token=jwt, body={})
        token = data.get("token")
        expires = data.get("expires_at")
        if not token:
            raise GitHubAPIError(502, "GitHub did not issue an installation token")
        import datetime
        try:
            expiration = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        except (AttributeError, ValueError):
            expiration = now + 3000
        self._install_tokens[installation_id] = (token, expiration)
        return token

    def token_for_repo(self, full_name: str, user_token: str) -> str | None:
        fingerprint = base64.urlsafe_b64encode(hashlib.sha256(user_token.encode()).digest()).decode()
        cached = self._repo_installations.get(fingerprint)
        if not cached or cached[1] < time.time():
            repos = self.installed_repositories(user_token)
            mapping = {r.get("full_name", "").casefold(): int(r["_tracerpyx_installation_id"])
                       for r in repos if r.get("full_name") and r.get("_tracerpyx_installation_id")}
            self._repo_installations[fingerprint] = (mapping, time.time() + 60)
        else:
            mapping = cached[0]
        installation_id = mapping.get(full_name.casefold())
        return self.installation_token(installation_id) if installation_id else None

    def list_repositories(self, user_token: str, query: str = "") -> list[dict]:
        installed = self.installed_repositories(user_token)
        by_name = {r.get("full_name", "").casefold(): r for r in installed}
        if query.strip():
            search = self.paginate("/search/repositories", token=user_token,
                                   params={"q": query.strip(), "sort": "updated", "per_page": 100})
            for repo in search:
                by_name.setdefault(repo.get("full_name", "").casefold(), repo)
        return sorted(by_name.values(), key=lambda r: (r.get("full_name", "").casefold()))

    def list_pull_requests(self, full_name: str, user_token: str, *, state: str = "open") -> list[dict]:
        token = self.repository_token(full_name, user_token)
        return self.paginate(f"/repos/{quote(full_name, safe='/')}/pulls", token=token,
                             params={"state": state, "per_page": 100, "sort": "updated", "direction": "desc"})

    def pull_request(self, full_name: str, number: int, user_token: str) -> dict:
        token = self.repository_token(full_name, user_token)
        return self.get_json(f"/repos/{quote(full_name, safe='/')}/pulls/{number}", token=token)

    def pull_request_files(self, full_name: str, number: int, user_token: str) -> list[dict]:
        token = self.repository_token(full_name, user_token)
        files = self.paginate(f"/repos/{quote(full_name, safe='/')}/pulls/{number}/files", token=token,
                              params={"per_page": 100})
        if len(files) >= 3000:
            raise GitHubCoverageError("GitHub limits pull request file listings to 3,000 files; split this PR to preserve complete diff coverage")
        return files

    def repository_token(self, full_name: str, user_token: str) -> str | None:
        # An app user token can read public GitHub API resources. Private data still
        # requires a repository installation token, and review writes never use this fallback.
        return self.token_for_repo(full_name, user_token) or user_token

    def commit_tree(self, full_name: str, commit_sha: str, user_token: str) -> str:
        token = self.repository_token(full_name, user_token)
        commit = self.get_json(f"/repos/{quote(full_name, safe='/')}/git/commits/{commit_sha}", token=token)
        tree_sha = (commit.get("tree") or {}).get("sha")
        if not tree_sha:
            raise GitHubAPIError(502, "GitHub commit response did not include a tree")
        return tree_sha

    def tree(self, full_name: str, tree_sha: str, user_token: str) -> list[dict]:
        token = self.repository_token(full_name, user_token)
        data = self.get_json(f"/repos/{quote(full_name, safe='/')}/git/trees/{tree_sha}", token=token)
        if data.get("truncated"):
            raise GitHubCoverageError("GitHub truncated a repository tree response; complete context could not be built")
        return data.get("tree", [])

    def blob(self, full_name: str, blob_sha: str, user_token: str, *, blob_cache: dict[str, bytes] | None = None) -> bytes:
        if blob_cache is not None and blob_sha in blob_cache:
            return blob_cache[blob_sha]
        token = self.repository_token(full_name, user_token)
        data = self.get_json(f"/repos/{quote(full_name, safe='/')}/git/blobs/{blob_sha}", token=token)
        if data.get("encoding") != "base64" or not data.get("content"):
            raise GitHubCoverageError("GitHub did not return complete content for a repository file")
        try:
            result = base64.b64decode(data["content"])
        except (ValueError, TypeError) as exc:
            raise GitHubAPIError(502, "GitHub returned invalid file content") from exc
        if blob_cache is not None:
            blob_cache[blob_sha] = result
        return result

    def create_or_update_review(self, full_name: str, number: int, user_token: str,
                                head_sha: str, summary_body: str | None, inline_comments: list[dict],
                                resolved_comments: list[dict] | None = None) -> dict:
        token = self.token_for_repo(full_name, user_token)
        if not token:
            raise GitHubAPIError(403, "Install the TracerPyX GitHub App on this repository to publish a review")
        existing = self.paginate(f"/repos/{quote(full_name, safe='/')}/pulls/{number}/comments", token=token,
                                 params={"per_page": 100})
        existing_by_marker = {}
        bot_login = (app_slug() + "[bot]").casefold()
        for comment in existing:
            if ((comment.get("user") or {}).get("login") or "").casefold() != bot_login:
                continue
            body = comment.get("body") or ""
            for line in body.splitlines():
                if line.startswith("<!-- tracerpyx:finding:"):
                    existing_by_marker[line] = comment
        new_comments = []
        updated = 0
        resolved = 0
        for comment in inline_comments:
            marker = comment["body"].splitlines()[0]
            old = existing_by_marker.get(marker)
            if old:
                self._request("PATCH", f"/repos/{quote(full_name, safe='/')}/pulls/comments/{old['id']}",
                              token=token, json_body={"body": comment["body"]})
                updated += 1
            else:
                new_comments.append(comment)
        for item in resolved_comments or []:
            marker = f"<!-- tracerpyx:finding:{item['finding_id']} -->"
            old = existing_by_marker.get(marker)
            if not old:
                continue
            body = (f"{marker}\n**Finding fixed by this PR**\n\n"
                    f"{item.get('classification_explanation', 'The finding is absent at the analyzed head commit.')}\n\n"
                    f"Analyzed head commit: `{head_sha}`. This TracerPyX comment was updated during an explicitly requested review publish.")
            self._request("PATCH", f"/repos/{quote(full_name, safe='/')}/pulls/comments/{old['id']}",
                          token=token, json_body={"body": body})
            resolved += 1
        prior_summary = None
        if summary_body is not None:
            summary_marker = "<!-- tracerpyx:summary -->"
            summary_body = summary_marker + "\n" + summary_body
            issue_comments = self.paginate(f"/repos/{quote(full_name, safe='/')}/issues/{number}/comments",
                                           token=token, params={"per_page": 100})
            prior_summary = next((c for c in issue_comments if ((c.get("user") or {}).get("login") or "").casefold() == bot_login and summary_marker in (c.get("body") or "")), None)
            if prior_summary:
                self._request("PATCH", f"/repos/{quote(full_name, safe='/')}/issues/comments/{prior_summary['id']}",
                              token=token, json_body={"body": summary_body})
            else:
                self._request("POST", f"/repos/{quote(full_name, safe='/')}/issues/{number}/comments",
                              token=token, json_body={"body": summary_body})
        review_ids = []
        for start in range(0, len(new_comments), 30):
            response = self._request("POST", f"/repos/{quote(full_name, safe='/')}/pulls/{number}/reviews",
                                     token=token, json_body={"commit_id": head_sha,
                                                            "body": "TracerPyX inline findings", "event": "COMMENT",
                                                            "comments": new_comments[start:start + 30]})
            try:
                review_id = response.json().get("id")
            except ValueError:
                review_id = None
            if review_id:
                review_ids.append(review_id)
        return {"review_ids": review_ids, "inline_published": len(new_comments),
                "inline_updated": updated, "inline_resolved": resolved,
                "summary_published": summary_body is not None,
                "summary_updated": bool(prior_summary)}
