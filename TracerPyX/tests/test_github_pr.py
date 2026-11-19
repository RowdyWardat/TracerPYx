"""GitHub App and PR analysis regression tests. GitHub responses are mocked; no PR data is fabricated in the UI."""
from __future__ import annotations

import base64
import difflib
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from fastapi.testclient import TestClient

from backend import pr_storage
from backend.github_pr_analysis import (_attribute, _parse_patch_lines, analyze_pull_request,
                                        normalize_changed_files)
from integrations.github_app import GitHubAPIError, GitHubAppClient, GitHubCoverageError, app_configured, app_jwt

BASE = "a" * 40
HEAD = "b" * 40
REPOSITORY = {"id": 12, "full_name": "acme/demo", "private": False, "html_url": "https://github.com/acme/demo"}


def unified_patch(old: str, new: str, path: str = "app.py") -> str:
    lines = list(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                      fromfile="a/" + path, tofile="b/" + path, n=3))
    return "".join(lines[2:])


class MemoryGitHub:
    """Git object fixture that exposes immutable per-commit trees and blobs."""
    def __init__(self, snapshots: dict[str, dict[str, str]]):
        self.commit_roots: dict[str, str] = {}
        self.trees: dict[str, list[dict]] = {}
        self.blobs: dict[str, bytes] = {}
        for commit, files in snapshots.items():
            tree_ids: dict[str, str] = {"": f"tree-{commit}"}
            for path in files:
                parts = path.split("/")
                for index in range(1, len(parts)):
                    prefix = "/".join(parts[:index])
                    tree_ids.setdefault(prefix, f"tree-{commit}-{hashlib.sha1(prefix.encode()).hexdigest()[:8]}")
            for prefix, tree_id in tree_ids.items():
                children = {}
                for path, text in files.items():
                    if prefix and not path.startswith(prefix + "/"):
                        continue
                    relative = path[len(prefix) + 1:] if prefix else path
                    first, slash, rest = relative.partition("/")
                    if slash:
                        subpath = (prefix + "/" + first).strip("/")
                        children[first] = {"path": first, "type": "tree", "mode": "040000", "sha": tree_ids[subpath]}
                    else:
                        data = text.encode()
                        blob_sha = hashlib.sha1(data).hexdigest()
                        self.blobs[blob_sha] = data
                        children[first] = {"path": first, "type": "blob", "mode": "100644", "sha": blob_sha, "size": len(data)}
                self.trees[tree_id] = list(children.values())
            self.commit_roots[commit] = tree_ids[""]

    def repository_token(self, _repo, _user_token):
        return "installation-token"

    def commit_tree(self, _repo, commit_sha, _user_token):
        return self.commit_roots[commit_sha]

    def tree(self, _repo, tree_sha, _user_token):
        return self.trees[tree_sha]

    def blob(self, _repo, blob_sha, _user_token, blob_cache=None):
        if blob_cache is not None and blob_sha in blob_cache:
            return blob_cache[blob_sha]
        data = self.blobs[blob_sha]
        if blob_cache is not None:
            blob_cache[blob_sha] = data
        return data

    def get_json(self, path, token=None, params=None):
        return {"full_name": path.rsplit("/", 1)[-1], "private": False}


def run_report(base_files: dict[str, str], head_files: dict[str, str], changed_files: list[dict], *, head_repo: str = "acme/demo"):
    client = MemoryGitHub({BASE: base_files, HEAD: head_files})
    pull = {"number": 7, "title": "Security update", "body": "", "state": "closed", "draft": False,
            "html_url": "https://github.com/acme/demo/pull/7", "user": {"login": "author"},
            "base": {"sha": BASE, "ref": "main"},
            "head": {"sha": HEAD, "ref": "feature", "repo": {"full_name": head_repo}}}
    return analyze_pull_request(client, "user-token", REPOSITORY, pull, changed_files,
                                lambda _stage: None, lambda: False)


def test_diff_line_mapping_handles_additions_deletions_and_empty_diff():
    patch = "@@ -2,2 +2,3 @@\n old()\n-gone()\n+new()\n+next()\n"
    added, deleted = _parse_patch_lines(patch)
    assert added == {3, 4}
    assert deleted == {3}
    changed, added_map, deleted_map, warnings = normalize_changed_files([
        {"filename": "a.py", "status": "modified", "patch": patch, "additions": 2, "deletions": 1},
        {"filename": "bin.dat", "status": "modified", "patch": None, "additions": 0, "deletions": 0},
    ])
    assert added_map["a.py"] == {3, 4}
    assert deleted_map["a.py"] == {3}
    assert changed[0]["diff_complete"] is True
    assert changed[1]["diff_complete"] is False
    assert warnings and "inline comments are disabled" in warnings[0]
    empty, adds, deletes, empty_warnings = normalize_changed_files([])
    assert empty == [] and dict(adds) == {} and dict(deletes) == {} and empty_warnings == []


def test_deleted_and_renamed_file_metadata_preserves_both_paths():
    changed, added, deleted, _ = normalize_changed_files([
        {"filename": "new_name.py", "previous_filename": "old_name.py", "status": "renamed",
         "patch": "@@ -4 +4 @@\n-old()\n+new()\n", "additions": 1, "deletions": 1},
        {"filename": "gone.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x()\n", "additions": 0, "deletions": 1},
    ])
    assert changed[0]["previous_path"] == "old_name.py"
    assert deleted["old_name.py"] == {4}
    assert deleted["gone.py"] == {1}


def test_large_pr_file_limit_is_reported_without_silent_truncation(monkeypatch):
    client = GitHubAppClient()
    monkeypatch.setattr(client, "repository_token", lambda *_: "install-token")
    monkeypatch.setattr(client, "paginate", lambda *args, **kwargs: [{"filename": f"f{i}.py"} for i in range(3000)])
    with pytest.raises(GitHubCoverageError, match="3,000 files"):
        client.pull_request_files("acme/demo", 2, "user-token")


def test_full_head_context_detects_reachable_cross_file_sql_injection():
    base = {"app.py": "from flask import Flask, request\nfrom helpers import run_query\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return run_query(request.args.get('name'))\n",
            "helpers.py": "def run_query(name):\n    return name\n"}
    head = dict(base)
    head["helpers.py"] = "def run_query(name):\n    return db.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
    patch = unified_patch(base["helpers.py"], head["helpers.py"], "helpers.py")
    report = run_report(base, head, [{"filename": "helpers.py", "status": "modified", "patch": patch,
                                      "additions": 1, "deletions": 1, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "SQL query assembled by string formatting")
    assert finding["classification"] == "introduced"
    assert finding["reachability"] == "confirmed_reachable"
    assert finding["file"] == "helpers.py" and finding["line"] == 2
    assert finding["line_in_pr_diff"] and finding["review_commentable"]
    assert finding["call_path"][-1].endswith("run_query")
    assert finding["taint_analysis"]["status"] == "not_established"
    assert "attacker-controlled" in finding["taint_analysis"]["explanation"]
    assert "not established" in finding["exploitability"].lower()


def test_new_eval_is_detected_but_unreached_function_is_not_claimed_reachable():
    base = {"app.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return 'ok'\n"}
    head = dict(base)
    head["unsafe.py"] = "def parse_user_value(value):\n    return eval(value)\n"
    report = run_report(base, head, [{"filename": "unsafe.py", "status": "added",
                                      "patch": "@@ -0,0 +1,2 @@\n+def parse_user_value(value):\n+    return eval(value)\n",
                                      "additions": 2, "deletions": 0, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "Dynamic code evaluation")
    assert finding["classification"] == "introduced"
    assert finding["reachability"] != "confirmed_reachable"
    assert finding["call_path"] == []
    assert finding["taint_analysis"]["status"] == "not_established"


def test_existing_finding_worsens_when_pr_adds_a_cross_file_caller_on_an_unchanged_sink():
    base = {"app.py": "from flask import Flask\nfrom helpers import unsafe_query\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return 'ok'\n",
            "helpers.py": "def unsafe_query(name):\n    return db.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"}
    head = dict(base)
    head["app.py"] = base["app.py"].replace("    return 'ok'", "    return unsafe_query('alice')")
    patch = unified_patch(base["app.py"], head["app.py"])
    report = run_report(base, head, [{"filename": "app.py", "status": "modified", "patch": patch,
                                      "additions": 1, "deletions": 1, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "SQL query assembled by string formatting")
    assert finding["classification"] == "worsened"
    assert finding["reachability"] == "confirmed_reachable"
    assert finding["file"] == "helpers.py" and not finding["line_in_pr_diff"]
    assert not finding["review_commentable"]


def test_pr_that_fixes_existing_sql_injection_is_classified_fixed():
    base = {"app.py": "def query(name):\n    return db.execute(f\"SELECT * FROM t WHERE n='{name}'\")\n"}
    head = {"app.py": "def query(name):\n    return db.execute('SELECT * FROM t WHERE n=?', (name,))\n"}
    patch = unified_patch(base["app.py"], head["app.py"])
    report = run_report(base, head, [{"filename": "app.py", "status": "modified", "patch": patch,
                                      "additions": 1, "deletions": 1, "changes": 2}])
    assert report["findings"] == []
    assert report["summary"]["fixed"] == 1
    fixed = report["fixed_findings"][0]
    assert fixed["classification"] == "fixed"
    assert fixed["line_in_pr_diff"] is True


def test_unrelated_change_does_not_relabel_preexisting_finding_as_introduced():
    source = "def query(name):\n    return db.execute(f\"SELECT * FROM t WHERE n='{name}'\")\n"
    base = {"app.py": source, "README.md": "old\n"}
    head = {"app.py": source, "README.md": "new\n"}
    report = run_report(base, head, [{"filename": "README.md", "status": "modified",
                                      "patch": "@@ -1 +1 @@\n-old\n+new\n", "additions": 1, "deletions": 1, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "SQL query assembled by string formatting")
    assert finding["classification"] == "pre_existing"
    assert not finding["line_in_pr_diff"]


def test_sanitizer_change_is_not_misreported_as_taint_proof_or_a_fix():
    base = {"app.py": "def parse_value(value):\n    return eval(value)\n"}
    head = {"app.py": "def parse_value(value):\n    return eval(validate(value))\n"}
    report = run_report(base, head, [{"filename": "app.py", "status": "modified",
                                      "patch": unified_patch(base["app.py"], head["app.py"]),
                                      "additions": 1, "deletions": 1, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "Dynamic code evaluation")
    assert finding["classification"] == "pre_existing"
    assert finding["taint_analysis"]["status"] == "not_established"
    assert "exploitability" in finding


def test_route_auth_decorator_change_does_not_claim_authorization_was_proven():
    base = {"app.py": "from flask import Flask\nfrom helpers import run_query\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return run_query('x')\n",
            "helpers.py": "def run_query(value):\n    return db.execute(f\"SELECT * FROM t WHERE x='{value}'\")\n"}
    head = dict(base)
    head["app.py"] = "from flask import Flask\nfrom helpers import run_query\nfrom auth import login_required\napp = Flask(__name__)\n@app.route('/')\n@login_required\ndef home():\n    return run_query('x')\n"
    report = run_report(base, head, [{"filename": "app.py", "status": "modified",
                                      "patch": unified_patch(base["app.py"], head["app.py"]),
                                      "additions": 2, "deletions": 0, "changes": 2}])
    finding = next(f for f in report["findings"] if f["title"] == "SQL query assembled by string formatting")
    assert finding["classification"] == "pre_existing"
    assert finding["reachability"] == "confirmed_reachable"
    assert "authorization" not in finding.get("exploitability", "").lower()
    assert finding["taint_analysis"]["status"] == "not_established"


def test_dependency_advisory_introduced_and_fixed_by_exact_manifest_line(monkeypatch):
    from backend import analyzer
    def osv(package):
        if package["version"] != "1.0":
            return []
        return [{"advisory_id": "GHSA-example", "title": "Vulnerable package", "package": package["name"],
                 "declared_version": package["version"], "version_source": package["source"],
                 "source": "OSV", "synthetic": False, "verdict": "UNCERTAIN", "confidence": "LOW",
                 "severity": "HIGH", "evidence": ["OSV reports the pinned package version as affected."]}]
    monkeypatch.setattr(analyzer, "query_package", osv)
    old, new = "Flask==2.0\n", "Flask==1.0\n"
    introduced = run_report({"requirements.txt": old}, {"requirements.txt": new},
                            [{"filename": "requirements.txt", "status": "modified", "patch": unified_patch(old, new, "requirements.txt"),
                              "additions": 1, "deletions": 1, "changes": 2}])
    assert introduced["findings"][0]["classification"] == "introduced"
    assert introduced["findings"][0]["file"] == "requirements.txt"
    assert introduced["findings"][0]["line"] == 1
    change = introduced["dependency_changes"]["version_changed"][0]
    assert change["name"] == "flask" and change["base"]["version"] == "2.0" and change["head"]["version"] == "1.0"
    assert change["head"]["usage"] == "no_matching_python_import_observed"
    fixed = run_report({"requirements.txt": new}, {"requirements.txt": old},
                       [{"filename": "requirements.txt", "status": "modified", "patch": unified_patch(new, old, "requirements.txt"),
                         "additions": 1, "deletions": 1, "changes": 2}])
    assert fixed["summary"]["fixed"] == 1
    assert fixed["fixed_findings"][0]["classification"] == "fixed"
    added = run_report({}, {"requirements.txt": "requests==2.31.0\n"},
                       [{"filename": "requirements.txt", "status": "added",
                         "patch": "@@ -0,0 +1 @@\n+requests==2.31.0\n", "additions": 1, "deletions": 0, "changes": 1}])
    assert added["dependency_changes"]["added"][0]["name"] == "requests"
    assert added["dependency_changes"]["added"][0]["usage"] == "no_matching_python_import_observed"


def test_renamed_and_deleted_files_and_binary_patches_remain_explicit():
    files, added, deleted, warnings = normalize_changed_files([
        {"filename": "renamed.py", "previous_filename": "old.py", "status": "renamed", "patch": "@@ -1 +1 @@\n-x\n+y\n"},
        {"filename": "deleted.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x\n"},
        {"filename": "image.bin", "status": "modified", "patch": None},
    ])
    assert len(files) == 3
    assert files[0]["previous_path"] == "old.py"
    assert deleted["deleted.py"] == {1}
    assert files[2]["diff_complete"] is False
    assert warnings


def test_private_and_fork_pr_snapshots_require_an_installation_for_each_private_repo():
    client = GitHubAppClient()
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(client, "token_for_repo", lambda name, _token: "private-install-token" if name == "acme/demo" else None)
        assert client.repository_token("acme/demo", "user-token") == "private-install-token"
        assert client.repository_token("someone/fork", "user-token") == "user-token"
        assert client.token_for_repo("someone/fork", "user-token") is None
    finally:
        monkeypatch.undo()


def test_github_client_follows_link_pagination_and_rejects_external_link():
    client = GitHubAppClient()
    pages = []
    def request(_method, url, **_kwargs):
        pages.append(url)
        if len(pages) == 1:
            return FakeResponse([{"id": 1}], {'Link': '<https://api.github.com/user/repos?page=2>; rel="next"'})
        return FakeResponse([{"id": 2}], {})
    client._request = request
    assert [x["id"] for x in client.paginate("/user/repos", token="not-returned", params={"per_page": 1})] == [1, 2]
    assert len(pages) == 2
    client._request = lambda *_args, **_kwargs: FakeResponse([], {'Link': '<https://evil.example/steal>; rel="next"'})
    with pytest.raises(GitHubAPIError, match="unexpected destination"):
        client.paginate("/user/repos", token="secret")


class FakeResponse:
    def __init__(self, data, headers):
        self.data, self.headers = data, headers
    def json(self):
        return self.data


def test_github_api_errors_map_permission_rate_limit_and_network_failures(monkeypatch):
    client = GitHubAppClient(transport=httpx.MockTransport(lambda _request: httpx.Response(403, json={"message": "denied"}, headers={"X-RateLimit-Remaining": "0", "Retry-After": "0"})))
    monkeypatch.setattr("integrations.github_app.time.sleep", lambda _delay: None)
    with pytest.raises(GitHubAPIError) as rate:
        client.get_json("/user", token="never-logged")
    assert rate.value.status == 403
    assert "rate limit" in rate.value.reason
    assert "never-logged" not in str(rate.value)
    client = GitHubAppClient(transport=httpx.MockTransport(lambda _request: (_ for _ in ()).throw(httpx.ConnectError("offline"))))
    with pytest.raises(GitHubAPIError) as network:
        client.get_json("/user")
    assert network.value.status == 503
    assert "Network error" in network.value.reason


def test_github_app_jwt_is_signed_and_short_lived(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "app.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    monkeypatch.setenv("GITHUB_APP_ID", "app-123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(key_path))
    token = app_jwt(now=1000)
    header, payload, signature = token.split(".")
    body = f"{header}.{payload}".encode()
    key.public_key().verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), body,
                            rsa_padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims == {"iat": 940, "exp": 1540, "iss": "app-123"}


def test_app_status_does_not_claim_a_missing_signing_key_is_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test"); monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", str(tmp_path / "missing.pem"))
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PEM", raising=False)
    assert not app_configured()


def test_review_publisher_updates_only_its_marked_comments_and_deduplicates(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    client = GitHubAppClient()
    monkeypatch.setattr(client, "token_for_repo", lambda *_: "installation-token")
    existing_inline = [
        {"id": 1, "user": {"login": "tracerpyx-test[bot]"}, "body": "<!-- tracerpyx:finding:f1 -->\nold"},
        {"id": 2, "user": {"login": "contributor"}, "body": "<!-- tracerpyx:finding:f2 -->\nforged marker"},
        {"id": 3, "user": {"login": "tracerpyx-test[bot]"}, "body": "<!-- tracerpyx:finding:f3 -->\nold finding"},
    ]
    existing_summaries = [{"id": 3, "user": {"login": "contributor"}, "body": "<!-- tracerpyx:summary -->\nforged"}]
    monkeypatch.setattr(client, "paginate", lambda path, **_kwargs: existing_inline if "/pulls/3/comments" in path else existing_summaries)
    requests = []
    def request(method, path, **kwargs):
        requests.append((method, path, kwargs.get("json_body")))
        return FakeResponse({"id": 44}, {})
    client._request = request
    result = client.create_or_update_review("acme/demo", 3, "user-token", HEAD, "summary", [
        {"path": "app.py", "line": 4, "side": "RIGHT", "body": "<!-- tracerpyx:finding:f1 -->\nupdated"},
        {"path": "app.py", "line": 8, "side": "RIGHT", "body": "<!-- tracerpyx:finding:f2 -->\nours"},
    ], resolved_comments=[{"finding_id": "f3", "classification_explanation": "The unsafe call was removed."}])
    assert result["inline_updated"] == 1 and result["inline_published"] == 1
    assert result["inline_resolved"] == 1
    assert any(path.endswith("/pulls/comments/1") and method == "PATCH" for method, path, _body in requests)
    resolved_body = next(body["body"] for method, path, body in requests if method == "PATCH" and path.endswith("/pulls/comments/3"))
    assert "fixed by this PR" in resolved_body and HEAD in resolved_body
    assert not any(path.endswith("/pulls/comments/2") for _method, path, _body in requests)
    review = next(body for method, path, body in requests if method == "POST" and path.endswith("/pulls/3/reviews"))
    assert len(review["comments"]) == 1 and review["comments"][0]["line"] == 8
    assert any(path.endswith("/issues/3/comments") and method == "POST" for method, path, _body in requests)


def test_session_encryption_and_oauth_callback_state(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GITHUB_APP_ID", "app-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "not-used-by-oauth-test.pem")
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    monkeypatch.setattr(routes, "app_configured", lambda: True)
    class OAuthClient:
        def viewer(self, token):
            assert token == "private-access-token"
            return {"login": "security-user"}
    monkeypatch.setattr(routes, "GitHubAppClient", OAuthClient)
    monkeypatch.setattr(routes, "exchange_code", lambda _code: {"access_token": "private-access-token", "refresh_token": None})
    response = TestClient(__import__("backend.main", fromlist=["app"]).app).get(
        "/api/github/auth/callback?code=auth-code&state=wrong", cookies={routes.STATE_COOKIE: "expected"}, follow_redirects=False)
    assert response.status_code == 303 and "reason=authorization" in response.headers["location"]
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    response = client.get("/api/github/auth/callback?code=auth-code&state=state-value",
                          cookies={routes.STATE_COOKIE: "state-value"}, follow_redirects=False)
    assert response.status_code == 303
    assert "private-access-token" not in response.text
    session_cookie = response.cookies.get(routes.SESSION_COOKIE)
    assert session_cookie and "private-access-token" not in session_cookie
    row = pr_storage.get_session(pr_storage.hash_session(session_cookie))
    assert "private-access-token" not in row["token_ciphertext"]
    assert row["login"] == "security-user"


def test_oauth_start_sets_http_only_csrf_state_and_redirects_to_github(monkeypatch):
    monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id"); monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "private-key.pem")
    from backend.main import app
    from backend import github_pr_routes as routes
    monkeypatch.setattr(routes, "app_configured", lambda: True)
    response = TestClient(app).get("/api/github/auth/start", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("https://github.com/login/oauth/authorize?")
    cookie = response.headers["set-cookie"]
    assert "httponly" in cookie.lower() and "samesite=lax" in cookie.lower()
    assert "client_secret" not in response.headers["location"]


def test_expiring_github_user_token_refreshes_and_rotates_encrypted_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "refresh.sqlite3"))
    monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    class RefreshClient:
        def refresh_user_token(self, refresh_token):
            assert refresh_token == "old-refresh"
            return {"access_token": "new-access", "refresh_token": "new-refresh", "expires_at": 4_000_000_000}
    monkeypatch.setattr(routes, "GitHubAppClient", RefreshClient)
    raw = "refresh-cookie"; digest = pr_storage.hash_session(raw)
    old = {"access_token": "expired-access", "refresh_token": "old-refresh", "expires_at": 1, "refresh_expires_at": 4_000_000_000}
    pr_storage.put_session(digest, routes._encrypt_credentials(old), "alice")
    assert routes._user_token(digest) == "new-access"
    saved = pr_storage.get_session(digest)
    assert "new-access" not in saved["token_ciphertext"]
    assert routes._decrypt_credentials(saved["token_ciphertext"])["refresh_token"] == "new-refresh"


def test_auth_status_discloses_connection_but_never_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret"); monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "key.pem")
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    raw = "opaque-session-cookie"
    pr_storage.put_session(pr_storage.hash_session(raw), routes._encrypt_credentials({"access_token": "hidden-token"}), "alice")
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    response = client.get("/api/github/auth/status", cookies={routes.SESSION_COOKIE: raw})
    assert response.json()["connected"] is True and response.json()["login"] == "alice"
    assert "hidden-token" not in response.text


def test_repo_and_pr_discovery_support_closed_and_fork_pull_requests(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "state.sqlite3")); monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    class Discovery:
        def list_repositories(self, _token, query=""):
            assert query == "public-project"
            return [{"id": 1, "full_name": "org/public-project", "private": False, "_tracerpyx_installation_id": 4}]
        def list_pull_requests(self, _repo, _token, state="open"):
            assert state == "all"
            return [{"number": 9, "title": "Closed update", "state": "closed", "draft": False,
                     "html_url": "https://github.com/org/public-project/pull/9", "user": {"login": "dev"},
                     "base": {"ref": "main", "sha": BASE}, "head": {"ref": "fix", "sha": HEAD,
                     "repo": {"full_name": "contrib/fork"}}}]
    monkeypatch.setattr(routes, "GitHubAppClient", Discovery)
    raw = "session-cookie"
    pr_storage.put_session(pr_storage.hash_session(raw), routes._encrypt_credentials({"access_token": "token"}), "dev")
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    repos = client.get("/api/github/repositories?q=public-project", cookies={routes.SESSION_COOKIE: raw})
    assert repos.json()["repositories"][0]["private"] is False
    pulls = client.get("/api/github/repositories/org/public-project/pull-requests?state=all", cookies={routes.SESSION_COOKIE: raw})
    assert pulls.json()["pull_requests"][0]["state"] == "closed"
    assert pulls.json()["pull_requests"][0]["head_repository"] == "contrib/fork"


def test_analysis_jobs_are_pinned_stable_and_deduplicated(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "state.sqlite3")); monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret"); monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "key.pem")
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    monkeypatch.setattr(routes, "app_configured", lambda: True)
    queued = []
    class Executor:
        def submit(self, _fn, job): queued.append(job)
    class Discovery:
        def repository_token(self, *_): return "read-token"
        def get_json(self, *_args, **_kwargs): return {"id": 12, "full_name": "acme/demo", "private": False}
        def pull_request(self, *_args, **_kwargs):
            return {"number": 3, "base": {"sha": BASE}, "head": {"sha": HEAD}}
    monkeypatch.setattr(routes, "GitHubAppClient", Discovery); monkeypatch.setattr(routes, "_executor", Executor())
    raw = "job-session"
    pr_storage.put_session(pr_storage.hash_session(raw), routes._encrypt_credentials({"access_token": "token"}), "alice")
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    headers = {"Origin": "http://localhost:3000"}
    payload = {"repository": "acme/demo", "number": 3}
    first = client.post("/api/github/analyze", json=payload, headers=headers, cookies={routes.SESSION_COOKIE: raw})
    second = client.post("/api/github/analyze", json=payload, headers=headers, cookies={routes.SESSION_COOKIE: raw})
    assert first.status_code == second.status_code == 200
    assert first.json()["job_id"] == second.json()["job_id"]
    assert first.json()["base_sha"] == BASE and first.json()["head_sha"] == HEAD
    assert len(queued) == 1


def test_job_storage_cache_is_scoped_to_exact_sha_pair_and_analyzer(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "jobs.sqlite3")); pr_storage.init_db()
    session = pr_storage.hash_session("owner")
    first, cached = pr_storage.create_job(session_hash=session, cache_key="repo:base1:head1:v1", repo_id=1,
                                          full_name="org/repo", pr_number=1, base_sha="base1", head_sha="head1")
    assert not cached
    pr_storage.update_job(first["job_id"], status="complete", stage="complete", result={"ok": True}, cache_key="repo:base1:head1:v1")
    replay, cached = pr_storage.create_job(session_hash=session, cache_key="repo:base1:head1:v1", repo_id=1,
                                           full_name="org/repo", pr_number=1, base_sha="base1", head_sha="head1")
    assert cached and replay["status"] == "complete" and json.loads(replay["result_json"]) == {"ok": True}
    different, cached = pr_storage.create_job(session_hash=session, cache_key="repo:base1:head2:v1", repo_id=1,
                                              full_name="org/repo", pr_number=1, base_sha="base1", head_sha="head2")
    assert not cached and different["head_sha"] == "head2"


def test_review_comments_update_marked_items_and_publish_valid_anchors_only(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "publish.sqlite3")); monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    raw = "publisher-cookie"; owner = pr_storage.hash_session(raw)
    finding = {"finding_id": "f1", "title": "SQL injection", "severity": "high", "file": "app.py", "line": 12,
               "review_commentable": True, "line_in_pr_diff": True, "classification": "introduced",
               "classification_explanation": "Added line", "reachability": "confirmed_reachable",
               "reachability_explanation": "Call graph path", "evidence": ["app.py:12"], "cwe": ["CWE-89"]}
    invalid_finding = {**finding, "finding_id": "invalid", "line": 99, "review_commentable": False,
                       "line_in_pr_diff": False, "classification": "pre_existing"}
    report = {"repository": {"full_name": "acme/demo"}, "pull_request": {"number": 3}, "base_sha": BASE,
              "head_sha": HEAD, "summary": {"total_findings": 1, "introduced": 1, "worsened": 0, "fixed": 0,
              "pre_existing": 1, "uncertain_attribution": 0}, "findings": [finding, invalid_finding], "analysis_warnings": []}
    row, _ = pr_storage.create_job(session_hash=owner, cache_key="publish-key", repo_id=1, full_name="acme/demo",
                                   pr_number=3, base_sha=BASE, head_sha=HEAD)
    pr_storage.update_job(row["job_id"], status="complete", stage="complete", result=report, cache_key="publish-key")
    calls = []
    class PublishClient:
        def pull_request(self, *_args): return {"head": {"sha": HEAD}, "base": {"sha": BASE}}
        def create_or_update_review(self, _repo, _num, _token, _sha, summary, comments, resolved_comments=None):
            calls.append((summary, comments)); return {"inline_published": len(comments), "inline_updated": 0,
                                                       "inline_resolved": len(resolved_comments or []),
                                                       "summary_published": summary is not None, "summary_updated": False}
    monkeypatch.setattr(routes, "GitHubAppClient", PublishClient)
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret"); monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "key.pem")
    pr_storage.put_session(owner, routes._encrypt_credentials({"access_token": "private-token"}), "alice")
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    headers = {"Origin": "http://localhost:3000"}
    url = f"/api/github/jobs/{row['job_id']}/publish"
    comparison = client.get(f"/api/github/jobs/{row['job_id']}/comparison", cookies={routes.SESSION_COOKIE: raw})
    assert comparison.status_code == 200 and comparison.json()["base_sha"] == BASE
    assert len(comparison.json()["introduced"]) == 1 and not comparison.json()["fixed"]
    response = client.post(url, json={"finding_ids": ["f1"], "publish_summary": True}, headers=headers, cookies={routes.SESSION_COOKIE: raw})
    assert response.status_code == 200
    summary, comments = calls[0]
    assert "TracerPyX security analysis" in summary
    assert "app.py:99" in summary and "pre_existing" in summary
    assert comments[0]["path"] == "app.py" and comments[0]["line"] == 12 and comments[0]["side"] == "RIGHT"
    assert "taint flow" in comments[0]["body"].lower()
    invalid = client.post(url, json={"finding_ids": ["invalid"], "publish_summary": False}, headers=headers,
                          cookies={routes.SESSION_COOKIE: raw})
    assert invalid.status_code == 422 and len(calls) == 1
    class DeniedPublisher:
        def pull_request(self, *_args): return {"head": {"sha": HEAD}, "base": {"sha": BASE}}
        def create_or_update_review(self, *_args, **_kwargs): raise GitHubAPIError(403, "GitHub denied this request; check App installation permissions")
    monkeypatch.setattr(routes, "GitHubAppClient", DeniedPublisher)
    denied = client.post(url, json={"finding_ids": ["f1"], "publish_summary": True}, headers=headers,
                         cookies={routes.SESSION_COOKIE: raw})
    assert denied.status_code == 403 and "private-token" not in denied.text


def test_invalid_repository_pr_and_missing_permissions_have_clear_http_status(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "invalid-input.sqlite3"))
    monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    pr_storage.init_db()
    from backend import github_pr_routes as routes
    monkeypatch.setattr(routes, "app_configured", lambda: True)
    monkeypatch.setenv("GITHUB_APP_ID", "app-id"); monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_APP_SLUG", "tracerpyx-test"); monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PATH", "configured.pem")
    raw = "invalid-input-cookie"
    pr_storage.put_session(pr_storage.hash_session(raw), routes._encrypt_credentials({"access_token": "private-token"}), "alice")
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    headers = {"Origin": "http://localhost:3000"}
    invalid_repo = client.post("/api/github/analyze", json={"repository": "not/a/repo/format", "number": 1},
                               headers=headers, cookies={routes.SESSION_COOKIE: raw})
    invalid_number = client.post("/api/github/analyze", json={"repository": "acme/demo", "number": 0},
                                 headers=headers, cookies={routes.SESSION_COOKIE: raw})
    assert invalid_repo.status_code == 422 and invalid_number.status_code == 422
    class Denied:
        def pull_request(self, *_args): raise GitHubAPIError(404, "GitHub repository, pull request, or commit was not found or is not accessible")
        def list_pull_requests(self, *_args, **_kwargs): raise GitHubAPIError(403, "GitHub denied this request; check App installation permissions")
    monkeypatch.setattr(routes, "GitHubAppClient", Denied)
    missing_pr = client.get("/api/github/repositories/acme/demo/pull-requests/999", cookies={routes.SESSION_COOKIE: raw})
    missing_permission = client.get("/api/github/repositories/acme/demo/pull-requests", cookies={routes.SESSION_COOKIE: raw})
    assert missing_pr.status_code == 404
    assert missing_permission.status_code == 403 and "private-token" not in missing_permission.text
    class Revoked:
        def list_repositories(self, *_args, **_kwargs): raise GitHubAPIError(401, "GitHub authorization expired or was revoked")
    monkeypatch.setattr(routes, "GitHubAppClient", Revoked)
    revoked = client.get("/api/github/repositories", cookies={routes.SESSION_COOKIE: raw})
    assert revoked.status_code == 401 and "private-token" not in revoked.text
    assert pr_storage.get_session(pr_storage.hash_session(raw)) is None
    expired_raw = "expired-token-cookie"
    pr_storage.put_session(pr_storage.hash_session(expired_raw), routes._encrypt_credentials(
        {"access_token": "expired-token", "expires_at": 1}), "alice")
    expired = client.get("/api/github/repositories", cookies={routes.SESSION_COOKIE: expired_raw})
    assert expired.status_code == 401 and pr_storage.get_session(pr_storage.hash_session(expired_raw)) is None


def test_publish_is_not_called_until_user_requests_it_and_cancel_requires_active_job(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "cancel.sqlite3")); monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode()); pr_storage.init_db()
    from backend import github_pr_routes as routes
    raw = "cancel-cookie"; session_hash = pr_storage.hash_session(raw)
    pr_storage.put_session(session_hash, routes._encrypt_credentials({"access_token": "private-token"}), "alice")
    row, _ = pr_storage.create_job(session_hash=session_hash, cache_key="cancel-key", repo_id=1, full_name="o/r", pr_number=1, base_sha=BASE, head_sha=HEAD)
    called = []
    monkeypatch.setattr(routes, "GitHubAppClient", lambda: called.append(True))
    client = TestClient(__import__("backend.main", fromlist=["app"]).app)
    headers = {"Origin": "http://localhost:3000"}
    status = client.get(f"/api/github/jobs/{row['job_id']}", cookies={routes.SESSION_COOKIE: raw})
    assert status.status_code == 200 and status.json()["status"] == "queued"
    cancelled = client.post(f"/api/github/jobs/{row['job_id']}/cancel", headers=headers, cookies={routes.SESSION_COOKIE: raw})
    assert cancelled.status_code == 200 and called == []
    publish = client.post(f"/api/github/jobs/{row['job_id']}/publish", json={"finding_ids": [], "publish_summary": True},
                          headers=headers, cookies={routes.SESSION_COOKIE: raw})
    assert publish.status_code == 404 and called == []


def test_missing_origin_is_rejected_for_cookie_authenticated_mutations(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACERPYX_DB_PATH", str(tmp_path / "origin.sqlite3")); monkeypatch.setenv("TRACERPYX_GITHUB_ENCRYPTION_KEY", Fernet.generate_key().decode()); pr_storage.init_db()
    from backend import github_pr_routes as routes
    raw = "origin-cookie"; pr_storage.put_session(pr_storage.hash_session(raw), routes._encrypt_credentials({"access_token": "x"}), "a")
    response = TestClient(__import__("backend.main", fromlist=["app"]).app).post("/api/github/auth/disconnect", cookies={routes.SESSION_COOKIE: raw})
    assert response.status_code == 403
