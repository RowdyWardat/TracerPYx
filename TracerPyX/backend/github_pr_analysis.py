"""PR snapshot construction, reuse of the project analyzer, and evidence-based attribution."""
from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.parse import quote

from backend.analyzer import analyze_project
from integrations.github_app import GitHubAppClient, GitHubCoverageError

log = logging.getLogger("tracerpyx.github_pr")
MAX_TREE_ENTRIES = 50_000
MAX_CONTEXT_FILES = 12_000
MAX_CONTEXT_BYTES = 250 * 1024 * 1024
MAX_CONTEXT_FILE_BYTES = 10 * 1024 * 1024
MAX_PYTHON_FILES = 5_000
EXCLUDED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
DEPENDENCY_NAMES = {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "pipfile.lock",
                    "uv.lock", "setup.py", "setup.cfg"}
CONFIG_NAMES = {"tox.ini", "pytest.ini", "mypy.ini", "ruff.toml", ".python-version", "dockerfile",
                "docker-compose.yml", "docker-compose.yaml", ".env.example"}


class JobCancelled(Exception):
    pass


def _path_is_relevant(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part in EXCLUDED_PARTS for part in p.parts):
        return False
    name = p.name.casefold()
    return (p.suffix.casefold() == ".py" or name in DEPENDENCY_NAMES or
            name.startswith(("requirements", "constraints")) and name.endswith((".txt", ".in")) or name in CONFIG_NAMES or
            p.suffix.casefold() in {".yaml", ".yml", ".toml", ".ini", ".cfg"} and
            (".github/workflows" in path or "config" in name or "settings" in name) or
            p.suffix.casefold() == ".json" and ("config" in name or "settings" in name))


def _snapshot(client: GitHubAppClient, repo: str, commit_sha: str, user_token: str,
              root: Path, blob_cache: dict[str, bytes], check_cancel: Callable[[], bool]) -> dict:
    tree_sha = client.commit_tree(repo, commit_sha, user_token)
    files: list[dict] = []
    warnings: list[str] = []
    pending: list[tuple[str, str]] = [("", tree_sha)]
    entries_seen = 0
    included_bytes = 0
    while pending:
        check_cancel()
        prefix, current_tree = pending.pop()
        for entry in client.tree(repo, current_tree, user_token):
            entries_seen += 1
            if entries_seen % 128 == 0:
                check_cancel()
            if entries_seen > MAX_TREE_ENTRIES:
                raise GitHubCoverageError(f"Repository tree exceeds the {MAX_TREE_ENTRIES:,}-entry analysis limit; no partial analysis was started")
            raw_path = "/".join(filter(None, (prefix, entry.get("path", ""))))
            rel = PurePosixPath(raw_path)
            if rel.is_absolute() or not raw_path or ".." in rel.parts or "\\" in raw_path:
                raise GitHubCoverageError("GitHub returned an unsafe repository path; snapshot was rejected")
            kind = entry.get("type")
            excluded = next((part for part in rel.parts if part in EXCLUDED_PARTS), None)
            if excluded:
                if kind == "tree" and rel.parts[-1] == excluded:
                    warnings.append(f"{raw_path}: generated or local environment directory excluded from analysis scope")
                continue
            mode = entry.get("mode")
            if kind == "tree":
                pending.append((raw_path, entry["sha"]))
                continue
            if kind != "blob":
                continue
            if mode == "120000":
                warnings.append(f"{raw_path}: symbolic link excluded from static snapshot")
                continue
            if not _path_is_relevant(raw_path):
                continue
            size = int(entry.get("size") or 0)
            if size > MAX_CONTEXT_FILE_BYTES:
                warnings.append(f"{raw_path}: omitted because it exceeds the {MAX_CONTEXT_FILE_BYTES // (1024 * 1024)} MB per-file context limit")
                continue
            if len(files) >= MAX_CONTEXT_FILES:
                raise GitHubCoverageError(f"Repository context exceeds the {MAX_CONTEXT_FILES:,}-file analysis limit; no partial analysis was started")
            data = client.blob(repo, entry["sha"], user_token, blob_cache=blob_cache)
            if b"\0" in data:
                warnings.append(f"{raw_path}: binary content excluded from text analysis")
                continue
            if len(data) > MAX_CONTEXT_FILE_BYTES:
                warnings.append(f"{raw_path}: omitted because returned content exceeds the {MAX_CONTEXT_FILE_BYTES // (1024 * 1024)} MB per-file context limit")
                continue
            files.append({"path": raw_path, "sha": entry["sha"], "size": len(data), "data": data})
            included_bytes += len(data)
            if included_bytes > MAX_CONTEXT_BYTES:
                raise GitHubCoverageError(f"Repository text context exceeds the {MAX_CONTEXT_BYTES // (1024 * 1024)} MB analysis limit; no partial analysis was started")
            target = (root / Path(*rel.parts)).resolve()
            if root.resolve() not in target.parents:
                raise GitHubCoverageError("GitHub returned a path outside the temporary snapshot")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    py_count = sum(Path(item["path"]).suffix.casefold() == ".py" for item in files)
    if py_count > MAX_PYTHON_FILES:
        raise GitHubCoverageError(f"Repository contains {py_count:,} Python files; the configured analysis limit is {MAX_PYTHON_FILES:,}")
    return {"files": files, "warnings": warnings, "tree_entries": entries_seen, "python_files": py_count,
            "config_files": [item["path"] for item in files if Path(item["path"]).name.casefold() in CONFIG_NAMES or Path(item["path"]).suffix.casefold() in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".json"}]}


def _parse_patch_lines(patch: str | None) -> tuple[set[int], set[int]]:
    """Parse actual GitHub unified diff hunks into right-side additions and left-side deletions."""
    added: set[int] = set()
    deleted: set[int] = set()
    if not patch:
        return added, deleted
    old_line = new_line = 0
    for line in patch.splitlines():
        if line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                old_line, new_line = int(match.group(1)), int(match.group(3))
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("\\"):
            continue
        if line.startswith("+"):
            added.add(new_line); new_line += 1
        elif line.startswith("-"):
            deleted.add(old_line); old_line += 1
        else:
            old_line += 1; new_line += 1
    return added, deleted


def normalize_changed_files(files: list[dict]) -> tuple[list[dict], dict[str, set[int]], dict[str, set[int]], list[str]]:
    changed = []
    added_lines: dict[str, set[int]] = defaultdict(set)
    deleted_lines: dict[str, set[int]] = defaultdict(set)
    warnings = []
    patch_total = 0
    for item in files:
        filename = item.get("filename", "")
        previous = item.get("previous_filename")
        patch = item.get("patch")
        patch_total += len(patch or "")
        if patch_total > 10 * 1024 * 1024:
            raise GitHubCoverageError("PR diff patches exceed the 10 MB report limit; split the PR to preserve complete review coverage")
        added, deleted = _parse_patch_lines(patch)
        added_lines[filename].update(added)
        deleted_lines[filename].update(deleted)
        if previous:
            deleted_lines[previous].update(deleted)
        binary = patch is None
        diff_complete = patch is not None
        if patch is None:
            warnings.append(f"{filename}: GitHub did not provide a text patch (binary or omitted by GitHub); inline comments are disabled for this file")
        changed.append({"path": filename, "previous_path": previous, "status": item.get("status"),
                        "additions": item.get("additions", 0), "deletions": item.get("deletions", 0),
                        "changes": item.get("changes", 0), "binary_or_patch_unavailable": binary,
                        "diff_complete": diff_complete, "patch": patch})
    return changed, added_lines, deleted_lines, warnings


def _source_and_line(finding: dict) -> tuple[str | None, int | None]:
    path, line = finding.get("file"), finding.get("line")
    if path and isinstance(line, int):
        return path, line
    source = finding.get("version_source") or ""
    match = re.match(r"(.+):(\d+)$", source)
    return (match.group(1), int(match.group(2))) if match else (path, line)


def _severity(finding: dict) -> tuple[str, str]:
    if finding.get("severity"):
        return str(finding["severity"]).lower(), "upstream advisory severity"
    cwe = set(finding.get("cwe") or [])
    high = {"CWE-78", "CWE-79", "CWE-89", "CWE-95", "CWE-22", "CWE-502", "CWE-918", "CWE-798"}
    if cwe & high:
        return "high", "potential impact of the matched source pattern; exploitability is not established"
    if cwe:
        return "medium", "potential impact of the matched source pattern; exploitability is not established"
    return "unknown", "no severity was provided by the analyzer or advisory source"


def _finding_key(finding: dict) -> tuple:
    path, _line = _source_and_line(finding)
    category = finding.get("category") or ("dependency" if finding.get("source") == "OSV" else "source-pattern")
    return (category, path or "", finding.get("advisory_id") if category == "dependency" else "",
            finding.get("title", ""), finding.get("package", ""),
            finding.get("vulnerable_symbol") or finding.get("resolved_function") or "",
            tuple(sorted(finding.get("cwe") or [])))


def _snippet(contents: bytes | None, line: int | None) -> str | None:
    if contents is None or not isinstance(line, int) or line < 1:
        return None
    text = contents.decode("utf-8", errors="replace").splitlines()
    if line > len(text):
        return None
    start, end = max(1, line - 2), min(len(text), line + 2)
    lines = []
    for n in range(start, end + 1):
        value = text[n - 1]
        if re.search(r"(?i)(password|passwd|secret|token|api.?key|access.?key|private.?key)\s*=", value):
            value = re.sub(r"(=\s*).+$", r"\1<redacted>", value, count=1)
        lines.append(f"{n}: {value}")
    return "\n".join(lines)


def _reachable(finding: dict) -> tuple[str, str]:
    verdict = finding.get("verdict")
    if verdict == "REACHABLE":
        return "confirmed_reachable", finding.get("reachability_reason") or "A static call path reaches the operation; this does not establish attacker-controlled input or exploitability."
    if verdict == "NOT REACHABLE":
        return "not_reachable_within_analyzed_coverage", finding.get("reachability_reason") or "No path was found in the analyzed graph; undiscovered runtime entry points remain possible."
    return "uncertain", finding.get("reachability_reason") or "The analyzer did not establish a complete reachability result."


def _remediation(finding: dict) -> tuple[str, str | None]:
    text = (finding.get("title", "") + " " + " ".join(finding.get("cwe") or [])).lower()
    if "sql" in text or "cwe-89" in text:
        return "Bind values through the database driver's parameterized query API; do not build SQL with string interpolation.", 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    if "eval" in text or "dynamic code" in text or "cwe-95" in text:
        return "Remove eval/exec for untrusted input. Use a strict parser and an explicit allowlist of supported operations.", "operation = ALLOWED_OPERATIONS[user_operation]"
    if "subprocess" in text or "cwe-78" in text:
        return "Pass an argument list with shell=False and validate every argument.", 'subprocess.run(["tool", validated_argument], check=True, shell=False)'
    if "deserial" in text or "cwe-502" in text:
        return "Use a safe data format or a restricted loader; never deserialize attacker-controlled objects.", None
    if "path" in text or "cwe-22" in text:
        return "Resolve the requested path under an approved root and reject paths that escape it.", None
    if "template" in text or "cwe-79" in text:
        return "Render a fixed template with escaped values; do not compile user-controlled template source.", None
    if "ssrf" in text or "cwe-918" in text:
        return "Allowlist destination hosts and block loopback, link-local, and private network ranges after DNS resolution.", None
    return "Use the safe API recommended by the relevant advisory and validate input at the trust boundary.", None


def _enrich(findings: list[dict], contents_by_path: dict[str, bytes], added_lines: dict[str, set[int]],
            deleted_lines: dict[str, set[int]], repo: str, pr_number: int, head_sha: str) -> list[dict]:
    output = []
    for raw in findings:
        finding = dict(raw)
        if finding.get("synthetic") or finding.get("category") in {"benchmark", "analysis-failure"}:
            continue
        path, line = _source_and_line(finding)
        finding["file"] = path
        finding["line"] = line
        finding["category"] = finding.get("category") or ("dependency" if finding.get("source") == "OSV" else "source-pattern")
        finding["reachability_confidence"] = finding.get("confidence") if finding["category"] == "source-pattern" else "not_assessed_for_dependencies"
        finding["confidence"] = finding.get("pattern_confidence", finding.get("confidence", "LOW"))
        finding["confidence_basis"] = ("confidence in matching the static source pattern; not exploitability confidence"
                                        if finding["category"] == "source-pattern" else
                                        "confidence in the upstream advisory/version match; installed runtime use is not established")
        finding["code_snippet"] = _snippet(contents_by_path.get(path) if path else None, line)
        finding["line_in_pr_diff"] = bool(path and line and line in added_lines.get(path, set()))
        finding["deleted_line_in_pr_diff"] = bool(path and line and line in deleted_lines.get(path, set()))
        finding["severity"], finding["severity_basis"] = _severity(finding)
        finding["reachability"] , finding["reachability_explanation"] = _reachable(finding)
        finding["taint_analysis"] = {"status": "not_established", "path": [],
                                      "explanation": "TracerPyX currently records risky operations and call-graph reachability but does not track attacker-controlled values across assignments or function boundaries."}
        finding["exploitability"] = finding.get("exploitability") or "not established by current static analysis"
        finding["remediation"], finding["remediation_example"] = _remediation(finding)
        identity = (finding.get("source"), finding.get("advisory_id"), path, line, finding.get("title"))
        finding["finding_id"] = hashlib.sha256(repr(identity).encode("utf-8")).hexdigest()[:24]
        finding["review_commentable"] = bool(finding["line_in_pr_diff"] and path and line)
        if path and line:
            finding["github_url"] = f"https://github.com/{repo}/blob/{head_sha}/{quote(path, safe='/')}#L{line}"
        finding["evidence"] = list(finding.get("evidence") or [])
        output.append(finding)
    return output


def _attribute(base_findings: list[dict], head_findings: list[dict], changed: list[dict],
               added_lines: dict[str, set[int]], deleted_lines: dict[str, set[int]]) -> tuple[list[dict], list[dict]]:
    by_key: dict[tuple, list[dict]] = defaultdict(list)
    for item in base_findings:
        by_key[_finding_key(item)].append(item)
    changed_paths = {item["path"] for item in changed}
    changed_paths.update(item["previous_path"] for item in changed if item.get("previous_path"))
    used: set[int] = set()
    results = []
    for finding in head_findings:
        path, line = finding.get("file"), finding.get("line")
        candidates = by_key.get(_finding_key(finding), [])
        match = next((item for item in candidates if id(item) not in used), None)
        if match:
            used.add(id(match))
            prior_verdict = match.get("verdict")
            current_verdict = finding.get("verdict")
            if prior_verdict in {"NOT REACHABLE", "UNCERTAIN"} and current_verdict == "REACHABLE":
                status, explanation = "worsened", "The same operation existed at base, but the head call graph now establishes a path from a discovered entry point. Taint and exploitability remain unestablished."
            elif match.get("severity") != finding.get("severity") and finding.get("severity") not in {None, "unknown"}:
                status, explanation = "worsened", "The matching head advisory has a higher reported severity than the base finding."
            else:
                status, explanation = "pre_existing", "A matching analyzer finding exists at both the base and head commits."
        elif path in changed_paths and line and line in added_lines.get(path, set()):
            status, explanation = "introduced", "The finding is anchored to a line added by this PR and no matching base finding was found."
        elif path and line and line in added_lines.get(path, set()):
            status, explanation = "introduced", "The finding is anchored to a line added by this PR and no matching base finding was found."
        else:
            status, explanation = "uncertain_attribution", "No matching base finding or direct added-line evidence was found; the relationship to this PR is not established."
        finding["classification"] = status
        finding["classification_explanation"] = explanation
        results.append(finding)
    fixed = []
    for item in base_findings:
        if id(item) in used:
            continue
        path, line = item.get("file"), item.get("line")
        dep_path = (item.get("version_source") or "").split(":", 1)[0]
        related_change = (path in changed_paths and bool(line and line in deleted_lines.get(path, set()))) or bool(dep_path and line and line in deleted_lines.get(dep_path, set()))
        status = "fixed" if related_change else "uncertain_attribution"
        out = dict(item)
        out["classification"] = status
        out["classification_explanation"] = ("A base finding is absent at head and its source line or dependency declaration was changed by this PR."
                                               if related_change else "A base finding was not matched at head, but no direct changed-line evidence establishes that this PR fixed it.")
        out["line_in_pr_diff"] = bool(path and line and line in deleted_lines.get(path, set()))
        out["review_commentable"] = False
        fixed.append(out)
    return results, fixed


def _compact_analysis(result: dict) -> dict:
    graph = result.get("graph") or {}
    return {"files_scanned": result.get("files_scanned", 0), "python_files": result.get("python_files", []),
            "manifests": result.get("manifests", []), "finding_count": len(result.get("findings", [])),
            "dependency_inventory": result.get("dependency_inventory", []),
            "analysis_warnings": result.get("analysis_warnings", []), "unsupported_files": result.get("unsupported_files", []),
            "summary": result.get("summary", {}), "analysis_diagnostics": result.get("analysis_diagnostics", {}),
            "graph": {"node_count": len(graph.get("nodes", [])), "edge_count": len(graph.get("edges", [])),
                      "entry_points": graph.get("entry_points", [])}, "status": result.get("status")}


def analyze_pull_request(client: GitHubAppClient, user_token: str, base_repository: dict,
                         pull: dict, file_items: list[dict], stage: Callable[[str], None],
                         check_cancel: Callable[[], bool]) -> dict:
    repo = base_repository["full_name"]
    pr_number = int(pull["number"])
    base_sha = pull["base"]["sha"]
    head_sha = pull["head"]["sha"]
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", base_sha) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", head_sha):
        raise GitHubCoverageError("GitHub did not provide full base and head commit SHAs")
    stage("detecting_changed_files")
    changed, added_lines, deleted_lines, diff_warnings = normalize_changed_files(file_items)
    diff_complete = all(item["diff_complete"] for item in changed)
    if not diff_complete:
        diff_warnings.append("One or more GitHub file patches are unavailable. Those files have no inline comment anchors.")
    stage("building_project_context")
    base_repo = repo
    head_repo = (pull.get("head", {}).get("repo") or {}).get("full_name") or repo
    if head_repo.casefold() != repo.casefold():
        # A private fork needs its own App installation; public forks can be read without one.
        client.get_json(f"/repos/{quote(head_repo, safe='/')}", token=client.repository_token(head_repo, user_token))
    temp_parent = Path(tempfile.mkdtemp(prefix="tracerpyx_pr_"))
    base_root, head_root = temp_parent / "base", temp_parent / "head"
    blob_cache: dict[str, bytes] = {}
    try:
        base_root.mkdir(); head_root.mkdir()
        base_snapshot = _snapshot(client, base_repo, base_sha, user_token, base_root, blob_cache, check_cancel)
        check_cancel()
        head_snapshot = _snapshot(client, head_repo, head_sha, user_token, head_root, blob_cache, check_cancel)
        base_contents = {item["path"]: item["data"] for item in base_snapshot["files"]}
        head_contents = {item["path"]: item["data"] for item in head_snapshot["files"]}
        def base_stage(name: str) -> None:
            stage("base_" + name)

        def head_stage(name: str) -> None:
            stage("head_" + name)

        base_analysis = analyze_project(base_root, repo + "@" + base_sha[:12], max_python_files=MAX_PYTHON_FILES,
                                        on_stage=base_stage, check_cancel=check_cancel, parallel_dependencies=True)
        check_cancel()
        head_analysis = analyze_project(head_root, repo + "@" + head_sha[:12], max_python_files=MAX_PYTHON_FILES,
                                        on_stage=head_stage, check_cancel=check_cancel, parallel_dependencies=True)
        stage("comparing_base_and_head")
        base_enriched = _enrich(base_analysis["findings"], base_contents, {}, deleted_lines, repo, pr_number, base_sha)
        head_enriched = _enrich(head_analysis["findings"], head_contents, added_lines, deleted_lines, repo, pr_number, head_sha)
        findings, fixed = _attribute(base_enriched, head_enriched, changed, added_lines, deleted_lines)
        def dependency_key(item: dict) -> tuple[str, str]:
            source = item.get("source", "")
            manifest_path = source.rsplit(":", 1)[0] if ":" in source else source
            return item.get("name", "").casefold(), manifest_path

        base_dependencies = {dependency_key(item): item for item in base_analysis.get("dependency_inventory", [])}
        head_dependencies = {dependency_key(item): item for item in head_analysis.get("dependency_inventory", [])}
        dependency_changes = {"added": [], "removed": [], "version_changed": []}
        for package_key in sorted(set(base_dependencies) | set(head_dependencies)):
            before, after = base_dependencies.get(package_key), head_dependencies.get(package_key)
            if before is None:
                dependency_changes["added"].append(after)
            elif after is None:
                dependency_changes["removed"].append(before)
            elif before.get("version") != after.get("version"):
                dependency_changes["version_changed"].append({"name": after["name"], "base": before, "head": after})
        stage("generating_final_report")
        warnings = list(dict.fromkeys([*base_snapshot["warnings"], *head_snapshot["warnings"], *diff_warnings,
                                       *base_analysis.get("analysis_warnings", []), *head_analysis.get("analysis_warnings", [])]))
        if base_snapshot["config_files"] or head_snapshot["config_files"]:
            warnings.append("Configuration files were retrieved into the commit snapshots; the current shared analyzer does not inspect their contents.")
        if any(f.get("taint_analysis", {}).get("status") == "not_established" for f in findings):
            warnings.append("Attacker-controlled value propagation is not implemented; no source-to-sink taint path is asserted.")
        summary = {
            "total_findings": len(findings) + len(fixed),
            "dependency_advisories": sum(f.get("category") == "dependency" for f in findings),
            "source_findings": sum(f.get("category") == "source-pattern" for f in findings),
            "introduced": sum(f.get("classification") == "introduced" for f in findings),
            "worsened": sum(f.get("classification") == "worsened" for f in findings),
            "fixed": sum(f.get("classification") == "fixed" for f in fixed),
            "pre_existing": sum(f.get("classification") == "pre_existing" for f in findings),
            "uncertain_attribution": sum(f.get("classification") == "uncertain_attribution" for f in findings) + sum(f.get("classification") == "uncertain_attribution" for f in fixed),
            "critical": sum(f.get("severity") == "critical" for f in findings),
            "high": sum(f.get("severity") == "high" for f in findings),
            "medium": sum(f.get("severity") == "medium" for f in findings),
            "low": sum(f.get("severity") == "low" for f in findings),
            "unknown_severity": sum(f.get("severity") == "unknown" for f in findings),
            "confirmed_reachable": sum(f.get("reachability") == "confirmed_reachable" for f in findings),
            "potentially_reachable_or_uncertain": sum(f.get("reachability") == "uncertain" for f in findings),
        }
        pr_info = {"number": pr_number, "title": pull.get("title"), "body": pull.get("body"),
                   "state": pull.get("state"), "draft": pull.get("draft"), "html_url": pull.get("html_url"),
                   "author": (pull.get("user") or {}).get("login"),
                   "base_branch": pull["base"].get("ref"), "base_sha": base_sha,
                   "head_branch": pull["head"].get("ref"), "head_sha": head_sha,
                   "head_repository": head_repo}
        report = {"repository": {"id": base_repository.get("id"), "full_name": repo,
                                 "private": base_repository.get("private"), "html_url": base_repository.get("html_url")},
                  "pull_request": pr_info, "base_sha": base_sha, "head_sha": head_sha,
                  "changed_files": changed, "diff_complete": diff_complete,
                  "dependency_changes": dependency_changes,
                  "head_analysis": _compact_analysis(head_analysis), "base_analysis": _compact_analysis(base_analysis),
                  "findings": findings, "fixed_findings": fixed, "summary": summary,
                  "coverage": {"base_python_files": base_snapshot["python_files"],
                               "head_python_files": head_snapshot["python_files"],
                               "base_tree_entries": base_snapshot["tree_entries"],
                               "head_tree_entries": head_snapshot["tree_entries"],
                               "base_configuration_files": base_snapshot["config_files"],
                               "head_configuration_files": head_snapshot["config_files"],
                               "configuration_analysis": "retrieved_not_analyzed"},
                  "analysis_warnings": warnings,
                  "classification_legend": {"introduced": "No matching base finding; exact added-line or affected-manifest evidence ties it to this PR.",
                                             "worsened": "A matching finding existed at base but evidence or reachability is worse at head.",
                                             "fixed": "A base finding is absent at head and its source line or dependency declaration changed.",
                                             "pre_existing": "A matching finding exists at both commits.",
                                             "uncertain_attribution": "The analyzer cannot tie the change confidently to this PR."},
                  "security_scope": {"source_code_executed": False, "taint_tracking": "not implemented",
                                     "exploitability": "not established by pattern matches or call-graph reachability"}}
        return report
    finally:
        shutil.rmtree(temp_parent, ignore_errors=True)
