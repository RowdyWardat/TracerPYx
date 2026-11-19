"""OSV lookups and conservative requirements.txt parsing (no manifest execution)."""
import json
import re
import ast
import tomllib
from urllib.request import Request, urlopen
from pathlib import Path

_PIN = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9_.!+\-]+)(?:\s*;.*)?\s*$")
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

def parse_pinned_requirements(contents: str) -> tuple[list[dict], list[str]]:
    packages, warnings = [], []
    for number, line in enumerate(contents.splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if value.startswith(("-r ", "--requirement ", "-r\t", "--requirement\t")):
            warnings.append(f"requirements.txt:{number}: nested requirements include is not expanded")
            continue
        if not value or value.startswith(("-", "http:", "https:")):
            if value and not value.startswith(("-r", "--")):
                warnings.append(f"requirements.txt:{number}: unsupported dependency reference")
            continue
        match = _PIN.match(value)
        if not match:
            warnings.append(f"requirements.txt:{number}: version is not exactly pinned; OSV lookup skipped")
            continue
        name, version = match.groups()
        if name.lower().startswith("demo-"):
            continue
        packages.append({"name": re.sub(r"[-_.]+", "-", name).lower(), "version": version, "source": f"requirements.txt:{number}"})
    return packages, warnings


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _manifest_line(contents: str, name: str, version: str) -> int:
    lines = contents.splitlines()
    normalized = _canonical_name(name)
    for index, line in enumerate(lines, 1):
        low = line.lower()
        if version.lower() in low and normalized.replace("-", "").strip() in re.sub(r"[^a-z0-9]", "", low):
            return index
    for index, line in enumerate(lines, 1):
        if version.lower() in line.lower():
            return index
    return 1


def _exact_spec(requirement: str) -> tuple[str, str] | None:
    value = requirement.strip().strip("'\"")
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9_.!+~-]+)(?:\s*;.*)?$", value)
    if match:
        return _canonical_name(match.group(1)), match.group(2)
    if value.startswith("==") and re.fullmatch(r"[A-Za-z0-9_.!+~-]+", value[2:]):
        return "", value[2:]
    # Poetry/Pipfile TOML exact versions are commonly represented as "1.2.3".
    if re.fullmatch(r"[A-Za-z0-9_.!+~-]+", value) and not value.startswith(("^", "~", ">", "<", "!", "*")):
        return "", value
    return None


def _append_exact(packages: list[dict], warnings: list[str], name: str, requirement: str,
                  contents: str, path: str, line: int | None = None) -> None:
    parsed = _exact_spec(requirement)
    if parsed is None:
        warnings.append(f"{path}:{line or 1}: dependency {name} is not exactly pinned; OSV lookup skipped")
        return
    parsed_name, version = parsed
    normalized_name = _canonical_name(name) if not parsed_name else parsed_name
    if not normalized_name or normalized_name.lower() == "python":
        return
    source_line = line or _manifest_line(contents, normalized_name, version)
    packages.append({"name": normalized_name, "version": version, "source": f"{path}:{source_line}"})


def _toml_lock_packages(data: dict, contents: str, path: str) -> tuple[list[dict], list[str]]:
    packages, warnings = [], []
    lines = contents.splitlines()
    for item in data.get("package", []):
        name, version = item.get("name"), item.get("version")
        if not name or not version:
            continue
        source = item.get("source")
        if isinstance(source, dict) and any(k in source for k in ("git", "directory", "editable", "path")):
            warnings.append(f"{path}: non-registry source for {name} is not queried against OSV")
            continue
        if isinstance(source, dict) and source.get("registry"):
            pass
        line_number = 1
        in_package = False
        for index, line in enumerate(lines, 1):
            if line.strip() == "[[package]]":
                in_package = False
            if re.match(r"\s*name\s*=\s*['\"]" + re.escape(name) + r"['\"]", line):
                in_package = True
            if in_package and re.match(r"\s*version\s*=\s*['\"]" + re.escape(version) + r"['\"]", line):
                line_number = index
                break
        packages.append({"name": _canonical_name(name), "version": version,
                         "source": f"{path}:{line_number}"})
    return packages, warnings


def parse_dependency_manifest(path: Path, source_path: str | None = None) -> tuple[list[dict], list[str]]:
    """Read supported Python manifests without evaluating project code."""
    # Findings and warnings are returned to users; keep them repository-relative
    # even when the analyzer reads from a temporary absolute directory.
    rel = source_path or path.as_posix()
    contents = path.read_text(encoding="utf-8", errors="replace")
    name = path.name.lower()
    if name.startswith(("requirements", "constraints")) and name.endswith((".txt", ".in")):
        packages, warnings = parse_pinned_requirements(contents)
        for package in packages:
            line = package["source"].rsplit(":", 1)[-1]
            package["source"] = f"{rel}:{line}"
        return packages, [f"{rel}:{warning.split(':', 1)[-1]}" for warning in warnings]
    try:
        if name.endswith(".toml") or name in {"pipfile", "poetry.lock", "uv.lock"}:
            data = tomllib.loads(contents)
            if name in {"poetry.lock", "uv.lock"}:
                return _toml_lock_packages(data, contents, rel)
            packages, warnings = [], []
            project = data.get("project", {})
            for requirement in [*project.get("dependencies", []), *(x for group in project.get("optional-dependencies", {}).values() for x in group)]:
                m = re.match(r"^([A-Za-z0-9_.-]+)", requirement)
                if m:
                    _append_exact(packages, warnings, m.group(1), requirement, contents, rel)
            poetry = data.get("tool", {}).get("poetry", {})
            poetry_tables = [poetry.get("dependencies", {})]
            poetry_tables.extend(group.get("dependencies", {}) for group in poetry.get("group", {}).values())
            for table in poetry_tables:
                for dependency, spec in table.items():
                    if dependency.lower() == "python":
                        continue
                    version_spec = spec.get("version") if isinstance(spec, dict) else spec
                    if isinstance(version_spec, str):
                        _append_exact(packages, warnings, dependency, version_spec, contents, rel)
            if name == "pipfile":
                for section in ("packages", "dev-packages"):
                    for dependency, spec in data.get(section, {}).items():
                        version_spec = spec.get("version") if isinstance(spec, dict) else spec
                        if isinstance(version_spec, str):
                            _append_exact(packages, warnings, dependency, version_spec, contents, rel)
            return packages, warnings
        if name == "pipfile.lock":
            data = json.loads(contents)
            packages, warnings = [], []
            lines = contents.splitlines()
            for section in ("default", "develop"):
                for dependency, spec in data.get(section, {}).items():
                    version = (spec.get("version") or "").removeprefix("==")
                    if not version:
                        warnings.append(f"{rel}: lock entry for {dependency} has no exact version")
                        continue
                    line = next((i for i, row in enumerate(lines, 1) if '"version"' in row and version in row),
                                next((i for i, row in enumerate(lines, 1) if f'"{dependency}"' in row), 1))
                    packages.append({"name": _canonical_name(dependency), "version": version,
                                     "source": f"{rel}:{line}"})
            return packages, warnings
        if name == "setup.cfg":
            packages, warnings = [], []
            active = False
            for line_number, line in enumerate(contents.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("["):
                    active = stripped.lower() == "[options]"
                    continue
                if active and stripped.lower().startswith("install_requires") and "=" in stripped:
                    right = stripped.split("=", 1)[1]
                    for offset, requirement in enumerate([right, *contents.splitlines()[line_number:]], 0):
                        value = requirement.strip()
                        if not value:
                            continue
                        match = re.match(r"^([A-Za-z0-9_.-]+)", value)
                        if match:
                            _append_exact(packages, warnings, match.group(1), value, contents, rel, line_number + offset)
                        elif offset:
                            break
                    break
            return packages, warnings
        if name == "setup.py":
            packages, warnings = [], []
            tree = ast.parse(contents, filename=rel)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if keyword.arg != "install_requires":
                        continue
                    if not isinstance(keyword.value, (ast.List, ast.Tuple)):
                        warnings.append(f"{rel}:{getattr(keyword.value, 'lineno', node.lineno)}: dynamic install_requires expression skipped")
                        continue
                    for requirement_node in keyword.value.elts:
                        if not isinstance(requirement_node, ast.Constant) or not isinstance(requirement_node.value, str):
                            warnings.append(f"{rel}:{getattr(requirement_node, 'lineno', node.lineno)}: dynamic install_requires item skipped")
                            continue
                        requirement = requirement_node.value
                        match = re.match(r"^([A-Za-z0-9_.-]+)", requirement)
                        if match:
                            _append_exact(packages, warnings, match.group(1), requirement, contents, rel, requirement_node.lineno)
            return packages, warnings
    except (ValueError, OSError, SyntaxError) as exc:
        return [], [f"{rel}: manifest parse failed ({type(exc).__name__})"]
    return [], [f"{rel}: manifest type is not supported for dependency extraction"]

def _json_request(url: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "TracerPyX/0.1"})
    with urlopen(req, timeout=4) as response:
        if response.status != 200:
            raise OSError(f"OSV returned HTTP {response.status}")
        return json.loads(response.read(2_000_001))

def query_package(package: dict) -> list[dict]:
    """Return source facts only. Lookup failures are handled by the caller."""
    result = _json_request(OSV_QUERY, {"package": {"name": package["name"], "ecosystem": "PyPI"}, "version": package["version"]})
    findings = []
    for vuln in result.get("vulns", []):
        canonical = lambda name: re.sub(r"[-_.]+", "-", name).lower()
        affected_entries = [a for a in vuln.get("affected", []) if canonical(a.get("package", {}).get("name", "")) == canonical(package["name"])]
        ranges = []
        fixed = []
        for affected in affected_entries:
            for item in affected.get("ranges", []):
                events = item.get("events", [])
                ranges.append({"type": item.get("type"), "events": events})
                fixed.extend(event["fixed"] for event in events if "fixed" in event)
        aliases = sorted(set([vuln.get("id", ""), *vuln.get("aliases", [])]) - {""})
        severities = vuln.get("severity", [])
        cvss_vector = next((s.get("score") for s in severities if s.get("type", "").startswith("CVSS")), None)
        database = vuln.get("database_specific", {})
        findings.append({"advisory_id": vuln.get("id"), "title": vuln.get("summary") or vuln.get("id"), "aliases": aliases, "package": package["name"], "declared_version": package["version"], "installed_version": None, "version_source": package["source"], "vulnerable_symbol": None,
            "affected_ranges": ranges, "fixed_versions": sorted(set(fixed)), "cvss": None, "cvss_vector": cvss_vector, "severity": database.get("severity"),
            "cwe": database.get("cwe_ids", []), "description": vuln.get("details"), "published": vuln.get("published"),
            "modified": vuln.get("modified"), "references": [r.get("url") for r in vuln.get("references", []) if r.get("url")],
            "source": "OSV", "synthetic": False, "verdict": "UNCERTAIN", "confidence": "LOW",
            "evidence": [f"OSV reports declared dependency {package['name']} {package['version']} as affected; installed runtime version and vulnerable-function mapping are not available."]})
    return findings

def deduplicate(findings: list[dict]) -> list[dict]:
    """Merge duplicate database records for one installed package version by aliases."""
    output = []
    for finding in findings:
        identity = (finding.get("package"), finding.get("declared_version", finding.get("installed_version")))
        aliases = set(finding.get("aliases", []))
        match = next((item for item in output if (item.get("package"), item.get("declared_version", item.get("installed_version"))) == identity and aliases.intersection(item.get("aliases", []))), None)
        if match is None:
            output.append(finding)
            continue
        match["aliases"] = sorted(set(match.get("aliases", [])) | aliases)
        match["fixed_versions"] = sorted(set(match.get("fixed_versions", [])) | set(finding.get("fixed_versions", [])))
        match["references"] = sorted(set(match.get("references", [])) | set(finding.get("references", [])))
    return output
