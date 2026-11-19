"""OSV lookups and conservative requirements.txt parsing (no manifest execution)."""
import json
import re
from urllib.request import Request, urlopen

_PIN = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.!+\-]+)(?:\s*;.*)?\s*$")
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

def parse_pinned_requirements(contents: str) -> tuple[list[dict], list[str]]:
    packages, warnings = [], []
    for number, line in enumerate(contents.splitlines(), 1):
        value = line.split("#", 1)[0].strip()
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
