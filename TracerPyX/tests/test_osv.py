from integrations.osv import deduplicate, parse_pinned_requirements, query_package

def test_requirements_parser_only_accepts_exact_pins():
    packages, warnings = parse_pinned_requirements("flask==0.12.2\nrequests>=2.0\n# ignored\n")
    assert packages == [{"name": "flask", "version": "0.12.2", "source": "requirements.txt:1"}]
    assert len(warnings) == 1

def test_osv_record_fields_are_source_data(monkeypatch):
    record = {"id": "GHSA-test", "aliases": ["CVE-2099-1234"], "summary": "Test advisory", "details": "Upstream description",
        "published": "2025-01-01T00:00:00Z", "modified": "2025-01-02T00:00:00Z", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-1"]}, "references": [{"url": "https://example.test/advisory"}],
        "affected": [{"package": {"name": "flask", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.13"}]}]}]}
    monkeypatch.setattr("integrations.osv._json_request", lambda *args: {"vulns": [record]})
    result = query_package({"name": "flask", "version": "0.12.2", "source": "requirements.txt:1"})[0]
    assert result["aliases"] == ["CVE-2099-1234", "GHSA-test"]
    assert result["fixed_versions"] == ["0.13"]
    assert result["cvss"] is None and result["cvss_vector"].startswith("CVSS:3.1/")
    assert result["verdict"] == "UNCERTAIN"
    assert result["synthetic"] is False
    assert result["declared_version"] == "0.12.2"
    assert result["installed_version"] is None
    assert result["version_source"] == "requirements.txt:1"

def test_alias_duplicates_for_one_dependency_are_merged():
    base = {"package": "flask", "installed_version": "0.12.2", "fixed_versions": [], "references": []}
    result = deduplicate([{**base, "aliases": ["OSV-1", "CVE-1"]}, {**base, "aliases": ["GHSA-1", "CVE-1"]}])
    assert len(result) == 1
    assert result[0]["aliases"] == ["CVE-1", "GHSA-1", "OSV-1"]
