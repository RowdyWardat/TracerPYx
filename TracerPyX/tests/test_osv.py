from pathlib import Path

from integrations.osv import deduplicate, parse_dependency_manifest, parse_pinned_requirements, query_package

def test_requirements_parser_only_accepts_exact_pins():
    packages, warnings = parse_pinned_requirements("flask==0.12.2\nrequests>=2.0\n# ignored\n")
    assert packages == [{"name": "flask", "version": "0.12.2", "source": "requirements.txt:1"}]
    assert len(warnings) == 1

def test_supported_dependency_manifests_are_static_and_repository_relative(tmp_path):
    cases = {
        "requirements-prod.txt": "flask==2.0.0\n",
        "constraints-prod.in": "flask==2.0.0\n",
        "pyproject.toml": '[project]\ndependencies = ["requests==2.31.0"]\n',
        "Pipfile": '[packages]\nflask = "==2.0.0"\n',
        "Pipfile.lock": '{"default":{"flask":{"version":"==2.0.0"}},"develop":{}}\n',
        "poetry.lock": '[[package]]\nname = "flask"\nversion = "2.0.0"\n',
        "uv.lock": '[[package]]\nname = "flask"\nversion = "2.0.0"\n',
        "setup.py": 'from setuptools import setup\nsetup(install_requires=["flask==2.0.0"])\n',
        "setup.cfg": '[options]\ninstall_requires =\n    flask==2.0.0\n',
    }
    for name, content in cases.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        packages, warnings = parse_dependency_manifest(path, f"deps/{name}")
        assert not warnings, (name, warnings)
        expected_name = "requests" if name == "pyproject.toml" else "flask"
        assert packages and packages[0]["name"] == expected_name
        assert packages[0]["source"].startswith(f"deps/{name}:")

def test_setup_py_dynamic_dependencies_are_not_executed_or_assumed():
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "setup.py"
        path.write_text('setup(install_requires=load_dependencies())\n', encoding="utf-8")
        packages, warnings = parse_dependency_manifest(path, "setup.py")
    assert packages == []
    assert warnings and "dynamic install_requires" in warnings[0]

def test_osv_service_failure_is_separate_from_a_clean_lookup(tmp_path):
    from backend.analyzer import analyze_project
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
    def unavailable(_package):
        raise TimeoutError("upstream unavailable")
    result = analyze_project(root, "repo", parallel_dependencies=True, query_package_fn=unavailable)
    assert result["analysis_diagnostics"]["advisory_lookup"] == "unavailable"
    assert any("OSV lookup failed" in warning for warning in result["analysis_warnings"])

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
