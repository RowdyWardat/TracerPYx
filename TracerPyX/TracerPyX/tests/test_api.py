import io
import json
import zipfile
from pathlib import Path
import anyio
import httpx
from backend.main import app
from backend.benchmark_eval import score

async def _request(method, path, kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, **kwargs)

def request(method, path, **kwargs):
    return anyio.run(_request, method, path, kwargs)

def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, content in files.items(): z.writestr(name, content)
    return out.getvalue()

def test_health():
    assert request("GET", "/api/health").json()["status"] == "ok"

def test_root_has_service_landing_response():
    response = request("GET", "/")
    assert response.status_code == 200
    assert response.json()["dashboard"] == "http://localhost:3000"

def test_analysis_detects_reachable_synthetic_advisory():
    data = archive({"app.py": "from demo_codec import unsafe_decode\ndef main():\n    unsafe_decode('x')\n", "requirements.txt": "demo-codec==1"})
    response = request("POST", "/api/analyze", files={"file": ("sample.zip", data, "application/zip")})
    assert response.status_code == 200
    result = response.json()
    assert result["files_scanned"] == 1
    assert result["manifests"][0]["type"] == "requirements.txt"
    assert result["findings"][0]["verdict"] == "REACHABLE"
    assert "not real CVEs" in result["advisory_notice"]

def test_invalid_zip_returns_client_error():
    response = request("POST", "/api/analyze", files={"file": ("bad.zip", b"bad", "application/zip")})
    assert response.status_code == 400

def analyze_source(source):
    data = archive({"app.py": source})
    response = request("POST", "/api/analyze", files={"file": ("scenario.zip", data, "application/zip")})
    assert response.status_code == 200
    return response.json()["findings"][0]

def test_indirect_path_has_evidence():
    source = "from demo_codec import unsafe_decode\ndef first():\n    second()\ndef second():\n    unsafe_decode('x')\ndef main():\n    first()\n"
    finding = analyze_source(source)
    assert finding["verdict"] == "REACHABLE"
    assert finding["call_path"][-1] == "demo_codec.unsafe_decode"

def test_imported_but_unused_is_not_reachable():
    finding = analyze_source("from demo_codec import unsafe_decode\ndef main():\n    print('safe')\n")
    assert finding["verdict"] == "NOT REACHABLE"

def test_reflection_preserves_uncertainty():
    finding = analyze_source("from demo_auth import weak_verify\ndef main(value):\n    fn = getattr(value, 'check')\n    return fn()\n")
    assert finding["verdict"] == "UNCERTAIN"

def test_dynamic_import_preserves_uncertainty():
    finding = analyze_source("import importlib\nfrom demo_archive import unsafe_extract\ndef main(name):\n    mod = importlib.import_module(name)\n    return mod.run()\n")
    assert finding["verdict"] == "UNCERTAIN"

def test_function_import_alias_resolves_reachable_path():
    source = "from demo_codec import unsafe_decode as decode\ndef main():\n    decode('x')\n"
    finding = analyze_source(source)
    assert finding["verdict"] == "REACHABLE"
    assert len(finding["call_path"]) >= 2

def test_nested_and_recursive_functions_terminate_with_reachable_path():
    source = "from demo_codec import unsafe_decode\ndef main():\n    def inner():\n        unsafe_decode('x')\n        inner()\n    inner()\n"
    finding = analyze_source(source)
    assert finding["verdict"] == "REACHABLE"

def test_unknown_callback_call_does_not_become_false_negative():
    source = "from demo_codec import unsafe_decode\ndef main(callback):\n    callback(unsafe_decode)\n"
    finding = analyze_source(source)
    assert finding["verdict"] == "UNCERTAIN"

def test_zip_path_traversal_rejected():
    data = archive({"../escape.py": "from demo_codec import unsafe_decode"})
    response = request("POST", "/api/analyze", files={"file": ("traversal.zip", data, "application/zip")})
    assert response.status_code == 400

def test_manifest_is_data_and_is_not_executed():
    marker = "must_not_be_created"
    malicious = "import os; os.system('echo compromised > " + marker + "')"
    data = archive({"setup.py": malicious, "app.py": "print('safe')\n"})
    response = request("POST", "/api/analyze", files={"file": ("manifest.zip", data, "application/zip")})
    assert response.status_code == 200
    from pathlib import Path
    assert not Path(marker).exists()

def test_real_dependency_lookup_finding_is_returned_as_uncertain(monkeypatch):
    record = {"advisory_id": "GHSA-example", "aliases": ["CVE-example"], "title": "Upstream package advisory",
        "package": "flask", "installed_version": "0.12.2", "vulnerable_symbol": None, "verdict": "UNCERTAIN",
        "confidence": "LOW", "evidence": ["OSV reports affected package version."], "synthetic": False, "source": "OSV"}
    monkeypatch.setattr("backend.main.query_package", lambda package: [record])
    data = archive({"app.py": "from flask import Flask\napp=Flask(__name__)\n", "requirements.txt": "flask==0.12.2\n"})
    response = request("POST", "/api/analyze", files={"file": ("application.zip", data, "application/zip")})
    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["advisory_id"] == "GHSA-example"
    assert finding["verdict"] == "UNCERTAIN"

def test_unsafe_python_calls_are_reported_as_unconfirmed_source_leads():
    source = "import pickle\ndef load(data):\n    return pickle.loads(data)\n"
    finding = analyze_source(source)
    assert finding["category"] == "source-pattern"
    assert finding["cwe"] == ["CWE-502"]
    assert finding["verdict"] == "UNCERTAIN"
    assert "exploitability were not established" in finding["evidence"][0]

def test_multiple_python_security_patterns_surface_without_fake_cves():
    source = "import subprocess, pickle\ndef handler(data):\n    subprocess.check_output(data, shell=True)\n    return pickle.loads(data)\n"
    data = archive({"app.py": source})
    result = request("POST", "/api/analyze", files={"file": ("patterns.zip", data, "application/zip")}).json()
    patterns = [f for f in result["findings"] if f.get("category") == "source-pattern"]
    assert {f["cwe"][0] for f in patterns} >= {"CWE-78", "CWE-502"}
    assert all(f["verdict"] == "UNCERTAIN" and f["advisory_id"].startswith("LOCAL-") for f in patterns)

def test_source_pattern_is_evaluated_by_reachability_engine():
    data = archive({
        "app.py": "from service import handle\ndef main():\n    handle()\n",
        "service.py": "from sink import run\ndef handle():\n    run()\n",
        "sink.py": "import subprocess\ndef run():\n    subprocess.run('echo unsafe', shell=True)\n",
    })
    result = request("POST", "/api/analyze", files={"file": ("source-path.zip", data, "application/zip")}).json()
    finding = next(f for f in result["findings"] if f.get("category") == "source-pattern")
    assert finding["verdict"] == "REACHABLE"
    assert finding["graph_node_exists"] is True
    assert finding["resolved_function"].endswith(".run")
    assert len(finding["call_path"]) == 3
    assert "Execution path:" in finding["evidence"][-1]

def test_benchmark_sink_markers_produce_labeled_reachability_findings():
    data = archive({
        "app/main.py": "from app.direct import run_direct\ndef main():\n    run_direct()\nif __name__ == '__main__':\n    main()\n",
        "app/direct.py": "from vulnlib.parser import parse_document\ndef run_direct():\n    return parse_document('x')\n",
        "vulnlib/parser.py": "def parse_document(value):\n    # VULN-SINK: benchmark only\n    return value\n",
        "vulnlib/exporter.py": "def export_legacy(value):\n    # VULN-SINK: dormant benchmark only\n    return value\n",
    })
    result = request("POST", "/api/analyze", files={"file": ("benchmark.zip", data, "application/zip")}).json()
    findings = {f["vulnerable_symbol"].rsplit(".", 1)[-1]: f for f in result["findings"] if f.get("category") == "benchmark"}
    assert findings["parse_document"]["verdict"] == "REACHABLE"
    assert findings["export_legacy"]["verdict"] == "NOT REACHABLE"
    assert all(f["synthetic"] and f["source"] == "VULN-SINK benchmark marker" for f in findings.values())

def test_supplied_benchmark_cases_match_ground_truth_without_using_it_for_analysis():
    fixture = Path(__file__).parent / "fixtures" / "TracerPyX-Benchmark.zip"
    raw = fixture.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        expected = json.loads(zf.read("TracerPyX-Benchmark/ground_truth/expected_results.json"))
    response = request("POST", "/api/analyze", files={"file": ("TracerPyX-Benchmark.zip", raw, "application/zip")})
    assert response.status_code == 200
    actual = {case["case_id"]: case for case in response.json()["benchmark_cases"]}
    assert set(actual) == {case["id"] for case in expected["cases"]}
    for case in expected["cases"]:
        result = actual[case["id"]]
        if case["id"] == "T08":
            assert result["verdict"] in {"REACHABLE", "UNCERTAIN"}
        else:
            assert result["verdict"].replace(" ", "_") == case["expected"]

def test_benchmark_two_all_thirteen_scenarios_and_metrics():
    fixture = Path(__file__).parent / "fixtures" / "TracerPyX-Benchmark-2.zip"
    raw = fixture.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        expected = json.loads(zf.read("TracerPyX-Benchmark-2/ground_truth/expected_results.json"))
    response = request("POST", "/api/analyze", files={"file": ("TracerPyX-Benchmark-2.zip", raw, "application/zip")})
    result = response.json()
    actual = result["benchmark_cases"]
    assert len(actual) == 13
    assert result["summary"]["benchmark_reachable_scenarios"] == 9
    assert result["summary"]["benchmark_not_reachable_scenarios"] == 2
    assert result["summary"]["benchmark_uncertain_scenarios"] == 2
    assert result["summary"]["benchmark_unclassified_scenarios"] == 0
    metrics = score(expected["cases"], actual)
    assert metrics["accepted"] == 13
    assert metrics["exact_outcome_cases"] == 8
    assert metrics["exact_outcome_coverage"] == 8 / 13
    assert metrics["classification_accuracy"] == 1
    assert metrics["unclassified_rate"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1
    assert metrics["recall"] == 1

def test_orphan_scenario_is_uncertain_not_false_not_reachable():
    data = archive({
        "app.py": "def maybe_entry():\n    # T99 scenario entry\n    return 1\n",
        "vulnlib/sink.py": "def dangerous():\n    # T99 VULN-SINK synthetic\n    return 1\n",
    })
    response = request("POST", "/api/analyze", files={"file": ("orphan.zip", data, "application/zip")})
    assert response.status_code == 200
    case = next(item for item in response.json()["benchmark_cases"] if item["case_id"] == "T99")
    assert case["verdict"] == "UNCERTAIN"
    assert case["source_file"] == "app.py"
    assert case["detection_status"] == "DETECTED"
    assert case["advisory_match_status"].startswith("NOT APPLICABLE")
    assert case["reason"] is None

def test_agent_requires_configuration_and_scan_context(monkeypatch):
    import backend.main as api
    analysis_id = "12345678-1234-5678-1234-567812345678"
    api.ANALYSIS_STORE[analysis_id] = {"analysis_id": analysis_id, "project_name": "demo", "findings": [], "graph": {}, "summary": {}}
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    response = request("POST", "/api/agent/chat", json={"analysis_id": analysis_id, "message": "What is reachable?"})
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]
    missing = request("POST", "/api/agent/chat", json={"analysis_id": "87654321-4321-8765-4321-876543218765", "message": "hello"})
    assert missing.status_code == 404

def test_agent_uses_server_stored_scan_context_and_chat_history(monkeypatch):
    import backend.main as api
    analysis_id = "11111111-2222-3333-4444-555555555555"
    api.ANALYSIS_STORE[analysis_id] = {"analysis_id": analysis_id, "project_name": "project-a", "findings": [{"advisory_id": "GHSA-real", "package": "flask", "verdict": "UNCERTAIN"}], "graph": {}, "summary": {}}
    seen = {}
    def responder(context, history, message):
        seen.update({"context": context, "history": history, "message": message})
        return "Grounded answer: GHSA-real is UNCERTAIN."
    monkeypatch.setattr(api, "ask_agent", responder)
    first = request("POST", "/api/agent/chat", json={"analysis_id": analysis_id, "message": "Why uncertain?"})
    assert first.status_code == 200
    assert seen["context"]["findings"][0]["advisory_id"] == "GHSA-real"
    second = request("POST", "/api/agent/chat", json={"analysis_id": analysis_id, "message": "How do I fix it?"})
    assert second.status_code == 200
    assert len(api.CHAT_HISTORY[analysis_id]) == 4
    cleared = request("POST", "/api/agent/chat/clear", json={"analysis_id": analysis_id})
    assert cleared.json()["cleared"] is True
    assert analysis_id not in api.CHAT_HISTORY

def test_parse_failure_is_visible_as_unclassified():
    data = archive({"broken.py": "def broken(:\n    pass\n", "script.js": "ignored"})
    result = request("POST", "/api/analyze", files={"file": ("broken.zip", data, "application/zip")}).json()
    assert result["summary"]["unclassified_findings"] == 1
    assert result["findings"][0]["verdict"] == "UNCLASSIFIED"
    assert any(name.endswith("script.js") for name in result["unsupported_files"])
