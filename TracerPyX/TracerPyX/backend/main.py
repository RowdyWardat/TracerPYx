import io
import re
import shutil
import tempfile
import zipfile
import uuid
import time
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from backend.benchmark import analyze_annotated_cases
from ai_agent.chat import ask as ask_agent, make_context as make_agent_context
from engine.reachability import evaluate
from engine.source_reachability import analyze_source_finding
from graph.builder import build_graph
from integrations.osv import deduplicate, parse_pinned_requirements, query_package
from parser.python_parser import parse_file
from parser.security_patterns import scan_security_patterns
from reporter_command.json_report import to_jsonable
from scanning_matcher.advisories import SYNTHETIC_ADVISORIES

app = FastAPI(title="TracerPyX API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], allow_methods=["*"], allow_headers=["*"])
MAX_UPLOAD = 20 * 1024 * 1024
MAX_FILES = 2000
MAX_UNPACKED = 100 * 1024 * 1024
ANALYSIS_STORE: dict[str, dict] = {}
CHAT_HISTORY: dict[str, list[dict]] = {}
CHAT_TIMES: dict[str, list[float]] = {}

class ChatRequest(BaseModel):
    analysis_id: str = Field(min_length=36, max_length=36)
    message: str = Field(min_length=1, max_length=3000)

class ChatClearRequest(BaseModel):
    analysis_id: str = Field(min_length=36, max_length=36)

@app.get("/")
def index():
    return {"service": "TracerPyX API", "status": "ok", "health": "/api/health", "api_docs": "/docs", "dashboard": "http://localhost:3000"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "TracerPyX"}

@app.get("/api/agent/status")
def agent_status():
    import os
    return {"configured": bool(os.getenv("OPENAI_API_KEY")), "provider": "OpenAI Responses API"}

@app.post("/api/agent/chat")
async def agent_chat(payload: ChatRequest):
    analysis = ANALYSIS_STORE.get(payload.analysis_id)
    if analysis is None:
        raise HTTPException(404, "Analysis not found or expired. Run the scan again before starting a chat.")
    now = time.monotonic()
    recent = [instant for instant in CHAT_TIMES.get(payload.analysis_id, []) if now - instant < 60]
    if len(recent) >= 10:
        raise HTTPException(429, "Chat rate limit reached. Wait a minute before sending another message.")
    recent.append(now); CHAT_TIMES[payload.analysis_id] = recent
    history = CHAT_HISTORY.setdefault(payload.analysis_id, [])
    prompt = payload.message.strip()
    if not prompt:
        raise HTTPException(422, "Message cannot be blank.")
    answer = await run_in_threadpool(ask_agent, make_agent_context(analysis), history[-12:], prompt)
    history.extend([{"role": "user", "content": prompt}, {"role": "assistant", "content": answer}])
    CHAT_HISTORY[payload.analysis_id] = history[-24:]
    return {"analysis_id": payload.analysis_id, "answer": answer, "references": []}

@app.post("/api/agent/chat/clear")
def clear_agent_chat(payload: ChatClearRequest):
    CHAT_HISTORY.pop(payload.analysis_id, None)
    return {"cleared": True}

def _benchmark_sink_findings(root: Path, parsed: list[dict], graph: dict, roots: set[str]) -> list[dict]:
    """Honor inert VULN-SINK benchmark annotations without treating them as real advisories."""
    reachable = set(roots)
    pending = list(roots)
    while pending:
        node = pending.pop()
        for target in graph.get(node, set()) - reachable:
            reachable.add(target)
            pending.append(target)
    dynamic_names = {"getattr", "setattr", "globals", "locals", "exec", "eval", "__import__", "importlib.import_module", "import_module"}
    reachable_dynamic = any(call["name"] in dynamic_names and call.get("caller") in reachable for item in parsed for call in item.get("calls", []))
    findings = []
    for item in parsed:
        try:
            lines = (root / item["path"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, 1):
            if "VULN-SINK" not in line:
                continue
            fn = next((f for f in item.get("functions", []) if f["line"] <= line_number <= f.get("end_line", f["line"])), None)
            if not fn:
                continue
            symbol = fn["name"]
            result = evaluate({"id": "BENCH-SINK:" + symbol, "title": "Marked benchmark vulnerable sink", "package": item["module"].split(".")[-1], "symbol": symbol}, graph, roots, reachable_dynamic)
            finding = to_jsonable(result)
            finding.update({"synthetic": True, "source": "VULN-SINK benchmark marker", "category": "benchmark", "file": item["path"], "line": line_number,
                            "evidence": [f"{item['path']}:{line_number}: inert benchmark sink marker; this is not a real advisory or CVE.", *finding["evidence"]]})
            findings.append(finding)
    return findings

def analyze_zip(data: bytes, filename: str) -> dict:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "Upload must be a valid ZIP archive.") from exc
    infos = archive.infolist()
    if len(infos) > MAX_FILES:
        raise HTTPException(413, "Archive contains too many files.")
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise HTTPException(413, "Expanded archive exceeds 100 MB.")
    root = Path(tempfile.mkdtemp(prefix="tracerpyx_"))
    unpacked = 0
    try:
        for info in infos:
            if info.is_dir():
                continue
            rel = PurePosixPath(info.filename)
            if rel.is_absolute() or ".." in rel.parts:
                raise HTTPException(400, "ZIP contains an unsafe path.")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            target = (root.joinpath(*rel.parts)).resolve()
            if root.resolve() not in target.parents:
                raise HTTPException(400, "ZIP contains an unsafe path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(64 * 1024):
                    unpacked += len(chunk)
                    if unpacked > MAX_UNPACKED:
                        raise HTTPException(413, "Expanded archive exceeds 100 MB.")
                    dst.write(chunk)
        parsed = [parse_file(p, root) for p in list(root.rglob("*.py"))[:MAX_FILES]]
        graph, roots, uncertain = build_graph(parsed)
        manifests = []
        for name in ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock", "uv.lock", "setup.py", "setup.cfg"):
            manifests.extend({"path": p.relative_to(root).as_posix(), "type": name} for p in list(root.rglob(name))[:20])
        recognized = {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock", "uv.lock", "setup.py", "setup.cfg", "expected_results.json"}
        unsupported_files = [info.filename for info in infos if Path(info.filename).suffix.lower() not in {".py", ".txt", ".toml", ".lock", ".cfg"} and Path(info.filename).name not in recognized]
        dependency_findings = []
        advisory_warnings = []
        advisory_warnings.extend(f"{m['path']}: manifest detected, but dependency/version extraction is not implemented for {m['type']}" for m in manifests if m["type"] != "requirements.txt")
        requirements = list(root.rglob("requirements.txt"))[:20]
        for manifest in requirements:
            packages, parse_warnings = parse_pinned_requirements(manifest.read_text(encoding="utf-8", errors="replace"))
            advisory_warnings.extend(parse_warnings)
            for package in packages:
                try:
                    dependency_findings.extend(query_package(package))
                except Exception as exc:
                    advisory_warnings.append(f"OSV lookup failed for {package['name']}: {type(exc).__name__}")
        imports = {i["module"].lstrip(".") for f in parsed for i in f.get("imports", [])}
        calls = {c["name"] for f in parsed for c in f["calls"]}
        symbols = {f["name"] for f in parsed for f in f["functions"]}
        dependency_findings = deduplicate(dependency_findings)
        source_findings = [finding for parsed_file in parsed for finding in scan_security_patterns(root / parsed_file["path"], root)]
        # Source-pattern leads previously bypassed the reachability engine and
        # were permanently left at the scanner's default UNCERTAIN verdict.
        source_findings = [analyze_source_finding(f, parsed, graph, roots, uncertain) for f in source_findings]
        benchmark_findings = _benchmark_sink_findings(root, parsed, graph, roots)
        findings = list(dependency_findings) + source_findings + benchmark_findings
        benchmark_cases = analyze_annotated_cases(root, parsed, graph, roots)
        unclassified_findings = [{"advisory_id": "UNCLASSIFIED:" + item["path"], "title": "Python file could not be parsed", "package": "application source", "installed_version": None,
            "vulnerable_symbol": None, "verdict": "UNCLASSIFIED", "confidence": "NONE", "synthetic": False, "source": "Python AST parser", "category": "analysis-failure", "file": item["path"],
            "evidence": [error for error in item["errors"]]} for item in parsed if item["errors"]]
        findings.extend(unclassified_findings)
        for advisory in SYNTHETIC_ADVISORIES:
            module = advisory["symbol"].rsplit(".", 1)[0]
            if module in imports or advisory["symbol"] in calls or advisory["symbol"] in symbols or module.split(".")[0] in imports:
                target = advisory["symbol"]
                # Bind imported function names to their dependency symbol in the project graph.
                matched_graph = {node: set(edges) for node, edges in graph.items()}
                short_name = target.rsplit(".", 1)[-1]
                for parsed_file in parsed:
                    imported_names = {item["module"].lstrip(".") for item in parsed_file.get("imports", [])}
                    imported_module = module in imported_names or module.split(".")[0] in imported_names
                    if not imported_module:
                        continue
                    imported_aliases = {item["name"]: item["target"] for item in parsed_file.get("aliases", [])}
                    symbol_aliases = {name for name, imported_target in imported_aliases.items() if imported_target == target}
                    symbol_aliases.add(short_name)
                    for call in parsed_file["calls"]:
                        if call["name"].rsplit(".", 1)[-1] not in symbol_aliases:
                            continue
                        caller = call.get("caller")
                        if caller:
                            matched_graph.setdefault(caller, set()).add(target)
                        else:
                            matched_graph.setdefault("__module__:" + parsed_file["module"], set()).add(target)
                findings.append(to_jsonable(evaluate(advisory, matched_graph, roots, uncertain)))
        analysis_id = str(uuid.uuid4())
        unresolved_imports = [{"file": f["path"], "module": i["module"], "line": i["line"]} for f in parsed for i in f.get("imports", []) if i.get("module") and not any(p["module"] == i["module"] or p["module"].endswith("." + i["module"]) for p in parsed)]
        unresolved_calls = [{"file": f["path"], "caller": c.get("caller"), "name": c["name"], "line": c["line"]} for f in parsed for c in f.get("calls", []) if c["name"] not in {"<dynamic>"} and c["name"].split(".")[-1] not in {fn["name"].split(".")[-1] for p in parsed for fn in p.get("functions", [])}]
        result = {"analysis_id": analysis_id, "project_name": Path(filename).stem, "files_scanned": len(parsed), "manifests": manifests,
                "python_files": [f["path"] for f in parsed], "parsed_files": parsed,
                "graph": {"nodes": sorted(graph), "edges": [{"from": a, "to": b} for a, targets in graph.items() for b in sorted(targets)], "entry_points": sorted(roots)},
                "findings": findings, "advisory_notice": "SYNTH-PYX entries are fabricated demo data, not real CVEs. OSV entries come from the OSV API; unavailable lookups are reported as warnings.",
                "benchmark_cases": benchmark_cases, "analysis_warnings": [e for f in parsed for e in f["errors"]] + advisory_warnings,
                "unsupported_files": unsupported_files, "status": "complete",
                "analysis_diagnostics": {"python_files_discovered": len(parsed), "files_parsed": sum(not f["errors"] for f in parsed),
                    "files_failed_parse": [{"path": f["path"], "category": "syntax_or_read_error", "message": e, "stage": "python_ast_parse", "affects_other_findings": False, "suggested_resolution": "Fix the reported source syntax or encoding and rerun analysis."} for f in parsed for e in f["errors"]],
                    "functions_discovered": sum(len(f.get("functions", [])) for f in parsed), "entry_points": sorted(roots),
                    "call_graph_nodes": len(graph), "call_graph_edges": sum(len(v) for v in graph.values()),
                    "unresolved_imports": unresolved_imports[:500], "unresolved_calls": unresolved_calls[:500],
                    "vulnerable_operations_detected": len(source_findings), "reachability_traces_generated": sum(bool(f.get("call_path")) for f in findings),
                    "uncertain_findings": [{"id": f.get("advisory_id"), "file": f.get("file"), "line": f.get("line"), "reason": f.get("evidence", [])} for f in findings if f.get("verdict") == "UNCERTAIN"],
                    "dependency_resolution": "requirements.txt exact pins only; other manifests reported as unsupported",
                    "advisory_lookup": "offline_or_online_failures_present" if advisory_warnings else "completed"}}
        result["summary"] = {"total_benchmark_scenarios": len(benchmark_cases), "total_dependency_advisories": len(dependency_findings),
            "total_source_sinks": len(source_findings) + len(benchmark_findings), "reachable_findings": sum(f.get("verdict")=="REACHABLE" for f in findings),
            "not_reachable_findings": sum(f.get("verdict")=="NOT REACHABLE" for f in findings), "uncertain_findings": sum(f.get("verdict")=="UNCERTAIN" for f in findings),
            "unclassified_findings": sum(f.get("verdict")=="UNCLASSIFIED" for f in findings), "analysis_failures": len(unclassified_findings) + len(advisory_warnings),
            "benchmark_reachable_scenarios": sum(c.get("verdict")=="REACHABLE" for c in benchmark_cases),
            "benchmark_not_reachable_scenarios": sum(c.get("verdict")=="NOT REACHABLE" for c in benchmark_cases),
            "benchmark_uncertain_scenarios": sum(c.get("verdict")=="UNCERTAIN" for c in benchmark_cases),
            "benchmark_unclassified_scenarios": sum(c.get("verdict")=="UNCLASSIFIED" for c in benchmark_cases)}
        ANALYSIS_STORE[analysis_id] = result
        if len(ANALYSIS_STORE) > 50: ANALYSIS_STORE.pop(next(iter(ANALYSIS_STORE)))
        return result
    finally:
        shutil.rmtree(root, ignore_errors=True)

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip project archive.")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "ZIP upload exceeds 20 MB.")
    try:
        result = await run_in_threadpool(analyze_zip, data, file.filename)
        return JSONResponse(to_jsonable(result))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Analysis failed: {type(exc).__name__}") from exc
