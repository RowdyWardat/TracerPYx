import uuid
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from backend.benchmark import analyze_annotated_cases
from engine.reachability import evaluate
from engine.source_reachability import analyze_source_finding
from graph.builder import build_graph
from integrations.osv import deduplicate, parse_dependency_manifest, query_package
from parser.python_parser import parse_file
from parser.security_patterns import scan_security_patterns
from reporter_command.json_report import to_jsonable
from scanning_matcher.advisories import SYNTHETIC_ADVISORIES

MAX_FILES = 2000
MAX_PR_OSV_PACKAGES = 5000

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

def analyze_project(root: Path, filename: str, unsupported_file_paths: list[str] | None = None,
                    max_python_files: int = MAX_FILES,
                    on_stage: Callable[[str], None] | None = None,
                    check_cancel: Callable[[], bool] | None = None,
                    parallel_dependencies: bool = False,
                    query_package_fn: Callable[[dict], list[dict]] | None = None) -> dict:
    def stage(name: str) -> None:
        if on_stage:
            on_stage(name)

    def check(index: int) -> None:
        if check_cancel and index % 25 == 0:
            check_cancel()

    osv_query = query_package_fn or query_package

    python_paths = sorted(root.rglob("*.py"))
    if len(python_paths) > max_python_files:
        raise ValueError(f"Project contains {len(python_paths)} Python files; configured analysis limit is {max_python_files}.")
    stage("parsing_python_files")
    parsed = []
    for index, path in enumerate(python_paths, 1):
        check(index)
        parsed.append(parse_file(path, root))
    stage("building_call_graph")
    graph, roots, uncertain = build_graph(parsed)
    supported_manifest_names = {"pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg"}
    manifest_paths = sorted(path for path in root.rglob("*") if path.is_file() and
                            (path.name.lower() in supported_manifest_names or
                             path.name.lower().startswith(("requirements", "constraints")) and
                             path.name.lower().endswith((".txt", ".in"))))
    manifests = [{"path": path.relative_to(root).as_posix(), "type": path.name} for path in manifest_paths]
    unsupported_files = list(unsupported_file_paths or [])
    dependency_findings = []
    advisory_warnings = []
    stage("running_vulnerability_detection")
    packages_to_check = []
    manifest_parse_warning_count = 0
    for manifest_index, manifest in enumerate(manifest_paths, 1):
        check(manifest_index)
        rel_manifest = manifest.relative_to(root).as_posix()
        packages, parse_warnings = parse_dependency_manifest(manifest, rel_manifest)
        manifest_parse_warning_count += len(parse_warnings)
        advisory_warnings.extend(parse_warnings)
        packages_to_check.extend(packages)
    declared_dependencies = list(packages_to_check)
    if parallel_dependencies and len(packages_to_check) > MAX_PR_OSV_PACKAGES:
        advisory_warnings.append(f"OSV coverage is limited to the first {MAX_PR_OSV_PACKAGES} exact-pinned requirements entries; {len(packages_to_check) - MAX_PR_OSV_PACKAGES} entries were not queried.")
        packages_to_check = packages_to_check[:MAX_PR_OSV_PACKAGES]
    lookup_failures = 0
    lookup_count = len(packages_to_check)
    if parallel_dependencies and packages_to_check:
        pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tracerpyx-osv")
        futures = {pool.submit(osv_query, package): package for package in packages_to_check}
        try:
            for result_index, future in enumerate(as_completed(futures), 1):
                check(result_index)
                package = futures[future]
                try:
                    dependency_findings.extend(future.result())
                except Exception as exc:
                    lookup_failures += 1
                    advisory_warnings.append(f"OSV lookup failed for {package['name']}: {type(exc).__name__}")
        finally:
            for future in futures:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
    elif not parallel_dependencies:
        for package_index, package in enumerate(packages_to_check, 1):
            check(package_index)
            try:
                dependency_findings.extend(osv_query(package))
            except Exception as exc:
                lookup_failures += 1
                advisory_warnings.append(f"OSV lookup failed for {package['name']}: {type(exc).__name__}")
    imports = {i["module"].lstrip(".") for f in parsed for i in f.get("imports", [])}
    calls = {c["name"] for f in parsed for c in f["calls"]}
    symbols = {f["name"] for f in parsed for f in f["functions"]}
    dependency_findings = deduplicate(dependency_findings)
    common_import_names = {"pyyaml": "yaml", "pillow": "pil", "beautifulsoup4": "bs4",
                           "scikit-learn": "sklearn", "opencv-python": "cv2", "python-dateutil": "dateutil",
                           "python-dotenv": "dotenv"}
    imported_roots = {module.split(".", 1)[0].casefold() for module in imports}
    dependency_inventory = []
    for package in declared_dependencies:
        normalized = re.sub(r"[-_.]+", "-", package.get("name", "")).casefold()
        expected = common_import_names.get(normalized, normalized).casefold()
        dependency_inventory.append({**package, "usage": "python_import_observed" if expected in imported_roots
                                     else "no_matching_python_import_observed"})
    for finding in dependency_findings:
        package = re.sub(r"[-_.]+", "-", finding.get("package", "")).casefold()
        expected = common_import_names.get(package, package).casefold()
        observed = expected in imported_roots
        finding["dependency_usage"] = "python_import_observed" if observed else "no_matching_python_import_observed"
        finding.setdefault("evidence", []).append("A matching Python import was observed in the project." if observed else
            "No matching Python import was found in the parsed files; this does not prove the declared dependency is unused.")
    stage("running_reachability_analysis")
    source_findings = []
    for parsed_index, parsed_file in enumerate(parsed, 1):
        check(parsed_index)
        source_findings.extend(scan_security_patterns(root / parsed_file["path"], root))
    # Source-pattern leads previously bypassed the reachability engine and
    # were permanently left at the scanner's default UNCERTAIN verdict.
    analyzed_source_findings = []
    for index, finding in enumerate(source_findings, 1):
        check(index)
        analyzed_source_findings.append(analyze_source_finding(finding, parsed, graph, roots, uncertain))
    source_findings = analyzed_source_findings
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
            "dependency_inventory": dependency_inventory,
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
                "dependency_resolution": "exact static versions from supported manifests; dynamic or non-exact declarations are reported as warnings",
                "dependency_manifest_warnings": manifest_parse_warning_count,
                "advisory_lookup": ("unavailable" if lookup_count and lookup_failures == lookup_count else
                                    "partial_failure" if lookup_failures else
                                    "completed" if lookup_count else "no_exact_versions_to_check")}}
    result["summary"] = {"total_benchmark_scenarios": len(benchmark_cases), "total_dependency_advisories": len(dependency_findings),
        "total_source_sinks": len(source_findings) + len(benchmark_findings), "reachable_findings": sum(f.get("verdict")=="REACHABLE" for f in findings),
        "not_reachable_findings": sum(f.get("verdict")=="NOT REACHABLE" for f in findings), "uncertain_findings": sum(f.get("verdict")=="UNCERTAIN" for f in findings),
        "unclassified_findings": sum(f.get("verdict")=="UNCLASSIFIED" for f in findings), "analysis_failures": len(unclassified_findings) + len(advisory_warnings),
        "benchmark_reachable_scenarios": sum(c.get("verdict")=="REACHABLE" for c in benchmark_cases),
        "benchmark_not_reachable_scenarios": sum(c.get("verdict")=="NOT REACHABLE" for c in benchmark_cases),
        "benchmark_uncertain_scenarios": sum(c.get("verdict")=="UNCERTAIN" for c in benchmark_cases),
        "benchmark_unclassified_scenarios": sum(c.get("verdict")=="UNCLASSIFIED" for c in benchmark_cases)}
    return result
