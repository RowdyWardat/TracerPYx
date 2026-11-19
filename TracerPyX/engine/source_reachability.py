"""Attach source-pattern findings to the parsed project graph without guessing symbols."""
from collections import deque


def resolve_finding(finding: dict, parsed_files: list[dict]) -> dict:
    path = finding.get("file")
    line = finding.get("line")
    parsed = next((item for item in parsed_files if item.get("path") == path), None)
    if not parsed:
        return {"module": None, "function": None, "class": None, "node": None,
                "reason": "Finding source file was not present in the parsed-file inventory."}
    functions = [fn for fn in parsed.get("functions", []) if isinstance(line, int) and fn.get("line", 0) <= line <= fn.get("end_line", fn.get("line", 0))]
    if functions:
        fn = min(functions, key=lambda item: item.get("end_line", item["line"]) - item["line"])
        return {"module": parsed["module"], "function": fn["name"], "class": fn["name"].rsplit(".", 1)[0] if fn.get("method") else None,
                "node": fn["name"], "reason": None}
    if isinstance(line, int):
        # Module-level findings map to the module initialization node. This is
        # location mapping only; it does not make the module an application root.
        return {"module": parsed["module"], "function": None, "class": None,
                "node": "__module__:" + parsed["module"], "reason": None}
    return {"module": parsed["module"], "function": None, "class": None, "node": None,
            "reason": "Finding has no source line to resolve to a function or module."}


def _path(graph: dict[str, set[str]], roots: set[str], target: str) -> list[str]:
    queue = deque((root, [root]) for root in sorted(roots))
    seen = set()
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        if node in seen:
            continue
        seen.add(node)
        queue.extend((child, path + [child]) for child in sorted(graph.get(node, set()) - seen))
    return []


def analyze_source_finding(finding: dict, parsed_files: list[dict], graph: dict[str, set[str]], roots: set[str],
                           graph_incomplete: bool) -> dict:
    resolved = resolve_finding(finding, parsed_files)
    path = _path(graph, roots, resolved["node"]) if resolved["node"] else []
    registration = next((entry.get("registration") for item in parsed_files for entry in item.get("entry_points", []) if entry.get("name") == resolved["node"] and entry.get("registration")), None)
    out = dict(finding)
    out.update({"module": resolved["module"], "resolved_function": resolved["function"],
                "resolved_class": resolved["class"], "graph_node": resolved["node"],
                "graph_node_exists": bool(resolved["node"] in graph) if resolved["node"] else False,
                "call_path": path, "registration_evidence": registration,
                "vulnerability_status": "UNCONFIRMED_STATIC_PATTERN", "data_flow_evidence": None,
                "sanitization_evidence": None, "exploitability": "NOT ESTABLISHED BY STATIC PATTERN MATCH"})
    if path:
        out["verdict"] = "REACHABLE"
        out["confidence"] = "HIGH"
        out["reachability_reason"] = "A call-graph path connects a discovered application root to this source operation's containing node. This establishes sink reachability, not exploitability or tainted input."
        out["evidence"] = [*out.get("evidence", []), "Execution path: " + " -> ".join(path)]
        if registration:
            out["evidence"].append("Framework registration evidence: " + registration)
    elif resolved["reason"]:
        out["verdict"] = "UNCERTAIN"
        out["confidence"] = "LOW"
        out["reachability_reason"] = resolved["reason"]
    elif not roots:
        out["verdict"] = "UNCERTAIN"
        out["confidence"] = "LOW"
        out["reachability_reason"] = "No application entry points were identified; absence of a path cannot establish non-reachability."
    elif graph_incomplete:
        out["verdict"] = "UNCERTAIN"
        out["confidence"] = "LOW"
        out["reachability_reason"] = "Call graph is incomplete because parsing or call resolution reported unresolved behavior."
    else:
        out["verdict"] = "NOT REACHABLE"
        out["confidence"] = "MEDIUM"
        out["reachability_reason"] = "No path from the discovered roots reaches the resolved source operation in the analyzed graph. This does not determine exploitability."
    out["function_has_callers"] = bool(resolved["node"] and any(resolved["node"] in children for children in graph.values()))
    out["unresolved_call_count"] = 0 if not graph_incomplete else None
    return out
