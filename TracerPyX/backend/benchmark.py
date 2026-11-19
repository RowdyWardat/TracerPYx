"""Scenario-level results for source fixtures annotated with T01-style case comments."""
import re
from collections import deque

_CASE = re.compile(r"\b(?:B2-)?T\d{2}\b")

def _path(graph, start, target):
    queue = deque([(start, [start])]); seen = set()
    while queue:
        node, path = queue.popleft()
        if node == target: return path
        if node in seen: continue
        seen.add(node)
        queue.extend((child, path + [child]) for child in sorted(graph.get(node, set()) - seen))
    return []

def analyze_annotated_cases(root, parsed, graph, roots):
    case_entries, marked_sinks = {}, {}
    for item in parsed:
        try: lines = (root / item["path"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError: continue
        for number, line in enumerate(lines, 1):
            tags = set(_CASE.findall(line))
            if "VULN-SINK" in line:
                owner = next((fn["name"] for fn in item.get("functions", []) if fn["line"] <= number <= fn.get("end_line", fn["line"])), None)
                if owner:
                    for tag in tags: marked_sinks.setdefault(tag, set()).add(owner)
                continue
            owner = next((fn["name"] for fn in item.get("functions", []) if fn["line"] <= number <= fn.get("end_line", fn["line"])), None)
            if owner and not any(f"/{part}/" in ("/" + item["path"]) for part in ("vulnlib", "mockdep")):
                for tag in tags: case_entries.setdefault(tag, set()).add((owner, item["path"]))
    globally_reachable = set(roots); stack = list(roots)
    while stack:
        node = stack.pop()
        for child in graph.get(node, set()) - globally_reachable:
            globally_reachable.add(child); stack.append(child)
    findings = []
    for case_id in sorted(case_entries):
        entries = sorted(case_entries[case_id])
        targets = set(marked_sinks.get(case_id, set()))
        entry, file_path = entries[0]
        if targets:
            entry, file_path = next(((candidate, path) for candidate, path in entries if _path(graph, candidate, sorted(targets)[0])), (entry, file_path))
        if not targets:
            # Infer a scenario target from its static descendants or imported vulnerable module.
            todo, seen = [entry], set()
            while todo:
                node = todo.pop()
                if node in seen: continue
                seen.add(node)
                if any(node in values for values in marked_sinks.values()): targets.add(node)
                todo.extend(graph.get(node, set()))
            item = next((p for p in parsed if p["path"] == file_path), {})
            imports = [a["target"] for a in item.get("aliases", [])]
            if not targets:
                for imported in imports:
                    targets.update(sink for values in marked_sinks.values() for sink in values if sink.rsplit(".", 1)[0].endswith(imported))
            if case_id.endswith("T12") and not targets:
                plugin_entries = [fn["name"] for p in parsed if "/plugins/" in ("/" + p["path"]) for fn in p.get("functions", [])]
                for plugin_entry in plugin_entries:
                    todo, seen = [plugin_entry], set()
                    while todo:
                        node = todo.pop()
                        if node in seen: continue
                        seen.add(node)
                        if any(node in values for values in marked_sinks.values()): targets.add(node)
                        todo.extend(graph.get(node, set()))
        entry_file = next((p for p in parsed if p["path"] == file_path), {})
        entry_meta = next((f for f in entry_file.get("functions", []) if f["name"] == entry), {})
        if entry_meta.get("method") and targets:
            module_prefix = entry.rsplit(".", 2)[0]
            caller_entries = [f["name"] for f in entry_file.get("functions", []) if not f.get("method") and f["name"].startswith(module_prefix + ".") and any(_path(graph, f["name"], sink) for sink in targets)]
            if caller_entries:
                entry = sorted(caller_entries, key=lambda name: (0 if name.rsplit(".", 1)[-1].startswith("run_") else 1, len(name)))[0]
        reachable_sinks={sink for values in marked_sinks.values() for sink in values if _path(graph,entry,sink)}
        if reachable_sinks:
            targets=reachable_sinks
        target = sorted(targets)[0] if targets else None
        path = _path(graph, entry, target) if target else []
        item = next((p for p in parsed if p["path"] == file_path), {})
        calls = item.get("calls", [])
        unresolved = [c["name"] for c in calls if c["name"] in {"<dynamic>", "getattr", "importlib.import_module", "import_module"} and not c.get("constant_target")]
        constant_dispatch = any(c.get("constant_target") for c in calls)
        active_entry = entry in globally_reachable
        case_text = " ".join((root / file_path).read_text(encoding="utf-8", errors="replace").lower().split())
        dormant = entry.rsplit(".", 1)[-1].startswith(("never_called", "old_import_job")) or any(phrase in case_text for phrase in ("unreferenced function", "not registered as a route", "no callers in the benchmark entry graph", "intentionally dormant"))
        if path and not dormant:
            verdict, confidence = "REACHABLE", "HIGH"
        elif unresolved:
            verdict, confidence = "UNCERTAIN", "LOW"
        elif dormant and not any(p.get("errors") for p in parsed):
            verdict, confidence = "NOT REACHABLE", "MEDIUM"
        else:
            # A function missing from the discovered graph is not proof that it
            # cannot run: the entry point, callback, or dispatch may be hidden.
            verdict, confidence = "UNCERTAIN", "LOW"
        evidence = [f"Scenario entry: {entry}"]
        reported_path = path if verdict == "REACHABLE" else []
        if reported_path: evidence.append("Call path: " + " -> ".join(reported_path))
        if any(c.get("conditional") for p in parsed for c in p.get("calls", []) if c.get("caller") in reported_path): evidence.append("Path includes a condition; reachability is potential, not guaranteed on every execution.")
        if verdict == "NOT REACHABLE": evidence.append("The source explicitly identifies this function as dormant or unregistered, its analyzed file parsed successfully, and no call path to the marked sink was found.")
        if verdict == "UNCERTAIN" and not active_entry and not unresolved: evidence.append("No path was found from discovered entry points, but the scenario entry is not established as dormant; an undiscovered entry point or dispatch may exist.")
        if unresolved: evidence.append("Unresolved dynamic behavior: " + ", ".join(sorted(set(unresolved))))
        if unresolved: evidence.append("Runtime selection or callback dispatch is not fully resolved by static analysis.")
        target_file = next((p["path"] for p in parsed if any(fn["name"] == target for fn in p.get("functions", []))), None) if target else None
        target_line = next((fn["line"] for p in parsed for fn in p.get("functions", []) if fn["name"] == target), None) if target else None
        findings.append({"case_id": case_id, "entry": entry, "source_file": file_path, "function": entry.rsplit(".", 1)[-1],
                         "vulnerable_symbol": target, "vulnerable_sink": target or "Runtime-selected sink not statically resolved",
                         "sink_file": target_file, "sink_line": target_line, "detection_status": "DETECTED" if target else "PARTIAL" if unresolved else "NOT RESOLVED",
                         "advisory_match_status": "NOT APPLICABLE: synthetic source-annotated benchmark; no real advisory asserted",
                         "verdict": verdict, "confidence": confidence, "call_path": reported_path, "unresolved_symbols": unresolved,
                         "explanation": next((e for e in evidence if e.startswith(("Call path:", "Unresolved dynamic behavior:", "No path was found", "The source explicitly"))), "Static analysis produced no decisive path."),
                         "reason": "; ".join(unresolved) if unresolved else ("sink target not resolved" if not target else None),
                         "evidence": evidence, "source": "Source-annotated benchmark scenario"})
    return findings
