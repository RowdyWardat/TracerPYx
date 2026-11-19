from dataclasses import dataclass
from enum import Enum
from collections import deque

class Verdict(str, Enum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT REACHABLE"
    UNCERTAIN = "UNCERTAIN"

@dataclass
class Finding:
    advisory_id: str
    title: str
    package: str
    vulnerable_symbol: str
    verdict: Verdict
    evidence: list[str]
    synthetic: bool = True
    confidence: str = "LOW"
    call_path: list[str] = None
    unresolved_symbols: list[str] = None

def evaluate(advisory: dict, graph: dict[str, set[str]], roots: set[str], uncertain: bool = False) -> Finding:
    target = advisory["symbol"]
    seen, todo = set(), deque((root, [root]) for root in sorted(roots))
    while todo:
        node, path = todo.popleft()
        if node == target:
            return Finding(advisory["id"], advisory["title"], advisory["package"], target, Verdict.REACHABLE, ["A call-graph path connects an application entry point to the vulnerable symbol."], True, "HIGH", path, [])
        if node in seen:
            continue
        seen.add(node)
        todo.extend((next_node, path + [next_node]) for next_node in sorted(graph.get(node, set()) - seen))
    verdict = Verdict.UNCERTAIN if uncertain else Verdict.NOT_REACHABLE
    evidence = ["Static analysis has unresolved calls or incomplete project context."] if uncertain else ["No path found in the analyzed application call graph."]
    confidence = "LOW" if uncertain else "MEDIUM"
    return Finding(advisory["id"], advisory["title"], advisory["package"], target, verdict, evidence, True, confidence, [], ["unresolved dynamic dispatch"] if uncertain else [])
