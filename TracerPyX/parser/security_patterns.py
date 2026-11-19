"""Heuristic Python sink checks. Results are leads for review, never confirmed CVEs."""
import ast
import re
from pathlib import Path

def scan_security_patterns(path: Path, project_root: Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []
    rel = path.relative_to(project_root).as_posix()
    results = []
    class Visitor(ast.NodeVisitor):
        def __init__(self): self.owner = None
        def visit_FunctionDef(self, node):
            old = self.owner; self.owner = node.name; self.generic_visit(node); self.owner = old
        visit_AsyncFunctionDef = visit_FunctionDef
        def visit_Call(self, node):
            fn = ast.unparse(node.func)
            title = cwe = None
            if fn in {"eval", "exec"}: title, cwe = "Dynamic code evaluation", "CWE-95"
            elif fn in {"pickle.loads", "pickle.load", "yaml.load"}: title, cwe = "Unsafe deserialization or YAML loading", "CWE-502"
            elif fn.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords): title, cwe = "Subprocess invoked with shell=True", "CWE-78"
            elif fn.endswith(".execute") and node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)): title, cwe = "SQL query assembled by string formatting", "CWE-89"
            elif fn == "render_template_string": title, cwe = "Dynamic template rendered from a string", "CWE-79"
            elif fn == "send_file" and node.args and not isinstance(node.args[0], ast.Constant): title, cwe = "File path passed dynamically to send_file", "CWE-22"
            elif fn.startswith("requests.") and any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords): title, cwe = "TLS certificate verification disabled", "CWE-295"
            elif fn == "hashlib.md5": title, cwe = "MD5 used for security-sensitive hashing", "CWE-327"
            elif fn == "random.random": title, cwe = "Non-cryptographic random value generation", "CWE-338"
            elif fn == "redirect" and node.args and not isinstance(node.args[0], ast.Constant): title, cwe = "Redirect destination is dynamic", "CWE-601"
            elif fn.endswith(".run") and any(k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords): title, cwe = "Web application debug mode enabled", "CWE-489"
            if title:
                results.append({"advisory_id": f"LOCAL-{cwe}-{rel}-{node.lineno}", "title": title, "package": "application source", "installed_version": None,
                    "vulnerable_symbol": self.owner, "verdict": "UNCERTAIN", "confidence": "LOW", "synthetic": False,
                    "source": "TracerPyX heuristic Python source check", "category": "source-pattern", "cwe": [cwe],
                    "evidence": [f"{rel}:{node.lineno}: found {fn}() pattern; input provenance and exploitability were not established."],
                    "file": rel, "line": node.lineno, "aliases": []})
            self.generic_visit(node)
        def visit_Assign(self, node):
            value = node.value
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value and any(re.search(r"(password|passwd|secret|token|api.?key|access.?key|private.?key)", name, re.I) for name in names):
                for name in names:
                    if re.search(r"(password|passwd|secret|token|api.?key|access.?key|private.?key)", name, re.I):
                        results.append({"advisory_id": f"LOCAL-CWE-798-{rel}-{node.lineno}", "title": "Possible hardcoded credential or secret", "package": "application source", "installed_version": None,
                            "vulnerable_symbol": self.owner, "verdict": "UNCERTAIN", "confidence": "LOW", "synthetic": False, "source": "TracerPyX heuristic Python source check", "category": "source-pattern", "cwe": ["CWE-798"],
                            "evidence": [f"{rel}:{node.lineno}: constant assigned to sensitive-looking variable {name}; value is intentionally omitted and validity was not checked."], "file": rel, "line": node.lineno, "aliases": []})
            self.generic_visit(node)
    Visitor().visit(tree)
    return results
