import ast
from pathlib import Path

def parse_file(path: Path, root: Path) -> dict:
    rel = path.relative_to(root).as_posix()
    module = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel.replace("/", ".")
    if module.endswith(".__init__"): module = module[:-9]
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=rel)
    except (SyntaxError, OSError) as exc:
        return {"path": rel, "module": module, "functions": [], "classes": [], "imports": [], "calls": [], "errors": [str(exc)]}
    functions, classes, imports, calls, aliases, decorators, inheritance, entry_points, instances = [], [], [], [], [], [], [], [], []
    class Visitor(ast.NodeVisitor):
        def __init__(self): self.stack=[]; self.owner=None; self.conditional=False
        def visit_FunctionDef(self,node):
            old=self.owner; name=".".join([module,*self.stack,node.name])
            args=node.args; params=[x.arg for x in [*args.posonlyargs,*args.args,*args.kwonlyargs]]
            if args.vararg: params.append(args.vararg.arg)
            if args.kwarg: params.append(args.kwarg.arg)
            functions.append({"name":name,"line":node.lineno,"end_line":node.end_lineno,"async":isinstance(node,ast.AsyncFunctionDef),"method":bool(self.stack),"parameters":params})
            decorator_names=[ast.unparse(d) for d in node.decorator_list]
            decorators.extend({"function":name,"name":decorator,"line":d.lineno} for d,decorator in zip(node.decorator_list,decorator_names))
            if node.name=="main": entry_points.append({"name":name,"line":node.lineno,"kind":"main"})
            self.stack.append(node.name); self.owner=name; self.generic_visit(node); self.stack.pop(); self.owner=old
        visit_AsyncFunctionDef=visit_FunctionDef
        def visit_ClassDef(self,node):
            name=".".join([module,*self.stack,node.name]); classes.append({"name":name,"line":node.lineno,"end_line":node.end_lineno})
            inheritance.extend({"class":name,"base":ast.unparse(base),"line":base.lineno} for base in node.bases)
            self.stack.append(node.name); self.generic_visit(node); self.stack.pop()
        def visit_If(self,node):
            old=self.conditional; self.conditional=True; self.generic_visit(node); self.conditional=old
        def visit_Import(self,node):
            for item in node.names:
                imports.append({"module":item.name,"line":node.lineno,"relative_level":0,"conditional":self.conditional})
                aliases.append({"name":item.asname or item.name.split(".")[0],"target":item.name,"line":node.lineno})
        def visit_ImportFrom(self,node):
            base=node.module or ""
            if node.level:
                package=module if rel.endswith("__init__.py") else module.rpartition(".")[0]
                parts=package.split(".") if package else []
                if node.level>1: parts=parts[:-(node.level-1)]
                base=".".join([*parts,*([base] if base else [])])
            imports.append({"module":base,"line":node.lineno,"relative_level":node.level,"conditional":self.conditional})
            for item in node.names:
                aliases.append({"name":item.asname or item.name,"target":base+("."+item.name if item.name!="*" else ".*"),"line":node.lineno,"reexport":rel.endswith("__init__.py")})
        def visit_Assign(self,node):
            if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name):
                for target in node.targets:
                    if isinstance(target,ast.Name): instances.append({"function":self.owner,"variable":target.id,"class":node.value.func.id,"line":node.lineno})
            self.generic_visit(node)
        def visit_Call(self,node):
            f=node.func
            if isinstance(f,ast.Name): name=f.id
            elif isinstance(f,ast.Attribute):
                parts=[]; cur=f
                while isinstance(cur,ast.Attribute): parts.append(cur.attr); cur=cur.value
                if isinstance(cur,ast.Name): parts.append(cur.id)
                name=".".join(reversed(parts))
            else: name="<dynamic>"
            constant_target=None
            if isinstance(f,ast.Name) and f.id=="getattr" and len(node.args)>=2 and isinstance(node.args[0],ast.Name) and isinstance(node.args[1],ast.Constant) and isinstance(node.args[1].value,str):
                base=next((a["target"] for a in aliases if a["name"]==node.args[0].id),node.args[0].id)
                constant_target=base+"."+node.args[1].value
            calls.append({"name":name,"line":node.lineno,"caller":self.owner,"conditional":self.conditional,"constant_target":constant_target,"arguments":[ast.unparse(a) for a in node.args],"keywords":{k.arg:ast.unparse(k.value) for k in node.keywords if k.arg}})
            self.generic_visit(node)
    Visitor().visit(tree)
    return {"path":rel,"module":module,"functions":functions,"classes":classes,"imports":imports,"aliases":aliases,"calls":calls,"decorators":decorators,"inheritance":inheritance,"instances":instances,"entry_points":entry_points,"errors":[]}
