from collections import defaultdict

_BUILTINS={"print","len","range","str","int","float","bool","list","dict","set","tuple","enumerate","zip","sum","min","max","any","all","isinstance","super","property","classmethod","staticmethod","open","type","hasattr","repr","sorted","round","abs"}

def build_graph(files: list[dict]):
    graph=defaultdict(set); definitions=defaultdict(list); uncertain=False
    functions={fn["name"]:fn for file in files for fn in file.get("functions",[])}
    classes={c["name"]:c for file in files for c in file.get("classes",[])}
    # A decorator only establishes an external entry point when its framework
    # import and decorated receiver's construction are both present in this file.
    for file in files:
        imported={imp.get("module", "").split(".")[0] for imp in file.get("imports", [])}
        instances={item.get("variable"): item.get("class") for item in file.get("instances", [])}
        aliases={a.get("name"): a.get("target", "") for a in file.get("aliases", [])}

        def registered_target(expression):
            if not expression or "(" in expression or not expression.replace(".", "").isidentifier():
                return []
            first, dot, rest = expression.partition(".")
            resolved_expression = aliases.get(first, first) + (dot + rest if dot else "")
            return [name for name in functions if name == resolved_expression or name.endswith("." + resolved_expression)]

        for dec in file.get("decorators", []):
            expression=dec.get("name", "")
            receiver=expression.split(".", 1)[0].split("(", 1)[0]
            method=expression.split(".", 1)[1].split("(", 1)[0] if "." in expression else ""
            kind=instances.get(receiver)
            framework=(kind == "Flask" and "flask" in imported and method == "route") or (kind in {"FastAPI", "APIRouter"} and "fastapi" in imported and method in {"get", "post", "put", "patch", "delete", "options", "head", "api_route"})
            if framework:
                file.setdefault("entry_points", []).append({"name": dec["function"], "line": dec.get("line"), "kind": "verified-framework-route", "registration": f"@{expression}; {receiver} is constructed as {kind}; framework import detected"})
            celery_task = (kind == "Celery" and "celery" in imported and method in {"task", "shared_task"})
            shared_task = expression.rsplit(".", 1)[-1].split("(", 1)[0] == "shared_task" and any(target.startswith("celery.") for target in aliases.values())
            if celery_task or shared_task:
                file.setdefault("entry_points", []).append({"name": dec["function"], "line": dec.get("line"), "kind": "verified-celery-task", "registration": f"@{expression}; Celery import and task registration detected"})
        for call in file.get("calls", []):
            name = call.get("name", "")
            receiver, dot, method = name.partition(".")
            kind = instances.get(receiver) if dot else None
            target_expression = None
            registration_kind = None
            if kind == "Flask" and "flask" in imported and method == "add_url_rule":
                target_expression = call.get("keywords", {}).get("view_func")
                registration_kind = "verified-flask-url-rule"
            elif kind in {"FastAPI", "APIRouter"} and "fastapi" in imported and method == "add_api_route":
                target_expression = call.get("keywords", {}).get("endpoint")
                if not target_expression and len(call.get("arguments", [])) > 1:
                    target_expression = call["arguments"][1]
                registration_kind = "verified-fastapi-route"
            for target in registered_target(target_expression):
                file.setdefault("entry_points", []).append({"name": target, "line": call.get("line"), "kind": registration_kind,
                    "registration": f"{name} at {file['path']}:{call.get('line')} statically resolves to {target}"})
        # Django route functions become roots only when a statically resolved
        # django.urls.path/re_path registration points at a project function.
        django_path_aliases = {name for name, target in aliases.items() if target in {"django.urls.path", "django.urls.re_path"}}
        if "django" in imported and django_path_aliases:
            for call in file.get("calls", []):
                if call.get("name", "").rsplit(".", 1)[-1] not in django_path_aliases or len(call.get("arguments", [])) < 2:
                    continue
                expression = call["arguments"][1]
                candidates = registered_target(expression)
                if len(candidates) == 1:
                    file.setdefault("entry_points", []).append({"name": candidates[0], "line": call.get("line"), "kind": "verified-django-url", "registration": f"django.urls.{call['name'].rsplit('.', 1)[-1]} at {file['path']}:{call.get('line')} resolves to {candidates[0]}"})
    for name in functions: definitions[name.rsplit(".",1)[-1]].append(name); graph.setdefault(name,set())
    for file in files:
        for alias in file.get("aliases",[]):
            if alias.get("reexport") and alias["name"]!="*":
                pseudo=file["module"]+"."+alias["name"]
                targets=[name for name in functions if name==alias["target"] or name.endswith("."+alias["target"]) or name.rsplit(".",1)[0].endswith(alias["target"].rsplit(".",1)[0]) and name.rsplit(".",1)[-1]==alias["target"].rsplit(".",1)[-1]]
                if len(targets)==1: graph[pseudo].add(targets[0]); definitions[alias["name"]].append(pseudo)
    def resolve(target):
        nodes=set(functions)|set(graph)
        return [name for name in nodes if name==target or name.endswith("."+target)]
    call_index=[]
    for file in files:
        if file.get("errors"): uncertain=True; continue
        aliases={a["name"]:a["target"] for a in file.get("aliases",[])}
        instances={(x.get("function"),x["variable"]):x["class"] for x in file.get("instances",[])}
        for call in file.get("calls",[]):
            caller=call.get("caller") or "__module__:"+file["module"]
            name=call["name"]
            if call.get("constant_target"):
                found=resolve(call["constant_target"])
                if len(found)==1: graph[caller].add(found[0])
                else: uncertain=True
                call_index.append((file,call,[])); continue
            short=name.rsplit(".",1)[-1]
            candidates=definitions.get(short,[])
            alias_target=aliases.get(short)
            if alias_target and not alias_target.endswith(".*"):
                aliased=resolve(alias_target)
                if aliased: candidates=aliased
            if "." in name:
                receiver,method=name.rsplit(".",1)
                receiver_type=instances.get((call.get("caller"),receiver.split(".")[0]))
                if receiver_type:
                    typed=[fn for fn in definitions.get(method,[]) if any(fn.endswith("."+receiver_type+"."+method) or fn.endswith("."+base.split(".")[-1]+"."+method) for c in classes.values() if c["name"].endswith("."+receiver_type) for base in next((x.get("base") for f in files for x in f.get("inheritance",[]) if x["class"]==c["name"]),""))]
                    exact=[fn for fn in definitions.get(method,[]) if fn.endswith("."+receiver_type+"."+method)]
                    if exact: candidates=exact
                    elif typed: candidates=typed
            if len(candidates)==1:
                graph[caller].add(candidates[0]); call_index.append((file,call,candidates))
            elif len(candidates)>1:
                uncertain=True; call_index.append((file,call,candidates))
            elif name in {"<dynamic>","getattr","setattr","importlib.import_module","import_module","exec","eval","__import__"}:
                uncertain=True; call_index.append((file,call,[]))
            elif short not in _BUILTINS and not name.startswith(("self.","cls.")):
                uncertain=True; call_index.append((file,call,[]))
    # Resolve simple callback arguments interprocedurally: apply(cb) -> cb(value).
    for file,call,callees in call_index:
        if len(callees)!=1: continue
        callee=callees[0]
        if callee not in functions: continue
        params=functions[callee].get("parameters",[])
        aliases={a["name"]:a["target"] for a in file.get("aliases",[])}
        for index,arg in enumerate(call.get("arguments",[])):
            if index>=len(params) or not arg.isidentifier(): continue
            value=aliases.get(arg,arg)
            for target_file in files:
                for nested in target_file.get("calls",[]):
                    if nested.get("caller")==callee and nested["name"]==params[index]:
                        possible=resolve(value)
                        if len(possible)==1: graph[callee].add(possible[0])
                        elif value in definitions: graph[callee].update(definitions[value])
                        else: uncertain=True
    # Module initialization is not automatically an application entry point.
    # Only explicitly discovered entry points can establish reachability.
    roots={e["name"] for f in files for e in f.get("entry_points",[])}
    if not roots: uncertain=True
    return dict(graph),roots,uncertain
