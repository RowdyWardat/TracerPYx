from engine.reachability import Verdict, evaluate

ADVISORY = {"id": "SYNTH", "title": "demo", "package": "demo", "symbol": "pkg.bad"}

def test_reachable_path():
    finding = evaluate(ADVISORY, {"app.main": {"pkg.bad"}}, {"app.main"})
    assert finding.verdict is Verdict.REACHABLE

def test_incomplete_graph_is_uncertain():
    finding = evaluate(ADVISORY, {}, {"app.main"}, uncertain=True)
    assert finding.verdict is Verdict.UNCERTAIN

def test_complete_graph_can_prove_not_reachable():
    finding = evaluate(ADVISORY, {"app.main": set()}, {"app.main"})
    assert finding.verdict is Verdict.NOT_REACHABLE

def test_verified_django_url_registration_is_an_entry_point(tmp_path):
    from graph.builder import build_graph
    from parser.python_parser import parse_file
    root = tmp_path
    (root / "views.py").write_text("def detail(request):\n    return None\n", encoding="utf-8")
    (root / "urls.py").write_text("from django.urls import path\nfrom views import detail\nurlpatterns = [path('detail/', detail)]\n", encoding="utf-8")
    parsed = [parse_file(path, root) for path in root.rglob("*.py")]
    _graph, roots, _uncertain = build_graph(parsed)
    assert any(root.endswith("detail") for root in roots)

def test_verified_celery_task_decorator_is_an_entry_point():
    from graph.builder import build_graph
    from parser.python_parser import parse_file
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tasks.py").write_text("from celery import Celery\napp = Celery('worker')\n@app.task\ndef send_email(user_id):\n    return user_id\n", encoding="utf-8")
        parsed = [parse_file(path, root) for path in root.rglob("*.py")]
        _graph, roots, _uncertain = build_graph(parsed)
        assert any(root.endswith("send_email") for root in roots)

def test_statically_registered_flask_callback_is_an_entry_point(tmp_path):
    from graph.builder import build_graph
    from parser.python_parser import parse_file
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef health():\n    return 'ok'\napp.add_url_rule('/health', view_func=health)\n", encoding="utf-8")
    parsed = [parse_file(path, tmp_path) for path in tmp_path.rglob("*.py")]
    _graph, roots, _uncertain = build_graph(parsed)
    assert any(root.endswith("health") for root in roots)
