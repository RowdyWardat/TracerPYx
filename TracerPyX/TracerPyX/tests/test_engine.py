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
