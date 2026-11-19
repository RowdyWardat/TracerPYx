"""Offline scorer. Ground truth is consumed only after scan results exist."""

def acceptable(expected: str) -> set[str]:
    if expected == "REACHABLE": return {"REACHABLE"}
    if expected == "NOT_REACHABLE": return {"NOT REACHABLE"}
    if expected == "UNCERTAIN": return {"UNCERTAIN"}
    if "REACHABLE_IF_" in expected: return {"REACHABLE", "UNCERTAIN"}
    if expected == "NOT_REACHABLE_IF_CONSTANT_PROPAGATION_SUPPORTED": return {"NOT REACHABLE", "REACHABLE"}
    if expected.startswith("UNCERTAIN_OR_REACHABLE_IF_"): return {"UNCERTAIN", "REACHABLE"}
    return {"UNCLASSIFIED"}

def score(expected_cases: list[dict], actual_cases: list[dict]) -> dict:
    actual={case["case_id"]:case for case in actual_cases}
    tp=tn=fp=fn=accepted_count=exact_outcome_cases=exact_label_correct=0
    uncertain=unclassified=0
    for reference in expected_cases:
        result=actual.get(reference["id"])
        verdict=result.get("verdict","UNCLASSIFIED") if result else "UNCLASSIFIED"
        if verdict=="UNCERTAIN": uncertain+=1
        if verdict=="UNCLASSIFIED": unclassified+=1
        if verdict in acceptable(reference.get("expected","")): accepted_count+=1
        if reference.get("expected")=="REACHABLE":
            exact_outcome_cases+=1
            if verdict=="REACHABLE": tp+=1
            else: fn+=1
        elif reference.get("expected")=="NOT_REACHABLE":
            exact_outcome_cases+=1
            if verdict=="NOT REACHABLE": tn+=1
            elif verdict=="REACHABLE": fp+=1
        elif reference.get("expected")=="UNCERTAIN":
            exact_outcome_cases+=1
        if reference.get("expected") in {"REACHABLE", "NOT_REACHABLE", "UNCERTAIN"} and verdict == reference["expected"].replace("_", " "):
            exact_label_correct+=1
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    exact_case_count=sum(reference.get("expected") in {"REACHABLE", "NOT_REACHABLE", "UNCERTAIN"} for reference in expected_cases)
    return {"cases":len(expected_cases),"accepted":accepted_count,"true_positives":tp,"true_negatives":tn,"false_positives":fp,"false_negatives":fn,
            "exact_outcome_cases":exact_outcome_cases,"exact_outcome_coverage":exact_outcome_cases/len(expected_cases) if expected_cases else 0.0,
            "exact_label_correct":exact_label_correct,"precision":precision,"recall":recall,"f1":f1,
            "classification_accuracy":exact_label_correct/exact_case_count if exact_case_count else 0.0,
            "uncertainty_rate":uncertain/len(expected_cases) if expected_cases else 0.0,"unclassified_rate":unclassified/len(expected_cases) if expected_cases else 0.0}
