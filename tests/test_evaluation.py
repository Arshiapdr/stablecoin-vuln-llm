import pytest

from asv.detect import Finding
from asv.evaluation import Label, evaluate, prf


def f(proto, file, fn, vid, detected, score=0.5, parse_failed=False):
    return Finding(slice_id=f"{proto}{fn}{vid}", protocol=proto, tier="primary",
                   file=file, contract="C", function=fn, start_line=1,
                   vuln_id=vid, report_category="A1", title="t",
                   detected=detected, confidence=0.9, severity="high",
                   score=score, parse_failed=parse_failed)


def test_prf_edges():
    assert prf(0, 0, 0)["f1"] == 0.0
    assert prf(1, 0, 0)["f1"] == 1.0


def test_evaluate_counts_tp_fp_fn():
    findings = [f("p", "a.sol", "x", "V1", True),
                f("p", "a.sol", "y", "V1", True),
                f("p", "a.sol", "z", "V1", False)]
    labels = [Label("p", "a.sol", "x", "V1"), Label("p", "a.sol", "z", "V1")]
    r = evaluate(findings, labels)["overall"]
    assert (r["tp"], r["fp"], r["fn"]) == (1, 1, 1)


def test_effective_f1_penalises_abstentions():
    good = [f("p", "a.sol", "x", "V1", True)]
    bad = [f("p", "a.sol", "x", "V1", True, parse_failed=True)]
    labels = [Label("p", "a.sol", "x", "V1")]
    assert evaluate(good, labels)["overall"]["effective_f1"] == 1.0
    assert evaluate(bad, labels)["overall"]["effective_f1"] == 0.0


def test_ranked_metrics_reward_ordering():
    findings = [f("p", "a.sol", "x", "V1", True, score=0.9),
                f("p", "a.sol", "x", "V2", True, score=0.1)]
    labels = [Label("p", "a.sol", "x", "V1")]
    r = evaluate(findings, labels)["ranked"]
    assert r["top_1"] == 1.0 and r["mrr"] == 1.0


# --- regressions for three flaws found in the end-to-end audit ---------------

def _f(fn, vid, detected, protocol="p", file="a/B.sol", score=0.9):
    from asv.detect import Finding
    return Finding(slice_id=f"s_{fn}_{vid}", protocol=protocol, tier="primary",
                   file=file, contract="B", function=fn, start_line=1,
                   vuln_id=vid, report_category="A1", title="t",
                   detected=detected, confidence=0.9, severity="high",
                   score=score, mitigation="M1")


def test_a_label_whose_class_was_never_retrieved_still_counts_as_a_miss():
    """Recall must not be inflated by labels that produced no finding.

    Previously the truth set was built only from findings that existed, so a
    label whose class retrieval never proposed vanished from the denominator:
    1 of 2 labels found reported recall 1.0 instead of 0.5.
    """
    from asv.evaluation import evaluate, Label
    labels = [Label(protocol="p", file_contains="a/B.sol", function="vulnA", vuln_id="V1"),
              Label(protocol="p", file_contains="a/B.sol", function="vulnB", vuln_id="V2")]
    findings = [_f("vulnA", "V1", True),      # found
                _f("vulnB", "V6", False)]     # V2 never proposed for vulnB
    res = evaluate(findings, labels)
    assert res["overall"]["recall"] == 0.5, "unretrieved label must count as FN"
    assert res["overall"]["fn"] == 1
    assert res["labels_unretrieved"] == 1
    assert "p:vulnB:V2" in res["unretrieved"]


def test_per_class_includes_classes_that_only_appear_in_labels():
    from asv.evaluation import evaluate, Label
    labels = [Label(protocol="p", file_contains="a/B.sol", function="v", vuln_id="V5")]
    res = evaluate([_f("other", "V1", False)], labels)
    assert "V5" in res["per_class"], "a class with a label but no finding must be reported"
    assert res["per_class"]["V5"]["fn"] == 1


def test_worst_critic_verdict_cannot_outrank_the_best():
    """`(0+0+0)/30 or 1.0` turned an all-zero critic score into the top score."""
    def score(conf, corr, prof, sev):
        return conf * ((corr + prof + sev) / 30.0)
    assert score(0.9, 0, 0, 0) < score(0.9, 9, 9, 9)
    assert score(0.9, 0, 0, 0) == 0.0


def test_bootstrap_honours_multiplicity_and_widens_with_small_samples():
    """Set-keyed resampling collapsed duplicates into ~63% subsampling."""
    from asv.evaluation import bootstrap_f1, Label
    labels = [Label(protocol="p", file_contains="a/B.sol", function=f"v{i}",
                    vuln_id="V1") for i in range(4)]
    findings = [_f(f"v{i}", "V1", i < 2) for i in range(4)]
    res = bootstrap_f1(findings, labels, iterations=500, seed=0)
    assert res["ci_low"] <= res["f1_mean"] <= res["ci_high"]
    # a genuine bootstrap on 4 units must show real spread, not a point mass
    assert res["ci_high"] > res["ci_low"]


def test_v8_terms_cannot_match_ordinary_english_words():
    """Static terms are substring-matched, so bare 'rate' fired on 'generate'."""
    from asv.config import Config
    from asv.kb import KnowledgeBase
    kb = KnowledgeBase.load(Config.load().knowledge_dir)
    innocent = ["generate", "iterate", "separate", "moderate", "accelerate",
                "operator", "delegate"]
    for term in kb.classes["V8"].static_checks.get("must_call", []):
        for word in innocent:
            assert term.lower() not in word, (
                f"V8 term {term!r} matches the unrelated word {word!r}")


# --- path portability -------------------------------------------------------
# A corpus collected on Windows once stored `x\market\keeper\swap.go` while
# every label says `x/market/keeper/swap.go`. Nothing crashed: the labels simply
# anchored to nothing, so the few-shot pool held no positives and the whole
# evaluation scored zero true positives. These tests pin the normalisation.
def test_labels_anchor_across_path_separators():
    from asv.config import file_matches, norm_rel
    lb = Label(protocol="terra-classic", file_contains="x/market/keeper/swap.go",
               function="ComputeSwap", vuln_id="V2")
    for stored in ("x/market/keeper/swap.go", "x\\market\\keeper\\swap.go"):
        assert file_matches(lb.file_contains, stored), stored
        assert lb.matches(f("terra-classic", stored, "ComputeSwap", "V2", True))
    assert norm_rel("a\\b/c") == "a/b/c"
    assert not file_matches("x/market/keeper/swap.go",
                            "x\\market\\keeper\\msg_server.go")


def test_collected_corpus_paths_are_posix():
    """Whatever the build OS, corpus.json must hold "/" paths."""
    from asv.config import Config
    from asv.corpus import load as load_corpus
    cfg = Config.load()
    if not (cfg.path("interim") / "corpus.json").exists():
        pytest.skip("needs a built corpus")
    assert not [f.rel_path for f in load_corpus(cfg) if "\\" in f.rel_path]


def test_confusion_cells_account_for_every_scored_pair():
    """TP + FN + FP + TN must equal the number of (slice, class) pairs scored.

    The TN term subtracted the whole truth-and-considered intersection, which
    already contains the detected labels counted in TP, so the confusion matrix
    summed to (pairs - TP). On the headline run that printed 420 cells for 423
    scored pairs, and understated accuracy.
    """
    findings = [f("p", "a.sol", "v1", "V1", True),       # tp
                f("p", "a.sol", "v2", "V1", False),      # fn
                f("p", "a.sol", "v3", "V1", True),       # fp
                f("p", "a.sol", "v4", "V1", False),      # tn
                f("p", "a.sol", "v5", "V1", False)]      # tn
    labels = [Label(protocol="p", file_contains="a.sol", function="v1", vuln_id="V1"),
              Label(protocol="p", file_contains="a.sol", function="v2", vuln_id="V1")]
    o = evaluate(findings, labels)["overall"]
    assert (o["tp"], o["fn"], o["fp"], o["tn"]) == (1, 1, 1, 2)
    assert o["tp"] + o["fn"] + o["fp"] + o["tn"] == len(findings)
