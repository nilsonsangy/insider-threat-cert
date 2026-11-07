"""Analysis 6: validation against the official r4.2 insider answer key.

Compares the risk-score ranking (analysis 5) and each individual signal with
the official CERT answer key (data/answers/insiders.csv, release 4.2: 70
insiders across 3 scenarios). Reports precision and recall per signal,
precision at the top of the ranking, and how many insiders of each scenario are
caught. The answer key is used only here, for evaluation, never for detection.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

from analyses import a05_correlation
from insider_threat.score import SuspectScore, signal_users

__all__ = ["Verdict", "SignalMetrics", "run", "signal_metrics", "precision_at", "main"]

TRUE_POSITIVE = "true positive"
FALSE_POSITIVE = "false positive"


@dataclass(frozen=True)
class Verdict:
    user: str
    score: int
    in_answer_key: bool
    classification: str


@dataclass(frozen=True)
class SignalMetrics:
    signal: str
    flagged: int
    true_positives: int
    precision: float
    recall: float


def _insiders(answer_key: pd.DataFrame) -> set[str]:
    return {u for u in answer_key["user"].astype(str).str.strip() if u}


def run(ranking: list[SuspectScore], answer_key: pd.DataFrame, *, min_score: int = 1) -> list[Verdict]:
    insiders = _insiders(answer_key)
    out: list[Verdict] = []
    for s in ranking:
        if s.score < min_score:
            continue
        hit = s.user in insiders
        out.append(Verdict(s.user, s.score, hit, TRUE_POSITIVE if hit else FALSE_POSITIVE))
    return out


def signal_metrics(presence: dict[str, set[str]], answer_key: pd.DataFrame) -> list[SignalMetrics]:
    insiders = _insiders(answer_key)
    out = []
    for name, users in presence.items():
        tp = len(users & insiders)
        out.append(SignalMetrics(name, len(users), tp,
                                 tp / len(users) if users else 0.0,
                                 tp / len(insiders) if insiders else 0.0))
    return out


def precision_at(verdicts: list[Verdict], k: int) -> float:
    top = verdicts[:k]
    return sum(v.in_answer_key for v in top) / len(top) if top else 0.0


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a06_validation",
                                description="Analysis 6: validation against the official answer key.")
    p.add_argument("--top", type=int, default=30)
    args = p.parse_args(argv)

    sources, web_users = a05_correlation.load_inputs()
    key = sources["answer_key"]
    insiders = _insiders(key)
    ranking = a05_correlation.run(sources, web_users=web_users)
    verdicts = run(ranking, key)
    presence = signal_users(sources, web_users=web_users)

    print("Analysis 6: validation against the official answer key (r4.2)")
    print("=" * 72)
    print(f"Users in LDAP: {sources['ldap']['user_id'].nunique()} | insiders in the answer key: "
          f"{len(insiders)} (scenarios: "
          + ", ".join(f"{s}={n}" for s, n in key.groupby('scenario')['user'].nunique().items()) + ")")

    print("\nPer signal (who presents it vs. the answer key)")
    print(f"  {'signal':<22} {'flagged':>7} {'TP':>4} {'precision':>9} {'recall':>7}")
    for m in signal_metrics(presence, key):
        print(f"  {m.signal:<22} {m.flagged:>7} {m.true_positives:>4} "
              f"{m.precision:>9.1%} {m.recall:>7.1%}")

    print("\nRanking quality")
    for k in (10, 30, 70, 100):
        print(f"  precision@{k:<4} {precision_at(verdicts, k):6.1%}")
    by_score = pd.DataFrame([(v.score, v.in_answer_key) for v in verdicts], columns=["score", "tp"])
    if not by_score.empty:
        summary = by_score.groupby("score")["tp"].agg(["size", "sum"]).sort_index(ascending=False)
        print("  score  users  insiders")
        for score, r in summary.iterrows():
            print(f"  {score:>5}  {int(r['size']):>5}  {int(r['sum']):>8}")

    print("\nInsiders caught per scenario (top 70 of the ranking)")
    top70 = {v.user for v in verdicts[:70]}
    for scenario, g in key.groupby("scenario"):
        users = set(g["user"])
        print(f"  scenario {scenario}: {len(users & top70)}/{len(users)}")

    print(f"\nTop {args.top}")
    print(f"  {'':<5}{'user':<10} {'score':>5}  verdict")
    for v in verdicts[: args.top]:
        tag = "[TP]" if v.in_answer_key else "[FP]"
        print(f"  {tag} {v.user:<10} {v.score:>5}  {v.classification}")


if __name__ == "__main__":
    main()
