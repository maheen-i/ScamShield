"""Evaluate rules / LLM / hybrid modes against eval/tests.csv."""
import argparse
import csv
import os
import sys
import time
from pathlib import Path

from scamshield.analyzer import analyze
from scamshield.rules import rule_flags, rule_score, rule_verdict

HERE = Path(__file__).parent
MAX_UNCONFIRMED_CALLS = 60
API_MODES = ("llm", "hybrid")


def load_rows(limit: int | None) -> list[dict]:
    """Load test rows from tests.csv, optionally limited."""
    with open(HERE / "tests.csv", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return rows[:limit] if limit else rows


def predict(row: dict, mode: str) -> dict:
    """Return verdict, risk_score and token usage for one row in one mode."""
    msg = row["message"]
    if mode == "rules":
        score = rule_score(rule_flags(msg))
        return {"verdict": rule_verdict(score), "risk_score": score,
                "in": 0, "out": 0}
    res = analyze(msg, use_rules=(mode == "hybrid"))
    if "error" in res:
        raise RuntimeError(res["error"])
    usage = res.get("usage", {})
    return {"verdict": res["verdict"], "risk_score": res["risk_score"],
            "in": usage.get("input_tokens", 0), "out": usage.get("output_tokens", 0)}


def run_mode(rows: list[dict], mode: str) -> list[dict]:
    """Run one mode over all rows, recording per-row outcomes."""
    out = []
    for row in rows:
        try:
            p = predict(row, mode)
            pred = "SAFE" if p["verdict"] == "LIKELY SAFE" else "SCAM"
        except ValueError as exc:
            if "ANTHROPIC_API_KEY" in str(exc):
                sys.exit(f"Aborting: {exc}")
            p, pred = {"verdict": "error", "risk_score": 0, "in": 0, "out": 0}, "error"
        except Exception:  # per-message failure counts as an error
            p, pred = {"verdict": "error", "risk_score": 0, "in": 0, "out": 0}, "error"
        out.append({"mode": mode, "label": row["label"], "category": row["category"],
                    "verdict": p["verdict"], "risk_score": p["risk_score"],
                    "pred": pred, "correct": pred == row["label"],
                    "in": p["in"], "out": p["out"], "message": row["message"]})
        if mode in API_MODES:
            time.sleep(0.3)
    return out


def summarize(mode: str, res: list[dict]) -> dict:
    """Compute accuracy, scam recall, false-alarm rate and tokens."""
    scams = [r for r in res if r["label"] == "SCAM"]
    safes = [r for r in res if r["label"] == "SAFE"]
    return {
        "mode": mode,
        "acc": sum(r["correct"] for r in res) / len(res) if res else 0.0,
        "recall": sum(r["correct"] for r in scams) / len(scams) if scams else 0.0,
        "false": sum(r["pred"] == "SCAM" for r in safes) / len(safes) if safes else 0.0,
        "in": sum(r["in"] for r in res), "out": sum(r["out"] for r in res),
    }


def print_report(summaries: list[dict], all_res: list[dict]) -> None:
    """Print the summary table, then every miss."""
    print(f"{'mode':<8}{'accuracy':>10}{'scam recall':>13}{'false alarm':>13}"
          f"{'in tokens':>11}{'out tokens':>12}")
    for s in summaries:
        print(f"{s['mode']:<8}{s['acc']:>10.1%}{s['recall']:>13.1%}{s['false']:>13.1%}"
              f"{s['in']:>11}{s['out']:>12}")
    print("\nMISSES")
    for r in all_res:
        if not r["correct"]:
            print(f"{r['mode']:<8}{r['label']:<5} predicted={r['pred']:<6} "
                  f"{r['message'][:60]}")


def write_results(all_res: list[dict]) -> None:
    """Write per-(mode, message) outcomes to results.csv (no message text)."""
    cols = ["mode", "label", "category", "verdict", "risk_score", "correct"]
    with open(HERE / "results.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_res)


def main() -> None:
    """Parse args, confirm API usage, run the chosen modes and report."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["rules", "llm", "hybrid", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()
    rows = load_rows(args.limit)
    modes = ["rules", "llm", "hybrid"] if args.mode == "all" else [args.mode]
    planned = len(rows) * sum(m in API_MODES for m in modes)
    model = os.getenv("SCAMSHIELD_MODEL", "claude-haiku-5-5")
    print(f"Planned API calls: {planned} (model: {model})")
    if planned > MAX_UNCONFIRMED_CALLS and not args.yes:
        sys.exit("Too many API calls planned; re-run with --yes to proceed.")
    all_res: list[dict] = []
    summaries = []
    for mode in modes:
        res = run_mode(rows, mode)
        all_res += res
        summaries.append(summarize(mode, res))
    print_report(summaries, all_res)
    write_results(all_res)


if __name__ == "__main__":
    main()
