#!/usr/bin/env python3
"""Benchmark PhishLens on the E-PhishLLM dataset (E-PhishGEN project).

E-PhishLLM is an *external* dataset PhishLens was not designed around: 16,616
emails across ten detected languages, each a dict with ``Subject``, ``Body``,
``type`` (0 = legitimate, 1 = phishing) and ``Language``. This script measures
how well PhishLens's existing verdicts hold up on that unfamiliar data.

Only ``Subject`` + ``Body`` are available, so PhishLens is called on the raw
email text with no header/sender context. That means the header-dependent
checks (SPF/DKIM/DMARC, spoofing, attachments, QR) have nothing to fire on; the
detectors actually exercised here are the body-derived ones — manipulation
tactics, writing-style/authorship signals, pretext archetypes, in-body URLs,
credential-harvest language, and the cross-signal aggregation on top. This is
the honest operating condition for body-only email data.

Methodology (in order)
----------------------
1. Restrict to a single language (default English) — the largest, cleanest slice.
2. Split that slice into a DEV portion and a HELD-OUT portion (stratified,
   seeded, stable across runs).
3. On DEV: score every email, show the score distribution by class, evaluate
   PhishLens's current verdicts, and report accuracy / precision / recall / F1 /
   FPR + confusion matrix.
4. Inspect the worst false positives and false negatives (with PhishLens's own
   reasons) so detector logic can be improved deliberately.
5. A threshold sweep on DEV suggests an operating point — but you tune on DEV
   only.
6. When (and only when) you are done iterating, run ``--confirm --threshold X``
   to score the HELD-OUT portion ONCE at the operating point you chose. That
   number is the one to report. The default run never touches held-out, so the
   benchmark can't silently become a tuning set.

Zero third-party deps for the core (stdlib only). If ``matplotlib`` is present,
a score-distribution plot and a confusion-matrix PNG are also written.

Examples
--------
    # DEV benchmark on English (steps 1-5), held-out left untouched
    python evaluation/evaluation.py

    # Same, but inspect more errors and save every prediction
    python evaluation/evaluation.py --inspect-k 25 --save-predictions

    # One-shot held-out confirmation at the threshold you picked on DEV
    python evaluation/evaluation.py --confirm --decision threshold --threshold 55
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# PhishLens import — works pip-installed (`pip install -e .`) or from repo root. #
# --------------------------------------------------------------------------- #
try:
    from phishlens import analyze
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    try:
        from phishlens import analyze
    except ImportError as exc:  # pragma: no cover
        sys.exit(
            "Could not import `phishlens`. Run from the repo root, or "
            f"`pip install -e .` first. (import error: {exc})"
        )

# PhishLens verdicts that count as a "phishing" call under its native operating
# point (risk_score >= 45).
PHISHING_VERDICTS = {"likely_phishing", "high_risk"}
VERDICT_ORDER = ["benign", "suspicious", "likely_phishing", "high_risk"]


# --------------------------------------------------------------------------- #
# Load + split                                                                  #
# --------------------------------------------------------------------------- #
def _gold(record: dict[str, Any]) -> int:
    """Coerce the ``type`` field to a binary label (1 = phishing)."""
    raw = str(record.get("type", "")).strip().lower()
    return 1 if raw in {"1", "phishing", "phish", "true"} else 0


def load_records(path: Path, language: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list of objects in {path.name}")
    if language.lower() == "all":
        rows = data
    else:
        rows = [r for r in data if str(r.get("Language", "")).lower() == language.lower()]
    # Drop rows with no usable text.
    return [r for r in rows if str(r.get("Subject", "")).strip() or str(r.get("Body", "")).strip()]


def stratified_split(
    records: list[dict[str, Any]],
    dev_frac: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Class-stratified, seeded split. Stable across runs for a fixed seed."""
    rng = random.Random(seed)
    by_class: dict[int, list[dict[str, Any]]] = {0: [], 1: []}
    for r in records:
        by_class[_gold(r)].append(r)

    dev: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    for _cls, items in sorted(by_class.items()):
        # Sort by a stable key before shuffling so the split is reproducible
        # regardless of input ordering.
        items = sorted(items, key=lambda r: (str(r.get("Subject", "")), str(r.get("Body", ""))[:64]))
        rng.shuffle(items)
        cut = int(round(len(items) * dev_frac))
        dev.extend(items[:cut])
        held.extend(items[cut:])
    rng.shuffle(dev)
    rng.shuffle(held)
    return dev, held


# --------------------------------------------------------------------------- #
# Scoring                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class Scored:
    gold: int
    score: float
    verdict: str
    language: str
    subject: str
    body: str
    reasons: list[str] = field(default_factory=list)


def score_records(records: list[dict[str, Any]], progress_every: int = 1000) -> tuple[list[Scored], int]:
    """Run PhishLens on Subject+Body (body-only; no header context)."""
    scored: list[Scored] = []
    errors = 0
    total = len(records)
    for i, r in enumerate(records, 1):
        subject = str(r.get("Subject", "")).strip()
        body = str(r.get("Body", "")).strip()
        text = f"{subject}\n\n{body}".strip()
        try:
            result = analyze(text)  # deliberately no from_header/headers/etc.
            scored.append(
                Scored(
                    gold=_gold(r),
                    score=float(result.risk_score),
                    verdict=str(getattr(result.verdict, "value", result.verdict)),
                    language=str(r.get("Language", "")),
                    subject=subject,
                    body=body,
                    reasons=list(getattr(result, "reasons", [])),
                    )
            )
        except Exception as exc:  # never let one row abort a 16k run
            errors += 1
            if errors <= 5:
                print(f"  ! analyze() failed on row {i}: {exc}", file=sys.stderr)
        if progress_every and i % progress_every == 0:
            print(f"  scored {i}/{total} ...", file=sys.stderr)
    return scored, errors


def predict(scored: list[Scored], decision: str, threshold: float) -> list[int]:
    if decision == "verdict":
        return [1 if s.verdict in PHISHING_VERDICTS else 0 for s in scored]
    return [1 if s.score >= threshold else 0 for s in scored]


# --------------------------------------------------------------------------- #
# Metrics                                                                       #
# --------------------------------------------------------------------------- #
def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def confusion(gold: list[int], pred: list[int]) -> tuple[int, int, int, int]:
    tp = tn = fp = fn = 0
    for g, p in zip(gold, pred):
        if g == 1 and p == 1:
            tp += 1
        elif g == 0 and p == 0:
            tn += 1
        elif g == 0 and p == 1:
            fp += 1
        else:
            fn += 1
    return tp, tn, fp, fn


def compute_metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float]:
    total = tp + tn + fp + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)  # a.k.a. detection rate / TPR
    return {
        "accuracy": _safe_div(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
        "fpr": _safe_div(fp, fp + tn),  # false-positive rate
        "specificity": _safe_div(tn, tn + fp),
        "balanced_accuracy": (recall + _safe_div(tn, tn + fp)) / 2,
    }


# --------------------------------------------------------------------------- #
# Reporting helpers                                                             #
# --------------------------------------------------------------------------- #
def _percentiles(values: list[float], ps: tuple[int, ...]) -> dict[int, float]:
    if not values:
        return {p: 0.0 for p in ps}
    s = sorted(values)
    out = {}
    for p in ps:
        k = (len(s) - 1) * (p / 100)
        lo, hi = int(k), min(int(k) + 1, len(s) - 1)
        out[p] = s[lo] + (s[hi] - s[lo]) * (k - lo)
    return out


def print_score_distribution(scored: list[Scored]) -> None:
    print("\n--- score distribution by class (risk_score 0-100) ---")
    for cls, label in ((1, "phishing (type=1)"), (0, "legit    (type=0)")):
        vals = [s.score for s in scored if s.gold == cls]
        if not vals:
            print(f"  {label}: (none)")
            continue
        pct = _percentiles(vals, (10, 25, 50, 75, 90))
        print(f"\n  {label}  n={len(vals)}  mean={statistics.mean(vals):.1f}")
        print(f"    p10={pct[10]:.0f}  p25={pct[25]:.0f}  median={pct[50]:.0f}  "
              f"p75={pct[75]:.0f}  p90={pct[90]:.0f}")
        # 10-wide text histogram
        bins = [0] * 10
        for v in vals:
            bins[min(int(v // 10), 9)] += 1
        peak = max(bins) or 1
        for b in range(10):
            bar = "#" * int(40 * bins[b] / peak)
            print(f"    {b*10:>3}-{b*10+9:<3} {bins[b]:>6} |{bar}")


def print_verdict_distribution(scored: list[Scored]) -> None:
    print("\n--- verdict distribution (PhishLens native bands) ---")
    print(f"  {'verdict':<16} {'phishing':>9} {'legit':>9} {'total':>9}")
    for v in VERDICT_ORDER:
        ph = sum(1 for s in scored if s.verdict == v and s.gold == 1)
        lg = sum(1 for s in scored if s.verdict == v and s.gold == 0)
        print(f"  {v:<16} {ph:>9} {lg:>9} {ph + lg:>9}")


def print_confusion_and_metrics(gold: list[int], pred: list[int], operating_point: str) -> dict[str, Any]:
    tp, tn, fp, fn = confusion(gold, pred)
    m = compute_metrics(tp, tn, fp, fn)
    print(f"\n--- confusion matrix @ {operating_point} ---")
    print("                       Predicted")
    print("                  Phishing    Benign")
    print(f"  Actual Phishing   {tp:>6}    {fn:>6}     (TP / FN)")
    print(f"         Benign     {fp:>6}    {tn:>6}     (FP / TN)")
    print("\n--- metrics ---")
    print(f"    accuracy          : {m['accuracy']:.4f}")
    print(f"    precision         : {m['precision']:.4f}")
    print(f"    recall (TPR)      : {m['recall']:.4f}")
    print(f"    f1                : {m['f1']:.4f}")
    print(f"    false-positive rate: {m['fpr']:.4f}")
    print(f"    specificity       : {m['specificity']:.4f}")
    print(f"    balanced accuracy : {m['balanced_accuracy']:.4f}")
    return {"confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn}, "metrics": m}


def sweep_thresholds(
    scored: list[Scored],
    out_dir: Path,
    step: float = 1.0,
    max_fpr: float = 0.05,
) -> tuple[float, float]:
    """Evaluate thresholds and recommend an operating point.
    Returns:
        best_f1_threshold
        recommended_threshold
    The recommended threshold maximizes recall while keeping
    false-positive rate <= max_fpr.
    """
    gold = [s.gold for s in scored]
    rows: list[dict[str, Any]] = []
    t = 0.0
    while t <= 100.0 + 1e-9:
        pred = [
            1 if s.score >= t else 0
            for s in scored
        ]
        tp, tn, fp, fn = confusion(gold, pred)
        metrics = compute_metrics(tp, tn, fp, fn)
        rows.append(
            {
                "threshold": t,
                "tp": tp,
                "fn": fn,
                "fp": fp,
                "tn": tn,
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "fpr": metrics["fpr"],
            }
        )
        t = round(t + step, 10)
    # Best threshold by F1.
    best_f1 = max(
        rows,
        key=lambda row: row["f1"],
    )
    # Thresholds satisfying the FPR constraint.
    eligible = [
        row
        for row in rows
        if row["fpr"] <= max_fpr
    ]
    if eligible:
        recommended = max(
            eligible,
            key=lambda row: (
                row["recall"],
                row["f1"],
                row["precision"],
            ),
        )
    else:
        recommended = best_f1
    print(
        "\n--- threshold sweep on DEV ---"
    )
    print(
        "    thr     TP    FN    FP    TN"
        "   prec    rec    f1     fpr"
    )
    for row in rows:
        marks = []
        if row["threshold"] == best_f1["threshold"]:
            marks.append("best F1")
        if row["threshold"] == recommended["threshold"]:
            marks.append(
                f"recommended @ FPR <= {max_fpr:.0%}"
            )
        marker = (
            "  <-- " + ", ".join(marks)
            if marks
            else ""
        )
        print(
            f"    {row['threshold']:>3.0f}"
            f"  {row['tp']:>6}"
            f"{row['fn']:>6}"
            f"{row['fp']:>6}"
            f"{row['tn']:>6}"
            f"  {row['precision']:.3f}"
            f"  {row['recall']:.3f}"
            f"  {row['f1']:.3f}"
            f"  {row['fpr']:.3f}"
            f"{marker}"
        )
    # Save the full sweep to CSV.
    sweep_path = out_dir / "threshold_sweep.csv"
    with sweep_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)
    print(
        f"\nBest F1 threshold:"
        f" {best_f1['threshold']:g}"
    )
    print(
        f"Recommended threshold:"
        f" {recommended['threshold']:g}"
        f" (highest recall with"
        f" FPR <= {max_fpr:.0%})"
    )
    print(
        f"Threshold sweep written to:"
        f" {sweep_path}"
    )
    return (
        float(best_f1["threshold"]),
        float(recommended["threshold"]),
    )


def inspect_errors(scored: list[Scored], pred: list[int], k: int, out_dir: Path) -> None:
    """Show and save the worst false positives and false negatives."""
    fps = [(s, s.score) for s, p in zip(scored, pred) if s.gold == 0 and p == 1]
    fns = [(s, s.score) for s, p in zip(scored, pred) if s.gold == 1 and p == 0]
    fps.sort(key=lambda x: x[1], reverse=True)   # most confidently-wrong legit first
    fns.sort(key=lambda x: x[1])                 # phishing PhishLens scored lowest first

    def _show(title: str, items: list[tuple[Scored, float]]) -> None:
        print(f"\n--- {title} (showing up to {k} of {len(items)}) ---")
        for s, sc in items[:k]:
            top = s.reasons[0] if s.reasons else "(no reasons emitted)"
            print(
                f"  score={sc:>5.1f}"
                f"[{s.verdict:<14}]"
                f"{s.subject[:90]!r}"
                )
            print(f"      why: {top}")

    _show("FALSE POSITIVES  (legit flagged as phishing)", fps)
    _show("FALSE NEGATIVES  (phishing missed)", fns)

    # Full dumps for offline error analysis.
    for name, items in (("false_positives", fps), ("false_negatives", fns)):
        path = out_dir / f"{name}.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(
                [
                    "risk_score",
                    "verdict",
                    "language",
                    "subject",
                    "body",
                    "reasons",
                ]
                )
            for s, sc in items:
                w.writerow(
                    [
                        f"{sc:.1f}",
                        s.verdict,
                        s.language,
                        s.subject,
                        s.body,
                        " || ".join(s.reasons),
                    ]
                    )
        print(f"  wrote {len(items):>5} rows -> {path}")


# --------------------------------------------------------------------------- #
# Optional plots                                                                #
# --------------------------------------------------------------------------- #
def save_plots(scored: list[Scored], cm: dict[str, int], out_dir: Path, tag: str) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return

    # Score distribution (overlaid histograms).
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist([s.score for s in scored if s.gold == 1], bins=20, range=(0, 100),
            alpha=0.6, label="phishing (type=1)")
    ax.hist([s.score for s in scored if s.gold == 0], bins=20, range=(0, 100),
            alpha=0.6, label="legit (type=0)")
    ax.set_xlabel("PhishLens risk_score")
    ax.set_ylabel("emails")
    ax.set_title(f"Score distribution ({tag})")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / f"{tag}_score_distribution.png", dpi=150)
    plt.close(fig)

    # Confusion matrix.
    mat = [[cm["tp"], cm["fn"]], [cm["fp"], cm["tn"]]]
    fig, ax = plt.subplots(figsize=(4.2, 4.2))
    ax.imshow(mat, cmap="Blues")
    ax.set_xticks([0, 1], ["Phishing", "Benign"])
    ax.set_yticks([0, 1], ["Phishing", "Benign"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion matrix ({tag})")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(mat[i][j]), ha="center", va="center", fontsize=14)
    fig.tight_layout()
    fig.savefig(out_dir / f"{tag}_confusion.png", dpi=150)
    plt.close(fig)


def save_predictions(scored: list[Scored], pred: list[int], out_dir: Path, tag: str) -> None:
    path = out_dir / f"{tag}_predictions.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["gold", "predicted", "risk_score", "verdict", "language", "subject"])
        for s, p in zip(scored, pred):
            w.writerow([s.gold, p, f"{s.score:.1f}", s.verdict, s.language, s.subject])
    print(f"  wrote predictions -> {path}")


# --------------------------------------------------------------------------- #
# Phases                                                                        #
# --------------------------------------------------------------------------- #
def run_dev(dev: list[dict[str, Any]], held_n: int, args: argparse.Namespace, out_dir: Path) -> None:
    print(f"\n{'=' * 70}\n  DEV BENCHMARK  ({len(dev)} emails, language={args.language})\n{'=' * 70}")
    scored, errors = score_records(dev)
    if errors:
        print(f"  ({errors} rows skipped due to analyze() errors)")
    if not scored:
        print("  no scored emails; check the dataset path/schema.")
        return

    # Step 2: score distribution.
    print_score_distribution(scored)
    # Step 3: current verdicts.
    print_verdict_distribution(scored)

    # Current operating point.
    op = ("native verdicts (score>=45)"
          if args.decision == "verdict"
          else f"risk_score >= {args.threshold:g}")
    current_pred = predict(scored, args.decision, args.threshold,)
    current_summary = print_confusion_and_metrics([s.gold for s in scored], current_pred, op,)
    
    # Fine-grained threshold analysis.
    best_f1_t, recommended_t = sweep_thresholds(scored, out_dir=out_dir,step=args.sweep_step,max_fpr=args.max_fpr,)
    
    # Evaluate the recommended DEV-selected threshold.
    recommended_pred = predict(scored, "threshold", recommended_t,)
    
    recommended_summary = print_confusion_and_metrics([s.gold for s in scored], recommended_pred,(f"recommended DEV threshold " f"{recommended_t:g} " f"(FPR <= {args.max_fpr:.0%})"),)
    
    # Error analysis at the useful candidate threshold,
    # # not at the unusable native threshold.
    inspect_errors(scored,recommended_pred,args.inspect_k,out_dir,)
    
    if args.save_predictions: save_predictions(scored, recommended_pred, out_dir, "dev",)
    
    save_plots(scored,recommended_summary["confusion"],out_dir,"dev",)
    
    summary = {
        "current_operating_point": current_summary, 
        "best_f1_threshold": best_f1_t,
        "recommended_threshold": recommended_t,
        "max_fpr_constraint": args.max_fpr,
        "recommended_operating_point": recommended_summary,
        }
    
    summary_path = out_dir / "dev_summary.json"
    
    summary_path.write_text(json.dumps(summary, indent=2),encoding="utf-8",)
    
    print(f"\n  wrote dev summary -> {summary_path}")
    print(f"  HELD-OUT set ({held_n} emails) left UNTOUCHED.")
    print(f"  When you're done iterating, confirm once with:")
    print(f"    python evaluation/evaluation.py " f"--confirm " f"--decision threshold " f"--threshold {recommended_t:g}")
    print(f"{'-' * 70}")


def run_confirm(held: list[dict[str, Any]], args: argparse.Namespace, out_dir: Path) -> None:
    print(f"\n{'=' * 70}")
    print(f"  HELD-OUT CONFIRMATION  ({len(held)} emails, language={args.language})")
    print(f"  Operating point: "
          f"{'native verdicts (score>=45)' if args.decision == 'verdict' else f'risk_score >= {args.threshold:g}'}")
    print(f"  >>> This is your single held-out evaluation. Report these numbers. <<<")
    print(f"{'=' * 70}")
    scored, errors = score_records(held)
    if errors:
        print(f"  ({errors} rows skipped due to analyze() errors)")
    if not scored:
        print("  no scored emails; check the dataset path/schema.")
        return

    pred = predict(scored, args.decision, args.threshold)
    op = "native verdicts (score>=45)" if args.decision == "verdict" else f"risk_score >= {args.threshold:g}"
    summary = print_confusion_and_metrics([s.gold for s in scored], pred, op)

    if args.save_predictions:
        save_predictions(scored, pred, out_dir, "holdout")
    save_plots(scored, summary["confusion"], out_dir, "holdout")
    (out_dir / "holdout_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n  wrote held-out summary -> {out_dir / 'holdout_summary.json'}")


# --------------------------------------------------------------------------- #
# Main                                                                          #
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-file", default="datasets/ephishLLM.json", help="path to ephishLLM.json")
    p.add_argument("--language", default="en", help="language code to evaluate, or 'all' (default: en)")
    p.add_argument("--dev-frac", type=float, default=0.7, help="fraction of the slice used for DEV (default 0.7)")
    p.add_argument("--seed", type=int, default=42, help="split seed — keep fixed so held-out stays held-out")
    p.add_argument("--decision", choices=["verdict", "threshold"], default="verdict",
                   help="'verdict' = PhishLens's native bands (>=45); 'threshold' = risk_score cutoff")
    p.add_argument("--threshold", type=float, default=45.0, help="risk_score cutoff when --decision threshold")
    p.add_argument("--confirm", action="store_true", help="evaluate the HELD-OUT split ONCE (final report)")
    p.add_argument("--inspect-k", type=int, default=10, help="how many FPs/FNs to print (default 10)")
    p.add_argument("--out-dir", default="evaluation/results", help="where to write artifacts")
    p.add_argument("--save-predictions", action="store_true", help="write a per-email predictions CSV")
    p.add_argument("--sweep-step", type=float, default=1.0, help="threshold sweep interval (default: 1.0)",)
    p.add_argument("--max-fpr", type=float, default=0.05, help=("maximum DEV false-positive rate used when " "recommending a threshold (default: 0.05)"),)
    args = p.parse_args(argv)

    path = Path(args.data_file)
    if not path.exists():
        sys.exit(f"Dataset not found: {path}. Place ephishLLM.json under datasets/ or pass --data-file.")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records = load_records(path, args.language)
    if not records:
        sys.exit(f"No records for language={args.language!r}. Try --language all.")

    dev, held = stratified_split(records, args.dev_frac, args.seed)
    n_ph = sum(_gold(r) for r in records)
    print(f"Loaded {len(records)} '{args.language}' emails "
          f"(phishing={n_ph}, legit={len(records) - n_ph}) -> "
          f"DEV={len(dev)}, HELD-OUT={len(held)}  (seed={args.seed})")

    if args.confirm:
        run_confirm(held, args, out_dir)
    else:
        run_dev(dev, len(held), args, out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())