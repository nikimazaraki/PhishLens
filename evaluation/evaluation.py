#!/usr/bin/env python3
"""Benchmark PhishLens on the E-PhishLLM dataset.

The E-PhishLLM dataset contains 16,616 emails across multiple languages.
Each record contains Subject, Body, type (0 = legitimate, 1 = phishing),
and Language.

This evaluation uses only Subject + Body because sender, authentication,
recipient-context, and attachment metadata are not available in the dataset.

Methodology
-----------
1. Restrict evaluation to one language, English by default.
2. Create a stable, stratified DEV / HELD-OUT split.
3. Use DEV for score analysis, threshold selection, and error inspection.
4. Select an operating threshold on DEV only.
5. Evaluate HELD-OUT once after the threshold has been fixed.

Examples
--------
Run the DEV benchmark:

    python evaluation/evaluation.py

Inspect more errors and save predictions:

    python evaluation/evaluation.py --inspect-k 25 --save-predictions

Run the final held-out evaluation:

    python evaluation/evaluation.py \
        --confirm \
        --decision threshold \
        --threshold 14
"""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# PhishLens import
# ---------------------------------------------------------------------------

try:
    from phishlens import analyze
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    try:
        from phishlens import analyze
    except ImportError as exc:  # pragma: no cover
        sys.exit(
            "Could not import `phishlens`. Run from the repo root, or "
            f"run `pip install -e .` first. Import error: {exc}"
        )


PHISHING_VERDICTS = {"likely_phishing", "high_risk"}
VERDICT_ORDER = ["benign", "suspicious", "likely_phishing", "high_risk"]


# ---------------------------------------------------------------------------
# Load and split
# ---------------------------------------------------------------------------


def _gold(record: dict[str, Any]) -> int:
    """Convert the dataset label to 0 = legitimate, 1 = phishing."""
    raw = str(record.get("type", "")).strip().lower()
    return 1 if raw in {"1", "phishing", "phish", "true"} else 0


def load_records(path: Path, language: str) -> list[dict[str, Any]]:
    """Load records and optionally filter by language."""
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list of objects in {path.name}")

    if language.lower() == "all":
        rows = data
    else:
        rows = [
            record
            for record in data
            if str(record.get("Language", "")).lower() == language.lower()
        ]

    return [
        record
        for record in rows
        if str(record.get("Subject", "")).strip() or str(record.get("Body", "")).strip()
    ]


def stratified_split(
    records: list[dict[str, Any]],
    dev_frac: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create a stable class-stratified DEV / HELD-OUT split."""
    rng = random.Random(seed)
    by_class: dict[int, list[dict[str, Any]]] = {0: [], 1: []}

    for record in records:
        by_class[_gold(record)].append(record)

    dev: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []

    for _, items in sorted(by_class.items()):
        items = sorted(
            items,
            key=lambda r: (
                str(r.get("Subject", "")),
                str(r.get("Body", ""))[:64],
            ),
        )

        rng.shuffle(items)
        cut = int(round(len(items) * dev_frac))

        dev.extend(items[:cut])
        held.extend(items[cut:])

    rng.shuffle(dev)
    rng.shuffle(held)

    return dev, held


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


@dataclass
class Scored:
    gold: int
    score: float
    verdict: str
    language: str
    subject: str
    body: str
    reasons: list[str] = field(default_factory=list)


def score_records(
    records: list[dict[str, Any]],
    progress_every: int = 1000,
) -> tuple[list[Scored], int]:
    """Run PhishLens on Subject + Body only."""
    scored: list[Scored] = []
    errors = 0
    total = len(records)

    for index, record in enumerate(records, start=1):
        subject = str(record.get("Subject", "")).strip()
        body = str(record.get("Body", "")).strip()
        text = f"{subject}\n\n{body}".strip()

        try:
            result = analyze(text)

            scored.append(
                Scored(
                    gold=_gold(record),
                    score=float(result.risk_score),
                    verdict=str(getattr(result.verdict, "value", result.verdict)),
                    language=str(record.get("Language", "")),
                    subject=subject,
                    body=body,
                    reasons=list(getattr(result, "reasons", [])),
                )
            )

        except Exception as exc:
            errors += 1

            if errors <= 5:
                print(
                    f"  ! analyze() failed on row {index}: {exc}",
                    file=sys.stderr,
                )

        if progress_every and index % progress_every == 0:
            print(f"  scored {index}/{total} ...", file=sys.stderr)

    return scored, errors


def predict(
    scored: list[Scored],
    decision: str,
    threshold: float,
) -> list[int]:
    """Convert PhishLens output into binary predictions."""
    if decision == "verdict":
        return [1 if item.verdict in PHISHING_VERDICTS else 0 for item in scored]

    return [1 if item.score >= threshold else 0 for item in scored]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def confusion(
    gold: list[int],
    pred: list[int],
) -> tuple[int, int, int, int]:
    """Return TP, TN, FP, FN."""
    tp = tn = fp = fn = 0

    for actual, predicted in zip(gold, pred):
        if actual == 1 and predicted == 1:
            tp += 1
        elif actual == 0 and predicted == 0:
            tn += 1
        elif actual == 0 and predicted == 1:
            fp += 1
        else:
            fn += 1

    return tp, tn, fp, fn


def compute_metrics(
    tp: int,
    tn: int,
    fp: int,
    fn: int,
) -> dict[str, float]:
    """Compute classification metrics."""
    total = tp + tn + fp + fn

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)

    return {
        "accuracy": _safe_div(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
        "fpr": _safe_div(fp, fp + tn),
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
    }


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


def _percentiles(
    values: list[float],
    ps: tuple[int, ...],
) -> dict[int, float]:
    if not values:
        return {p: 0.0 for p in ps}

    sorted_values = sorted(values)
    output: dict[int, float] = {}

    for p in ps:
        k = (len(sorted_values) - 1) * (p / 100)
        lo = int(k)
        hi = min(lo + 1, len(sorted_values) - 1)

        output[p] = sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (
            k - lo
        )

    return output


def print_score_distribution(scored: list[Scored]) -> None:
    print("\n--- score distribution by class (risk_score 0-100) ---")

    for cls, label in (
        (1, "phishing (type=1)"),
        (0, "legit    (type=0)"),
    ):
        values = [item.score for item in scored if item.gold == cls]

        if not values:
            print(f"  {label}: (none)")
            continue

        pct = _percentiles(values, (10, 25, 50, 75, 90))

        print(f"\n  {label}  n={len(values)}  mean={statistics.mean(values):.1f}")

        print(
            f"    p10={pct[10]:.0f}  "
            f"p25={pct[25]:.0f}  "
            f"median={pct[50]:.0f}  "
            f"p75={pct[75]:.0f}  "
            f"p90={pct[90]:.0f}"
        )

        bins = [0] * 10

        for value in values:
            bins[min(int(value // 10), 9)] += 1

        peak = max(bins) or 1

        for bucket in range(10):
            bar = "#" * int(40 * bins[bucket] / peak)

            print(f"    {bucket * 10:>3}-{bucket * 10 + 9:<3} {bins[bucket]:>6} |{bar}")


def print_verdict_distribution(scored: list[Scored]) -> None:
    print("\n--- verdict distribution (PhishLens native bands) ---")
    print(f"  {'verdict':<16} {'phishing':>9} {'legit':>9} {'total':>9}")

    for verdict in VERDICT_ORDER:
        phishing = sum(
            1 for item in scored if item.verdict == verdict and item.gold == 1
        )

        legit = sum(1 for item in scored if item.verdict == verdict and item.gold == 0)

        print(f"  {verdict:<16} {phishing:>9} {legit:>9} {phishing + legit:>9}")


def print_confusion_and_metrics(
    gold: list[int],
    pred: list[int],
    operating_point: str,
) -> dict[str, Any]:
    tp, tn, fp, fn = confusion(gold, pred)
    metrics = compute_metrics(tp, tn, fp, fn)

    print(f"\n--- confusion matrix @ {operating_point} ---")
    print("                       Predicted")
    print("                  Phishing    Benign")
    print(f"  Actual Phishing   {tp:>6}    {fn:>6}     (TP / FN)")
    print(f"         Benign     {fp:>6}    {tn:>6}     (FP / TN)")

    print("\n--- metrics ---")
    print(f"    accuracy           : {metrics['accuracy']:.4f}")
    print(f"    precision          : {metrics['precision']:.4f}")
    print(f"    recall (TPR)       : {metrics['recall']:.4f}")
    print(f"    f1                 : {metrics['f1']:.4f}")
    print(f"    false-positive rate: {metrics['fpr']:.4f}")
    print(f"    specificity        : {metrics['specificity']:.4f}")
    print(f"    balanced accuracy  : {metrics['balanced_accuracy']:.4f}")

    return {
        "confusion": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "metrics": metrics,
    }


def sweep_thresholds(
    scored: list[Scored],
    out_dir: Path,
    step: float = 1.0,
    max_fpr: float = 0.05,
) -> tuple[float, float]:
    """Evaluate thresholds and recommend an operating point."""
    gold = [item.gold for item in scored]
    rows: list[dict[str, Any]] = []

    threshold = 0.0

    while threshold <= 100.0 + 1e-9:
        pred = [1 if item.score >= threshold else 0 for item in scored]

        tp, tn, fp, fn = confusion(gold, pred)
        metrics = compute_metrics(tp, tn, fp, fn)

        rows.append(
            {
                "threshold": threshold,
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

        threshold = round(threshold + step, 10)

    best_f1 = max(rows, key=lambda row: row["f1"])

    eligible = [row for row in rows if row["fpr"] <= max_fpr]

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

    print("\n--- threshold sweep on DEV ---")
    print("    thr     TP    FN    FP    TN   prec    rec    f1     fpr")

    for row in rows:
        marks: list[str] = []

        if row["threshold"] == best_f1["threshold"]:
            marks.append("best F1")

        if row["threshold"] == recommended["threshold"]:
            marks.append(f"recommended @ FPR <= {max_fpr:.0%}")

        marker = "  <-- " + ", ".join(marks) if marks else ""

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

    sweep_path = out_dir / "threshold_sweep.csv"

    with sweep_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nBest F1 threshold: {best_f1['threshold']:g}")
    print(
        f"Recommended threshold: {recommended['threshold']:g} "
        f"(highest recall with FPR <= {max_fpr:.0%})"
    )
    print(f"Threshold sweep written to: {sweep_path}")

    return (
        float(best_f1["threshold"]),
        float(recommended["threshold"]),
    )


def inspect_errors(
    scored: list[Scored],
    pred: list[int],
    k: int,
    out_dir: Path,
) -> None:
    """Show and save false positives and false negatives."""
    fps = [
        (item, item.score)
        for item, prediction in zip(scored, pred)
        if item.gold == 0 and prediction == 1
    ]

    fns = [
        (item, item.score)
        for item, prediction in zip(scored, pred)
        if item.gold == 1 and prediction == 0
    ]

    fps.sort(key=lambda pair: pair[1], reverse=True)
    fns.sort(key=lambda pair: pair[1])

    def _show(
        title: str,
        items: list[tuple[Scored, float]],
    ) -> None:
        print(f"\n--- {title} (showing up to {k} of {len(items)}) ---")

        for item, score in items[:k]:
            top_reason = item.reasons[0] if item.reasons else "(no reasons emitted)"

            print(f"  score={score:>5.1f} [{item.verdict:<14}] {item.subject[:90]!r}")
            print(f"      why: {top_reason}")

    _show("FALSE POSITIVES  (legit flagged as phishing)", fps)
    _show("FALSE NEGATIVES  (phishing missed)", fns)

    for name, items in (
        ("false_positives", fps),
        ("false_negatives", fns),
    ):
        path = out_dir / f"{name}.csv"

        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)

            writer.writerow(
                [
                    "risk_score",
                    "verdict",
                    "language",
                    "subject",
                    "body",
                    "reasons",
                ]
            )

            for item, score in items:
                writer.writerow(
                    [
                        f"{score:.1f}",
                        item.verdict,
                        item.language,
                        item.subject,
                        item.body,
                        " || ".join(item.reasons),
                    ]
                )

        print(f"  wrote {len(items):>5} rows -> {path}")


# ---------------------------------------------------------------------------
# Optional plots
# ---------------------------------------------------------------------------


def save_plots(
    scored: list[Scored],
    cm: dict[str, int],
    out_dir: Path,
    tag: str,
) -> None:
    """Save plots if Matplotlib is available."""
    try:
        matplotlib = importlib.import_module("matplotlib")
        matplotlib.use("Agg")
        plt = importlib.import_module("matplotlib.pyplot")
    except ModuleNotFoundError:
        return

    fig, ax = plt.subplots(figsize=(6, 4))

    ax.hist(
        [item.score for item in scored if item.gold == 1],
        bins=20,
        range=(0, 100),
        alpha=0.6,
        label="phishing (type=1)",
    )

    ax.hist(
        [item.score for item in scored if item.gold == 0],
        bins=20,
        range=(0, 100),
        alpha=0.6,
        label="legit (type=0)",
    )

    ax.set_xlabel("PhishLens risk_score")
    ax.set_ylabel("emails")
    ax.set_title(f"Score distribution ({tag})")
    ax.legend()

    fig.tight_layout()
    fig.savefig(
        out_dir / f"{tag}_score_distribution.png",
        dpi=150,
    )
    plt.close(fig)

    matrix = [
        [cm["tp"], cm["fn"]],
        [cm["fp"], cm["tn"]],
    ]

    fig, ax = plt.subplots(figsize=(4.2, 4.2))
    ax.imshow(matrix, cmap="Blues")

    ax.set_xticks([0, 1], ["Phishing", "Benign"])
    ax.set_yticks([0, 1], ["Phishing", "Benign"])

    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion matrix ({tag})")

    for row in range(2):
        for column in range(2):
            ax.text(
                column,
                row,
                str(matrix[row][column]),
                ha="center",
                va="center",
                fontsize=14,
            )

    fig.tight_layout()
    fig.savefig(
        out_dir / f"{tag}_confusion.png",
        dpi=150,
    )
    plt.close(fig)


def save_predictions(
    scored: list[Scored],
    pred: list[int],
    out_dir: Path,
    tag: str,
) -> None:
    path = out_dir / f"{tag}_predictions.csv"

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "gold",
                "predicted",
                "risk_score",
                "verdict",
                "language",
                "subject",
            ]
        )

        for item, prediction in zip(scored, pred):
            writer.writerow(
                [
                    item.gold,
                    prediction,
                    f"{item.score:.1f}",
                    item.verdict,
                    item.language,
                    item.subject,
                ]
            )

    print(f"  wrote predictions -> {path}")


# ---------------------------------------------------------------------------
# Evaluation phases
# ---------------------------------------------------------------------------


def run_dev(
    dev: list[dict[str, Any]],
    held_n: int,
    args: argparse.Namespace,
    out_dir: Path,
) -> None:
    print(
        f"\n{'=' * 70}\n"
        f"  DEV BENCHMARK  ({len(dev)} emails, language={args.language})\n"
        f"{'=' * 70}"
    )

    scored, errors = score_records(dev)

    if errors:
        print(f"  ({errors} rows skipped due to analyze() errors)")

    if not scored:
        print("  no scored emails; check the dataset path/schema.")
        return

    print_score_distribution(scored)
    print_verdict_distribution(scored)

    operating_point = (
        "native verdicts (score>=45)"
        if args.decision == "verdict"
        else f"risk_score >= {args.threshold:g}"
    )

    current_pred = predict(scored, args.decision, args.threshold)

    current_summary = print_confusion_and_metrics(
        [item.gold for item in scored],
        current_pred,
        operating_point,
    )

    best_f1_threshold, recommended_threshold = sweep_thresholds(
        scored,
        out_dir=out_dir,
        step=args.sweep_step,
        max_fpr=args.max_fpr,
    )

    recommended_pred = predict(
        scored,
        "threshold",
        recommended_threshold,
    )

    recommended_summary = print_confusion_and_metrics(
        [item.gold for item in scored],
        recommended_pred,
        (
            f"recommended DEV threshold {recommended_threshold:g} "
            f"(FPR <= {args.max_fpr:.0%})"
        ),
    )

    inspect_errors(
        scored,
        recommended_pred,
        args.inspect_k,
        out_dir,
    )

    if args.save_predictions:
        save_predictions(
            scored,
            recommended_pred,
            out_dir,
            "dev",
        )

    save_plots(
        scored,
        recommended_summary["confusion"],
        out_dir,
        "dev",
    )

    summary = {
        "current_operating_point": current_summary,
        "best_f1_threshold": best_f1_threshold,
        "recommended_threshold": recommended_threshold,
        "max_fpr_constraint": args.max_fpr,
        "recommended_operating_point": recommended_summary,
    }

    summary_path = out_dir / "dev_summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(f"\n  wrote dev summary -> {summary_path}")
    print(f"  HELD-OUT set ({held_n} emails) left UNTOUCHED.")
    print("  When you're done iterating, confirm once with:")
    print(
        "    python evaluation/evaluation.py "
        "--confirm "
        "--decision threshold "
        f"--threshold {recommended_threshold:g}"
    )
    print(f"{'-' * 70}")


def run_confirm(
    held: list[dict[str, Any]],
    args: argparse.Namespace,
    out_dir: Path,
) -> None:
    operating_point = (
        "native verdicts (score>=45)"
        if args.decision == "verdict"
        else f"risk_score >= {args.threshold:g}"
    )

    print(f"\n{'=' * 70}")
    print(f"  HELD-OUT CONFIRMATION  ({len(held)} emails, language={args.language})")
    print(f"  Operating point: {operating_point}")
    print("  >>> This is your single held-out evaluation. Report these numbers. <<<")
    print(f"{'=' * 70}")

    scored, errors = score_records(held)

    if errors:
        print(f"  ({errors} rows skipped due to analyze() errors)")

    if not scored:
        print("  no scored emails; check the dataset path/schema.")
        return

    pred = predict(scored, args.decision, args.threshold)

    summary = print_confusion_and_metrics(
        [item.gold for item in scored],
        pred,
        operating_point,
    )

    if args.save_predictions:
        save_predictions(scored, pred, out_dir, "holdout")

    save_plots(
        scored,
        summary["confusion"],
        out_dir,
        "holdout",
    )

    summary_path = out_dir / "holdout_summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(f"\n  wrote held-out summary -> {summary_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--data-file",
        default="datasets/ephishLLM.json",
        help="path to ephishLLM.json",
    )

    parser.add_argument(
        "--language",
        default="en",
        help="language code to evaluate, or 'all' (default: en)",
    )

    parser.add_argument(
        "--dev-frac",
        type=float,
        default=0.7,
        help="fraction of the slice used for DEV (default: 0.7)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="split seed; keep fixed so held-out stays held-out",
    )

    parser.add_argument(
        "--decision",
        choices=["verdict", "threshold"],
        default="verdict",
        help=(
            "'verdict' = PhishLens native verdict bands; "
            "'threshold' = risk_score cutoff"
        ),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=45.0,
        help="risk_score cutoff when --decision threshold",
    )

    parser.add_argument(
        "--confirm",
        action="store_true",
        help="evaluate the HELD-OUT split once",
    )

    parser.add_argument(
        "--inspect-k",
        type=int,
        default=10,
        help="how many false positives and false negatives to print",
    )

    parser.add_argument(
        "--out-dir",
        default="evaluation/results",
        help="directory where evaluation artifacts are written",
    )

    parser.add_argument(
        "--save-predictions",
        action="store_true",
        help="write a per-email predictions CSV",
    )

    parser.add_argument(
        "--sweep-step",
        type=float,
        default=1.0,
        help="threshold sweep interval (default: 1.0)",
    )

    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.05,
        help=(
            "maximum DEV false-positive rate used when recommending "
            "a threshold (default: 0.05)"
        ),
    )

    args = parser.parse_args(argv)

    path = Path(args.data_file)

    if not path.exists():
        sys.exit(
            f"Dataset not found: {path}. "
            "Place ephishLLM.json under datasets/ or pass --data-file."
        )

    if not 0 < args.dev_frac < 1:
        sys.exit("--dev-frac must be between 0 and 1.")

    if args.sweep_step <= 0:
        sys.exit("--sweep-step must be greater than 0.")

    if not 0 <= args.max_fpr <= 1:
        sys.exit("--max-fpr must be between 0 and 1.")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records = load_records(path, args.language)

    if not records:
        sys.exit(f"No records for language={args.language!r}. Try --language all.")

    dev, held = stratified_split(
        records,
        args.dev_frac,
        args.seed,
    )

    phishing_count = sum(_gold(record) for record in records)
    legit_count = len(records) - phishing_count

    print(
        f"Loaded {len(records)} '{args.language}' emails "
        f"(phishing={phishing_count}, legit={legit_count}) -> "
        f"DEV={len(dev)}, HELD-OUT={len(held)} "
        f"(seed={args.seed})"
    )

    if args.confirm:
        run_confirm(held, args, out_dir)
    else:
        run_dev(dev, len(held), args, out_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
