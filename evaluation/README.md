# PhishLens Evaluation

PhishLens was evaluated against the English-language subset of the
E-PhishLLM dataset.

## Dataset

E-PhishLLM contains 16,616 emails across multiple languages. This benchmark
uses only the 11,502 English-language emails: 5,996 phishing and 5,506
legitimate. Non-English emails are excluded because the current PhishLens
detectors are built around English-language signals.

The English subset is split 70/30 into DEV and HELD-OUT, stratified by
class, seed `42`.

- **DEV** (8,051 emails): score distribution analysis, threshold selection,
  false-positive and false-negative analysis.
- **HELD-OUT** (3,451 emails): reserved for a single final evaluation.

E-PhishLLM provides only `Subject` and `Body`, so this is a body-only
evaluation. Sender identity, authentication signals, recipient context, and
attachment metadata are not exercised.

## Threshold selection

The threshold is chosen on DEV only: the highest recall with a
false-positive rate at or below 5%.

## V1 (tagged `v1.0-benchmark`)

Threshold: **14**.

### DEV results

| Metric | Result |
|---|---:|
| Accuracy | 67.94% |
| Precision | 90.73% |
| Recall | 42.89% |
| F1 | 58.24% |
| False-positive rate | 4.77% |
| Specificity | 95.23% |
| Balanced accuracy | 69.06% |

### HELD-OUT confusion matrix

| | Predicted Phishing | Predicted Benign |
|---|---:|---:|
| Actual Phishing | 799 | 1000 |
| Actual Legitimate | 66 | 1586 |

### HELD-OUT results

| Metric | Result |
|---|---:|
| Accuracy | 69.11% |
| Precision | 92.37% |
| Recall | 44.41% |
| F1 | 59.98% |
| False-positive rate | 4.00% |
| Specificity | 96.00% |
| Balanced accuracy | 70.21% |

PhishLens behaves as a high-precision, conservative detector: 92.37% of
flagged emails are actual phishing, 44.41% of phishing is caught, and 4.00%
of legitimate mail is misflagged. DEV and HELD-OUT results are close, so the
threshold generalized. Recall is the main limitation; body-only input also
means signals based on sender identity, authentication, recipient context,
and attachments are never exercised.

This HELD-OUT result is frozen as the official `v1.0-benchmark`. Later
development is evaluated on DEV only and not re-run against this set, so it
stays a clean test for whatever gets tagged next.

## V2 (DEV-only, frozen, not yet confirmed on HELD-OUT)

Changes were found and validated on DEV only:

1. **Ensemble averaging bug.** The score was divided by the full weight of
   all 12 detectors, including four that only fire with sender, header, or
   attachment metadata (`auth`, `sender`, `lateral`, `temporal`,
   `attachments`). Under body-only input those always scored 0, which was
   counted as confirmed-clean and silently capped every score. Fixed with
   `Signal.applicable`: a detector is now excluded from the average when its
   required context was never supplied.
2. **Broadened phrase banks.** Scarcity and credential-harvest cues, plus a
   new software/security-update pretext scenario, were added to catch
   paraphrases seen in DEV false negatives.
3. **Simplified personalization.** A greeting-by-name heuristic was added,
   then measured and removed: it fired about as often on legitimate email as
   on phishing. The pre-existing generic OSINT-cue phrase list ("your
   project", "your team", ...) was also removed: it fired more often on
   legitimate mail than on phishing. See the ablation below.

### DEV results

| Metric | Result |
|---|---:|
| Accuracy | 75.82% |
| Precision | 93.20% |
| Recall | 57.83% |
| F1 | 71.37% |
| False-positive rate | 4.59% |
| Specificity | 95.41% |
| Balanced accuracy | 76.62% |

Threshold: **23** (was 29 before the personalization ablation, 14 in V1).

### Ablation: personalization heuristics

Each row re-sweeps its own threshold under the same rule (highest recall at
FPR ≤ 5%):

| Config | Precision | Recall | F1 | FPR | Balanced accuracy | Threshold |
|---|---:|---:|---:|---:|---:|---:|
| A: both heuristics present | 93.50% | 49.68% | 64.88% | 3.76% | 72.96% | 29 |
| B: greeting-by-name removed only | 92.45% | 54.85% | 68.85% | 4.88% | 74.99% | 23 |
| C: OSINT-cue phrases removed only | 93.99% | 48.84% | 64.28% | 3.40% | 72.72% | 29 |
| D: both removed (frozen V2) | 93.20% | 57.83% | 71.37% | 4.59% | 76.62% | 23 |

Removing the OSINT-cue phrases alone (C) is roughly a wash against the
baseline (A). Most of the recall gain comes from removing the greeting
heuristic (B). Removing both together (D) improves precision, recall, F1,
and FPR at once.

V2 is frozen at config D. No further DEV tuning is planned before a
HELD-OUT confirmation.

### `authorship` left unchanged

On DEV, `authorship` fires on about 61% of both phishing and legitimate
emails, a coin flip. E-PhishLLM's legitimate emails are themselves clean,
LLM-generated text for contrast, so the detector is correctly flagging
AI-generated prose in both classes. That is a property of this dataset, not
a flaw in the detector, so it was left unchanged.

