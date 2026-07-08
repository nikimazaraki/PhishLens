# PhishLens Evaluation

PhishLens was evaluated against the English-language subset of the E-PhishLLM dataset.

## Dataset

The full E-PhishLLM dataset contains **16,616 emails** across multiple languages.

This benchmark uses only the **11,502 English-language emails**:

- **5,996 phishing emails**
- **5,506 legitimate emails**

Non-English emails are excluded because the current PhishLens detectors are primarily designed around English-language linguistic and behavioral signals.

## Methodology

The English-language subset is divided using a stratified 70/30 DEV and HELD-OUT split with seed `42`.

### DEV split

The DEV split contains **8,051 emails** and is used for:

- score distribution analysis
- threshold selection
- false-positive analysis
- false-negative analysis

### HELD-OUT split

The HELD-OUT split contains **3,451 emails** and is reserved for the final evaluation.

Because E-PhishLLM provides only `Subject` and `Body`, this benchmark evaluates PhishLens under **body-only conditions**.

The following metadata-dependent signals are therefore not evaluated:

- sender identity
- email authentication signals
- recipient context
- attachment metadata

## Threshold Selection

The operating threshold is selected exclusively on the DEV split using the following rule:

> Select the threshold with the highest recall while keeping the false-positive rate at or below 5%.

The resulting operating threshold is **14**.

### DEV Results

| Metric | Result |
|---|---:|
| Accuracy | 67.94% |
| Precision | 90.73% |
| Recall | 42.89% |
| F1 | 58.24% |
| False-positive rate | 4.77% |
| Specificity | 95.23% |
| Balanced accuracy | 69.06% |

These results are used only for threshold selection and error analysis. They are not the final benchmark results.

### DEV Interpretation

At the selected operating point, PhishLens shows a conservative detection profile:

- phishing predictions are usually correct
- the false-positive rate remains below 5%
- recall is limited, meaning a substantial portion of phishing emails are missed

The main observed limitations are:

- phishing emails that receive very low scores or trigger no detector signals
- legitimate professional emails that trigger multiple persuasion-related signals

## Final HELD-OUT Evaluation

After selecting and freezing the threshold at `14`, PhishLens was evaluated once on the untouched HELD-OUT split.

### Confusion Matrix

| | Predicted Phishing | Predicted Benign |
|---|---:|---:|
| Actual Phishing | 799 | 1000 |
| Actual Legitimate | 66 | 1586 |

### HELD-OUT Results

| Metric | Result |
|---|---:|
| Accuracy | 69.11% |
| Precision | 92.37% |
| Recall | 44.41% |
| F1 | 59.98% |
| False-positive rate | 4.00% |
| Specificity | 96.00% |
| Balanced accuracy | 70.21% |

## Interpretation

On the HELD-OUT set, PhishLens behaves as a **high-precision, conservative detector**.

At the selected operating point:

- **92.37%** of emails flagged as phishing are actually phishing
- **44.41%** of phishing emails are detected
- **4.00%** of legitimate emails are incorrectly flagged

The HELD-OUT results are close to the DEV results, suggesting that the DEV-selected threshold generalized consistently to unseen data.

However, recall remains the main limitation: more than half of the phishing emails in the benchmark are not detected.

These results should also be interpreted in the context of the benchmark input. Since E-PhishLLM provides only email subject and body content, PhishLens components that rely on sender identity, authentication information, recipient context, or attachment metadata are not exercised.