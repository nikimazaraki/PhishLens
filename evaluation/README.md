# PhishLens Evaluation

PhishLens is evaluated against the English-language subset of the E-PhishLLM dataset.

## Dataset

The full E-PhishLLM dataset contains **16,616 emails** across multiple languages.

For this benchmark, only the **11,502 English-language emails** are evaluated:

- **5,996 phishing emails**
- **5,506 legitimate emails**

The remaining non-English emails are excluded because the current PhishLens detectors are primarily designed around English-language linguistic and behavioral signals.

### Methodology

The 11,502 English-language emails are split using a stratified 70/30 DEV and HELD-OUT split with seed 42.

The DEV split contains **8,051 emails** and is used for:

- score-distribution analysis
- threshold selection
- false-positive analysis
- false-negative analysis

The HELD-OUT split contains **3,451 emails** and is reserved for one final evaluation.

Because E-PhishLLM provides only `Subject` and `Body`, this benchmark evaluates PhishLens under body-only conditions. Sender, authentication, recipient-context, and attachment-metadata checks are not exercised.

#### Threshold selection

The operating threshold is selected on DEV using the following rule:

> Select the threshold with the highest recall while keeping the false-positive rate at or below 5%.

The selected threshold is: 14

##### DEV results

Metric	Result
Accuracy	67.94%
Precision	90.73%
Recall	42.89%
F1	58.24%
False-positive rate	4.77%
Specificity	95.23%
Balanced accuracy	69.06%

These DEV results were used for threshold selection and are not the final held-out benchmark results.

###### Interpretation & Final Evaluation

At the selected operating point, PhishLens is conservative:

- predictions classified as phishing are usually correct
- the false-positive rate remains below 5%
- recall is limited, meaning a substantial portion of phishing emails are missed

The main observed limitations are low-scoring phishing emails that trigger no detector signals and legitimate professional emails that trigger multiple persuasion-related signals.

The final reported benchmark will use the untouched 3,451-email HELD-OUT split with the threshold fixed at 14 before evaluation.