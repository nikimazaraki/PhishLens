# PhishLens

An explainable detector for AI-generated spear-phishing emails. PhishLens scores
an email from 0–100, gives a verdict, and lists the evidence behind every flag —
so an analyst can triage in seconds instead of guessing.

## What it does

PhishLens runs an email past a panel of independent checks, each looking for one
hallmark of an AI-assisted attack, then combines them into a single risk score.
Every flag comes with a plain-language reason; nothing is a black box.

The checks cover:

- **Manipulation tactics** – authority, urgency, social proof, reciprocation,
  commitment, and liking.
- **Personalization** – whether the email targets the recipient by name, role,
  or employer.
- **AI-written prose** – unusually clean, uniform, command-heavy text.
- **Pretext** – common lures: fake password/MFA resets, bonus or refund bait,
  invoice fraud.
- **Deceptive links** – lookalike domains, homographs, shorteners, and link text
  that points elsewhere.
- **Fake login prompts** – "Sign in with…" credential-harvest pages and QR codes.
- **Sender & authentication** – brand names sent from free webmail, typosquatted
  domains, and failed SPF/DKIM/DMARC.
- **Risky attachments** – macro-enabled documents and disguised executables.

Two signals go beyond a simple flag count: the score escalates when several
manipulation tactics stack together, and it flags emails that are personalized,
credible, and threatening all at once.

## Requirements

Python 3.10+, standard library only. FastAPI is an optional extra for the HTTP
wrapper; pytest is used for the tests.

## Usage

```bash
# Analyze an email file, passing known details as flags
python -m phishlens.cli examples/spear_phish.txt \
  --name Alex --role analyst --employer "Acme Corp" --brand DocuSign \
  --from '"IT Support" <it-support@gmail.com>' --dmarc fail

# Pipe from stdin and get JSON
cat email.txt | python -m phishlens.cli - --json
```

From Python:

```python
from phishlens import analyze

result = analyze(
    "Hi Alex, the IT department requires all employees to verify your account "
    "within 24 hours to avoid suspension. Log in to confirm: "
    "https://docusign.login-verify.ru/sso",
    from_header='"IT Support" <it-support@gmail.com>',
    claimed_brand="DocuSign",
    recipient_name="Alex",
    headers={"spf": "softfail", "dmarc": "fail"},
)

print(result.risk_score, result.verdict.value)
for reason in result.reasons:
    print(" -", reason)
```

Run the tests with `pip install pytest && pytest -q`.

## Example output

```
Risk: 82.5/100   Verdict: HIGH_RISK

Why:
  - stacked persuasion: 3 manipulation tactics combined (authority, scarcity, social_proof)
  - complete con: relevant + credible + threatening all present
  - [links] brand "docusign" in subdomain of unrelated host (docusign.login-verify.ru)
  - [sender] corporate display name "IT Support" from free-mail (gmail.com)
  - [auth] DMARC = fail
  - [credential_harvest] credential-request language: "log in to confirm"
  - [pretext] it security reset pretext: "verify your account"
  - [personalization] addresses recipient by name ("Alex")
```

A benign message scores in the single digits with a `BENIGN` verdict.

## Design

Each check is a small, independent function that scores one signal and returns
its evidence. A scoring engine combines them into a weighted risk rating and adds
the two cross-cutting signals. Because the checks are independent, each is easy to
test and the system is hard to fool with any single trick. The AI-writing detector
sits behind a clean interface, so a machine-learning model can replace the
rule-based scorer without touching anything else.

## Disclaimer

Defensive tooling only. PhishLens analyzes emails for risk; it does not generate,
send, or facilitate phishing.
