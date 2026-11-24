# threatintel — on-device scam and phishing detectors

Two small, explainable models that run on the ChargeGuard node with no cloud
calls. They protect two people at a charging site:

- **drivers**, who receive scam texts about their charging account and scan
  payment QR codes on the charger;
- **operators**, whose chargers can be tampered with to show a fake payment QR code ("quishing").

| Detector | Input | Model | Used by |
|---|---|---|---|
| `ScamMessageDetector` | SMS / chat text | Logistic regression over hashed word 1–2-grams + character 3–5-grams | Driver Safety Check (`POST /api/threat/message`) |
| `PhishingUrlDetector` | URL or QR payload | Logistic regression over hashed hostname character 3–5-grams + 12 lexical features, plus explicit rules and a curated known-good list | Driver Safety Check (`POST /api/threat/url`), and the gateway, which checks the payment QR every charger displays |

Both are linear models over hashed features, chosen deliberately for the edge:

- **No vocabulary file** is needed.
- **About 1–3 ms per check** on a laptop CPU, measured by the dashboard.
- **Under 1.5 MB of weights.**
- **Every score is explainable:** each n-gram's contribution is its weight, so the
  dashboard and the advisor can say *why*.
- **ExecuTorch export:** the same weights export to an ExecuTorch program
  (`executorch_export.py`) as one embedding-lookup layer.

## Data

| Dataset | Licence | Rows used | Positives |
|---|---|---|---|
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | CC BY 4.0 | 5,171 unique messages (5,574 before removing duplicates) | 653 spam |
| [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | CC BY 4.0 | 219,036 unique hostnames (235,795 URLs) | 84,244 phishing |

`python scripts/fetch_datasets.py` downloads both into `data/raw/` (git-ignored)
and checks them against `data/checksums.json`.

## Evaluation protocol

- **SMS.** Duplicate messages are removed before splitting, so the same text
  cannot appear in training and test. The split is stratified 70/15/15
  (train/validation/test).
- **URLs: a label leak, and how it is avoided.** In PhiUSIIL, *every* legitimate
  URL has the form `https://www.<domain>`: HTTPS, `www.` and no path. Phishing
  URLs are 49% HTTPS, 42% `www.`, and 28% have a path. A model trained on
  full URLs scores close to 100% by learning "no path means safe", and fails on
  real links such as `https://bank.com/login`. The model therefore sees **only
  the hostname** (scheme, `www.` and path removed).
- **URL split.** It is grouped by registrable domain: zero domains appear in
  both training and test (`domains_in_both_train_and_test: 0`).
- **Threshold.** The decision threshold is chosen on the validation split
  (maximum F1) and reported on the untouched test split.

## Results (held-out test split)

From [`benchmarks/results/threatintel_metrics.json`](../benchmarks/results/threatintel_metrics.json):

| Model | Test size | Precision | Recall | F1 | ROC-AUC | False-positive rate |
|---|---|---|---|---|---|---|
| Scam messages (threshold 0.45) | 776 | 0.968 | 0.918 | **0.942** | 0.991 | 0.44% (3 of 678 legitimate) |
| Phishing hostnames (threshold 0.50) | 30,093 | 0.837 | 0.679 | **0.750** | 0.888 | 6.3% |

The hostname model is honest rather than impressive: many phishing pages sit
on ordinary-looking hostnames (`maria.susypro.com`) that no hostname-only
model can catch. A validation sweep of richer hostname features (character
2–6-grams, hostname tokens) gave F1 0.806–0.808 against 0.806 for the shipped
model, so the simpler model was kept.

## Rules and known-good list (documented, not learned)

These cover signals that the training data cannot teach without leaking the label.
Each rule raises the score independently (noisy-OR) and is shown to the user when it fires:

| Rule | Weight |
|---|---|
| Credential or payment keyword in the path (`login`, `verify`, `payment`, …) | 0.30 |
| Brand name used as a token outside the brand's own domain | 0.35 |
| Raw IP address instead of a domain | 0.45 |
| `@` in the authority part (credential-style redirect) | 0.40 |
| Punycode / look-alike characters | 0.35 |
| URL shortener | 0.25 |
| Free-hosting or user-content platform (Firebase, IPFS, Google Sites/Docs/Forms, …) | 0.20 |
| Unencrypted `http` | 0.10 |

[`known_good.txt`](known_good.txt) lists first-party domains of major platforms,
EV charging networks and payment providers.

- **Effect:** on a listed domain, the model score is capped at 0.05.
- **Why it exists:** phishing kits are often hosted *on* big platforms, which
  teaches URL models to distrust `google.com` itself. Reputation lists are the
  standard remedy.
- **Not covered:** user-content platforms are never on the list.
- **Hard red flags still apply on listed domains:** a raw IP address, an `@`
  redirect or punycode.

## Use

```python
from threatintel import analyse_message, analyse_url
analyse_message("URGENT: your charging account is suspended, pay at chargepoint-billing.top/verify")
analyse_url("https://chargepoint-pay.top/verify?station=CG-001")
```

Retrain and refresh the metrics:

```bash
python scripts/fetch_datasets.py
python -m threatintel.train
```

## Limitations

- The SMS data is general spam from 2012, not EV-specific scam traffic. The
  example EV messages in the tests are illustrative, not a benchmark.
- The URL model judges hostnames only; page content and live reputation feeds
  (PhishTank, OpenPhish) are not used, by design, because the node works offline.
- Thresholds were tuned on validation data from the same distributions as the
  test sets; field performance will differ and should be re-measured on
  captured site data.
