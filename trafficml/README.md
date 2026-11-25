# trafficml: learned traffic models for the behaviour check (C4)

Two models run beside the hand-written behaviour rules. Both read NetFlow records that
[`netflow/`](../netflow/) builds from packets on the node's bridge, both have a NumPy path
and an ExecuTorch program with identical decisions, and both explain their output.

| | Flow classifier | Learned per-charger baseline |
|---|---|---|
| Question | Does this one flow look like attack traffic? | Does this charger's last 10 seconds look like itself? |
| Model | MLP 39 → 128 → 64 → 1, 13,441 parameters | Autoencoder 20 → 12 → 6 → 12 → 20 |
| Trained on | NF-UNSW-NB15 (NetFlow v1), labelled | The charger's healthy traffic only, no labels |
| Output | Probability; the features that raised it (gradient × input) | Reconstruction error; the features furthest from normal |
| Effect on the verdict | Anomaly only for peers outside the baseline; otherwise evidence | Anomaly (`learned-baseline`), peers never seen in enrolment blocked |
| Files | `weights/flow_mlp.npz`, `weights/flow_mlp.pte` (58 KB) | `weights/behaviour_ae.npz`, `weights/behaviour_ae.pte` (8 KB) |

## Flow classifier

**Data.** NF-UNSW-NB15 from the University of Queensland: 1,623,118 NetFlow records of the
UNSW-NB15 testbed, 4.4% attacks in nine categories (`python scripts/fetch_datasets.py nf_unsw_nb15`).

**What the model is not allowed to see.** In this dataset several fields identify the
testbed rather than the behaviour, and a model that uses them scores near-perfectly
without learning anything transferable:

- IP addresses: every attack comes from 175.45.176.0/24;
- source ports: ephemeral and testbed-specific;
- TTL and TCP window size (v2): benign traffic has TTL 31–32, attacks 254–255;
- exotic IP protocol numbers: attacks use all 256 evenly, benign traffic only TCP/UDP/ICMP, so the protocol is folded into tcp / udp / icmp / other;
- several extended v2 fields are internally inconsistent (32-bit duration wrap-arounds of 4,294,952 ms, ICMP types on TCP flows, packet-size buckets that do not add up), so the deployed model uses the basic v1 fields.

Features (`features.py`, identical for training and on the node): bytes and packets each
way, duration, bytes per packet, reply/request ratios, a no-reply flag, packet rate, the
eight TCP flags, the protocol class and a destination-port class.

**Protocol** (`train.py`). 20,634 rows with wrapped durations dropped; duplicates of
(features, label) removed *before* splitting, which leaves 338,349 unique rows (52% of
the rows are duplicates once addresses are gone); stratified 70/15/15 split; threshold
chosen on validation for a 0.5% false-positive rate and reported once on test.

| Test (50,753 unique flows, 7,094 attacks) | ROC-AUC | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| MLP (deployed) | 0.988 | 0.950 | 0.541 | 0.689 | 0.46% |
| Gradient-boosted trees (reference) | 0.991 | 0.954 | 0.607 | 0.742 | 0.47% |

Recall by category at that threshold: Exploits 0.79, Generic 0.67, DoS 0.55,
Reconnaissance 0.54, Shellcode 0.37, Backdoor 0.36, Fuzzers 0.11, Analysis 0.02.
Retrained **without** a category, recall on it: Generic 0.58, DoS 0.52,
Reconnaissance 0.52, Exploits 0.35, Fuzzers 0.05. Published NF-UNSW-NB15 results near
99% keep duplicates and addresses; these numbers are lower because they are honest.

**On charger traffic** (`charger_eval.py`, synthetic): 0.3% of healthy flows flagged
(both were TLS firmware-update downloads), and almost none of a port scan, C2 beacons, a
DNS tunnel or an OCPP flood, because each of those flows is ordinary on its own. That is
why the classifier cannot fail a charger by itself unless the peer is outside the baseline,
and why the second model exists.

## Learned per-charger baseline

Twenty features per 10-second window (`behaviour.py`): connection rate, destination
hosts and ports, shares of unanswered, refused and half-open connections, DNS query
count, length and randomness of DNS labels, shares of never-seen peers and ports, upload
and download rates and their ratio, packet rate, beacon regularity, share of the busiest
service, UDP share, OCPP packet rate and share of TXT queries.

**Training** (`behaviour_train.py`). Healthy traffic is synthesised as real packets
(`netflow/synth.py`) with the variation a charger shows (1–3 OCPP messages a second,
session bursts, reconnects, DNS, NTP, update checks) and aggregated by the node's flow
table. Each window is also seen with 0–40% of the OCPP export slices missing, because on
a real bridge the exporter's timing decides how many land in a window. The threshold is
1.6 × the 99.9th percentile of held-out healthy windows.

**Evaluation.** 1,796 unseen healthy windows: no false alarms (highest score 0.31 × the
threshold). Nine attack shapes added to healthy background, 40 windows each, all detected;
five of them appear nowhere else in the project. The weakest margins are a C2 beacon
(1.4 × threshold) and a slow DNS tunnel through the approved resolver (1.38 ×), which the
rules miss. On three minutes of live simulator traffic the highest healthy window scored
about 0.7 × the threshold.

**Caveat.** Healthy and attack traffic both come from our own generator, so these figures
are optimistic. On the Raspberry Pi the baseline is refitted on the real charger's
enrolment capture (`python -m trafficml.behaviour fit --records ...`, see
[`deploy/pi/README.md`](../deploy/pi/README.md)), and its false-alarm rate has to be
measured there over days.

## ExecuTorch

`python -m trafficml.executorch_export` (ExecuTorch environment) exports both models with
standardisation folded in, then checks them against the NumPy models on real flows and
windows: every decision agrees, maximum difference 7×10⁻⁸ (flow) and 1×10⁻⁶ (window).
Latency on the development host's x86-64 CPU under WSL2: 0.10 ms and 0.05 ms (p50).
