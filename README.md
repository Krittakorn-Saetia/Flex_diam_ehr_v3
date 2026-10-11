# FLEX-DIAM V3 — scoped revocation prototype and experiments

Implementation and measurement harness for **FLEX-DIAM: Flexible Cross-Domain
Identity and Access Management with Selective Revocation for IoMT-EHR Sharing**
(conference submission, scoped-revocation revision of October 2026).

FLEX-DIAM combines decentralized identifiers, batch zero-knowledge authorization,
CP-ABE, context-bound attribute-based proxy re-encryption and blockchain-managed
*scoped* revocation: every doctor, policy and healthcare domain has its own
revocation version, so revoking one doctor does not touch anyone else's tokens,
keys or ciphertexts.

This repository contains everything needed to run the prototype and reproduce
the three experiments of the paper, compared against three revocable
cross-domain authentication schemes (Refs [20], [24], [28] of the paper).

- **[SETUP.md](SETUP.md)** — step-by-step setup from a clean machine to running
  the experiments.
- **[REPORT.md](REPORT.md)** — detailed report: what is implemented, how each
  experiment measures, results, validation, limitations.
- **[PAPER_FIDELITY.md](PAPER_FIDELITY.md)** — equation-by-equation map from the
  paper to the code, and every implementation choice.

Every number in this repository is a live measurement (Charm-Crypto operations,
real Groth16 proofs, real Hyperledger Fabric transactions). The plotting script
only reads CSV files; it never generates data.

## Status of the results

| Run | Date | Content | Where |
|---|---|---|---|
| Run 1 | 2026-10-11 | All three experiments, 30 independent runs each. FLEX-DIAM and Ref [28] are final. Refs [20] and [24] were measured with baseline models that were corrected afterwards (see REPORT.md §6). | `results/run1_2026-10-11/` |
| Run 2 | not completed | Re-run of all three experiments with the corrected baselines. A first attempt on 2026-10-12 was interrupted during Experiment 1 and is not used. REPORT.md §9 states whether a complete Run 2 has been added. | `results/` |

## What is implemented

| Part | Implementation |
|---|---|
| Phases 1–5 of the protocol | `flex_diam/protocol.py`, one method per paper step |
| Scoped revocation state, DID registry, audit anchors | Go chaincode on Hyperledger Fabric 2.5 (`chaincode/flex/`) |
| CP-ABE and context-bound ABPRE | BSW07 via Charm-Crypto, `flex_diam/abpre.py` |
| Authorization proof (eq. 19–22) | Circom circuit, 3,810 constraints, Groth16 via SnarkJS (`zkp/`) |
| Batch verification (eq. 23–26) | native verifier on gnark-crypto (`zkp/batchverify_native/`) |
| Compared schemes | `baselines/zeng.py` [20], `baselines/li.py` [24], `baselines/wang.py` [28] |
| Experiments 1–3 | `exp1_authz_throughput.py`, `exp2_scoped_revocation.py`, `exp3_unaffected_continuity.py` |

## Repository layout

| Path | Content |
|---|---|
| `flex_diam/protocol.py` | Phases 1–5 and the timed end-to-end access |
| `flex_diam/abpre.py` | CP-ABE (BSW07) and the context-bound ABPRE |
| `flex_diam/zkp.py` | credential issuance, proving, batch verification |
| `flex_diam/chain.py` | Fabric client (`peer` CLI) and an in-memory ledger for offline tests |
| `flex_diam/chain_meter.py`, `flex_diam/cost_model.py` | live calibration of chain units; chain-operation counts charged to the baselines |
| `flex_diam/hashing.py` | H(·), unambiguous concatenation, field encodings |
| `chaincode/flex/` | Go chaincode; `chaincode/deploy_ccaas.sh` deploys it as a service |
| `zkp/` | circuits, build script, proof-corpus generator, native batch verifier |
| `baselines/` | the three compared schemes and their self-test |
| `exp*.py`, `run_exp*.sh`, `repeat_exp*.sh` | experiment drivers, single runs, 30-run repetitions |
| `average_csvs.py`, `plot_figs.py` | per-cell mean / stdev over runs; figures from CSVs |
| `smoke_protocol.py` | 12 functional checks of the protocol (offline or on live Fabric) |
| `infra/` | one-time installer for the toolchain and Fabric |
| `results/` | measured CSVs (averaged and per-run) and figures |
| `results_v2_exp1/` | Experiment 1 as measured with the previous (V2) code, kept for comparison |

## Requirements

Ubuntu 22.04 (native, or WSL2 on Windows 11) with Docker running. The
experiments were measured with:

| Component | Version |
|---|---|
| Python / Charm-Crypto / PBC | 3.10.12 / 0.63 / 0.5.14 |
| `cryptography`, `matplotlib` | 49.0.0, 3.10.9 |
| Node.js / SnarkJS / Circom / circomlib | 18.20.8 / 0.7.6 / 2.1.9 / 2.0.5 |
| Go | 1.22.5 (the verifier needs gnark-crypto 0.20.1 and switches to a Go 1.25 toolchain automatically) |
| Hyperledger Fabric | 2.5.9 (test-network: 2 organizations, 1 Raft orderer, LevelDB, BatchTimeout 1 s) |
| Docker | 29.5.3 |

## Setup

**[SETUP.md](SETUP.md) is the full step-by-step guide**: installing Ubuntu and
Docker, what each script installs and where, the output to expect at every
step, how to restart after a reboot, and troubleshooting. The short version:

Clone inside Ubuntu:

```bash
git clone https://github.com/Krittakorn-Saetia/Flex_diam_ehr_v3.git ~/flex-diam-v3
```

Install the toolchain and Fabric once (20–40 minutes, uses sudo and downloads).
It installs into `~/flex-diam`; set `FLEX_INFRA` to use another directory. Skip
this if you already have that environment.

```bash
cd ~/flex-diam-v3 && ./infra/setup_infra.sh
```

Open a new shell, then build everything that does not need the blockchain:
circuits and Groth16 keys, the native verifier, the Experiment 1 proof corpus.
It finishes with the baseline self-test (4 checks) and the protocol check on the
in-memory ledger (12 checks).

```bash
cd ~/flex-diam-v3 && ./setup.sh
```

Bring up the Fabric test-network with its channel:

```bash
cd ~/flex-diam/fabric-samples/test-network && ./network.sh up createChannel -c mychannel
```

Deploy the chaincode (name `flexv3`, chaincode-as-a-service). The script first
checks that the peers, the orderer and the channel exist.

```bash
cd ~/flex-diam-v3 && ./chaincode/deploy_ccaas.sh
```

Check the whole protocol against the live network. It must end with
`12/12 checks passed`.

```bash
. ./env.sh && "$FLEX_PY" smoke_protocol.py
```

## Running the experiments

Pilots use a short grid and write `*_PILOT.csv`:

```bash
PILOT=1 ./run_exp1.sh
```

```bash
PILOT=1 ./run_exp2.sh
```

```bash
PILOT=1 ./run_exp3.sh
```

Full experiments, 30 independent runs each. If earlier results exist in the
directory, each script first moves them to `results_archive/<timestamp>_expN/`.

```bash
./repeat_exp1.sh
```

```bash
./repeat_exp2.sh
```

```bash
./repeat_exp3.sh
```

Figures from the CSVs:

```bash
. ./env.sh && "$FLEX_PY" plot_figs.py
```

Approximate duration on the reference machine: Experiment 1 about 1 minute per
run, Experiment 2 about 3 minutes, Experiment 3 about 2 minutes; roughly 3 hours
for all three at 30 runs. Run them one after another, not in parallel, and keep
the machine otherwise idle.

## Outputs

| File | Meaning |
|---|---|
| `exp1_authz_throughput.csv` (+ `_std`) | Fig. 2 — authorization throughput, requests/s |
| `exp2_scoped_revocation.csv` (+ `_std`, `_detail`) | Fig. 3 — end-to-end revocation latency, ms |
| `exp3_unaffected_continuity.csv` (+ `_std`, `_detail`) | Fig. 4 — unaffected-user access latency, ms |
| `fig/exp1_batch_throughput`, `fig/exp2_revocation_overhead`, `fig/exp3_unaffected_continuity` | figures (`.png`, `.pdf`) |

The `_detail` file of Experiment 3 holds the per-stage breakdown of the FLEX-DIAM
access and, for the baselines, maintenance, authentication and chain read. It
also records two correctness checks at every workload: `continuity_ok` (a token
issued before the workload was revoked still works afterwards) and
`revoked_rejected`.

Driver outputs in the repository root are ignored by git. To keep a result set,
copy it under `results/<name>/`.

## Switches

| Variable | Default | Effect |
|---|---|---|
| `REPEATS` | 30 | independent runs averaged by `repeat_*.sh` |
| `TRIALS` | 3 (1 under `repeat_exp2/3`) | repetitions per point inside one run |
| `PILOT` | unset | short grid, output to `*_PILOT.csv` |
| `REVOKE_MODE` | `batch` | Exp 2: one transaction per workload, or `per_tx` for one per doctor |
| `SRAA_BATCH` | 1 | Ref [24]: revoked twins per gateway update round (0 = one round for the whole workload) |
| `CHECKS` | 1 | Exp 3: record the continuity / enforcement checks |
| `FLEX_FS_BITS` | full field | width of the batch coefficients r_i (128 = small-exponent batching) |
| `FLEX_AEAD` | `chacha20poly1305` | `aesgcm` selects AES-256-GCM |
| `FLEX_CURVE` | `BN254` | pairing curve for CP-ABE / ABPRE and all baselines |
| `FLEX_INFRA` | `~/flex-diam` | directory holding `venv/` and `fabric-samples/` |
| `FLEX_CC`, `FLEX_CHANNEL` | `flexv3`, `mychannel` | chaincode and channel names |

## Troubleshooting

- **`Cannot run peer because cannot init crypto ... msp does not exist`** — the
  Fabric test-network is down. Bring it up with the `network.sh` command above,
  then deploy again.
- **`docker: command not found` inside WSL** — start Docker Desktop and enable
  WSL integration for the Ubuntu distribution.
- **After editing the chaincode** — `IMAGE_ONLY=1 ./chaincode/deploy_ccaas.sh`
  rebuilds the image and restarts the container without a new lifecycle round.
- **`argument ... exceeds the single-argument limit of the peer CLI`** — a
  workload is too large for one transaction; use a smaller workload or
  `REVOKE_MODE=per_tx`.
- **Stale network state** — `./network.sh down`, then bring it up and deploy
  again. This starts a fresh ledger.
