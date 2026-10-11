#!/usr/bin/env python3
"""exp1_authz_throughput.py — Experiment 1 / Fig. 2: Authorization Throughput.

Same method as the V2 driver that produced the Fig. 2 currently in the paper
(results_v2_exp1/). Kept here so the experiment can be re-run against the V3
circuit and verifier; see PAPER_FIDELITY.md for what differs from that run.

Produces exp1_authz_throughput.csv:
  concurrency,Ref [20],Ref [24],Ref [28],FLEX-DIAM        (cells = requests/second)

Model: a single-threaded authorization server drains a burst of R concurrent
authorization requests; throughput = R / (time to fully authorize all R).
The SAME single-threaded server model is applied to all four schemes.

Per-scheme cost of one window of R requests (every unit measured live):
  Ref [20]: R x (group-signature Verify                 [Charm, live]
                 + 1 on-chain read                      [chain_meter, live])
  Ref [24]: R x (poly-eval + chameleon + rev check      [Charm, live])   (no chain)
  Ref [28]: R x (certificateless verify                 [Charm, live]
                 + 1 on-chain read                      [chain_meter, live])
  FLEX-DIAM: BatchVerify(R) with eq. 24-25 coefficients [native gnark verifier]
             + R x ECDSA-P256 token sign (eq. 28)       [OpenSSL, live]
             + 1 batch-commitment chain write (eq. 30)  [chain_meter, live]

Proof GENERATION is requester-side (each doctor proves independently) and does
not gate server throughput for any scheme — the same convention is applied to
the baselines, whose signature / key-agreement generation is also client-side.

Env: TRIALS (crypto samples, default 30), REPS_BATCH (verifier reps, default 3),
     PILOT (short sweep), OUT (csv path).
Run via run_exp1.sh (needs zkp/build/corpus from zkp/gen_corpus.py).
"""

import csv
import os
import statistics
import sys
import time

from baselines import li, wang, zeng
from flex_diam import chain_meter, cost_model, zkp
from flex_diam.chain import FabricLedger, require_real

R_VALUES = [100, 250, 500, 750, 1000, 1500, 2000, 2500, 3000, 4000, 5000]
BASELINE_MODS = {"Ref [20]": zeng, "Ref [24]": li, "Ref [28]": wang}


def token_sign_unit_ms(samples: int = 500) -> float:
    """Real ECDSA P-256 signature over an eq.-28 token body (OpenSSL-backed)."""
    from flex_diam.protocol import AuthTok
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    body = AuthTok("did:flex:" + "a" * 32, "did:flex:" + "b" * 32, "did:flex:" + "c" * 32,
                   "cid:" + "d" * 32, "e" * 64, "f" * 64, 1790000000).body()
    algo = ec.ECDSA(hashes.SHA256())
    key.sign(body, algo)  # warm
    t0 = time.perf_counter_ns()
    for _ in range(samples):
        key.sign(body, algo)
    return (time.perf_counter_ns() - t0) / samples / 1e6


def crypto_unit_ms(mod, samples: int) -> float:
    mod.auth_verify_one_ns()  # warm (group/param setup)
    return statistics.mean(mod.auth_verify_one_ns() / 1e6 for _ in range(samples))


def main() -> int:
    pilot = bool(os.environ.get("PILOT"))
    trials = int(os.environ.get("TRIALS", "5" if pilot else "30"))
    reps_batch = int(os.environ.get("REPS_BATCH", "2" if pilot else "3"))
    r_values = [100, 500] if pilot else R_VALUES
    out_path = os.environ.get("OUT", "exp1_authz_throughput_PILOT.csv" if pilot else "exp1_authz_throughput.csv")

    ledger = FabricLedger()
    require_real(ledger)

    print(f"=== Experiment 1 (authorization throughput): TRIALS={trials}, "
          f"REPS_BATCH={reps_batch}, pilot={pilot} ===\n")

    print("[1/4] Calibrating chain unit costs (live Fabric)...")
    cal = chain_meter.calibrate(ledger, samples=5 if pilot else 20)
    t_write, t_read = cal["write_ms"], cal["read_ms"]
    print(f"  T_BC write = {t_write:7.1f} ms (stdev {cal['write_stdev']:.1f})")
    print(f"  T_BC read  = {t_read:7.1f} ms (stdev {cal['read_stdev']:.1f})\n")

    print("[2/4] Measuring live crypto units...")
    t_sign = token_sign_unit_ms()
    print(f"  FLEX token sign (ECDSA P-256)      = {t_sign:8.3f} ms")
    base_unit = {}
    for scheme, mod in BASELINE_MODS.items():
        base_unit[scheme] = crypto_unit_ms(mod, trials)
        print(f"  {scheme} server verify unit       = {base_unit[scheme]:8.3f} ms")
    ind = zkp.verifier_bench("individual", 32, reps_batch)
    print(f"  FLEX INDIVIDUAL Groth16 verify      = {ind['per_proof_ms']:8.3f} ms/proof "
          f"(reference: what per-request ZKP verification would cost)\n")

    print("[3/4] Sweeping concurrency (FLEX batch verify measured at every R)...")
    rows = []
    for R in r_values:
        row = {"concurrency": R}
        for scheme in ("Ref [20]", "Ref [24]", "Ref [28]"):
            per_req = base_unit[scheme] + cost_model.exp1_chain_reads_per_auth(scheme) * t_read
            row[scheme] = R / (R * per_req / 1000.0)
        bv = zkp.verifier_bench("batch", R, reps_batch)
        window_ms = (bv["median_ms"] + R * t_sign
                     + cost_model.exp1_chain_writes_per_window("FLEX-DIAM") * t_write)
        row["FLEX-DIAM"] = R / (window_ms / 1000.0)
        rows.append(row)
        print(f"  R={R:<5} "
              f"[20]={row['Ref [20]']:7.1f}  [24]={row['Ref [24]']:7.1f}  "
              f"[28]={row['Ref [28]']:7.1f}  FLEX={row['FLEX-DIAM']:7.1f} req/s "
              f"(batchverify {bv['median_ms']:8.1f} ms = {bv['per_proof_ms']:.2f} ms/proof)")

    print("\n[4/4] Writing CSV...")
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["concurrency"] + cost_model.SCHEMES)
        for row in rows:
            w.writerow([row["concurrency"]] + [f"{row[s]:.2f}" for s in cost_model.SCHEMES])
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
