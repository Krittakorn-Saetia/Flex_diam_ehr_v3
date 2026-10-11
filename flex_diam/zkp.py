"""flex_diam.zkp — credential issuance, proving and batch verification.

  issue_vc()      VC_D = Sign_skCI(Attr_D || DID_D || t_exp)               (eq. 5)
  policy_pid()    pid  = H(Encode(A))                                      (eq. 10)
  prove()         pi_i <- ZK.Prove(PK_zk, x_i, w_i), x_i = <DID, pid, rho> (eq. 19-22)
  batch_verify()  Valid_B = BatchVerify(VK_zk, B, {r_i})                   (eq. 23-26)

Proving is Circom + SnarkJS (`snarkjs groth16 fullprove`, one Node process that
computes the witness and the proof). Batch verification is the native
gnark-crypto verifier in zkp/batchverify_native. Both are timed as real
subprocess wall-clock, so Node / process start-up is included, as in V2.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import secrets
import subprocess
import time

from flex_diam.hashing import field_of_str

_HERE = os.path.dirname(os.path.abspath(__file__))
ZKP_DIR = os.path.abspath(os.path.join(_HERE, "..", "zkp"))
BUILD = os.environ.get("FLEX_ZKP_BUILD", os.path.join(ZKP_DIR, "build"))
WASM = os.path.join(BUILD, "authz_js", "authz.wasm")
ZKEY = os.path.join(BUILD, "authz.zkey")
VK = os.path.join(BUILD, "authz_vk.json")
CI_KEY = os.path.join(BUILD, "ci_key.json")
ORACLE_JS = os.path.join(ZKP_DIR, "oracle.js")
VERIFIER_BIN = os.path.join(ZKP_DIR, "batchverify_native", "batchverify_native")

NA = 4  # credential attribute slots (must match build_zkp.sh)
NP = 4  # policy slots
# Order of the Baby-Jubjub prime subgroup (same constant as zkp/oracle.js).
SUBORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041


def _env() -> dict:
    env = dict(os.environ)
    env["FLEX_ZKP_BUILD"] = BUILD
    return env


def oracle(a: int = 1, r: int = 1, attrs=None, did: int = 0, texp: int = 0, req=None) -> dict:
    """Evaluate zkp/oracle.circom; returns its outputs as ints."""
    inp = {
        "a": str(a), "r": str(r),
        "attrs": [str(x) for x in (attrs or [0] * NA)],
        "did": str(did), "texp": str(texp),
        "req": [str(x) for x in (req or [0] * NP)],
    }
    r_ = subprocess.run(["node", ORACLE_JS, "eval"], input=json.dumps(inp),
                        capture_output=True, text=True, env=_env())
    if r_.returncode != 0:
        raise RuntimeError(f"oracle failed: {r_.stderr[-500:]}")
    return {k: int(v) for k, v in json.loads(r_.stdout.strip().splitlines()[-1]).items()}


@functools.lru_cache(maxsize=1)
def ci_key() -> dict:
    """Credential issuer key (sk_CI = a, pk_CI = (Ax, Ay)) created by build_zkp.sh."""
    with open(CI_KEY) as f:
        return {k: int(v) for k, v in json.load(f).items()}


def _pad(values: list[int], n: int) -> list[int]:
    if len(values) > n:
        raise ValueError(f"at most {n} entries supported by the circuit, got {len(values)}")
    return values + [0] * (n - len(values))


def attr_fields(attr_names: list[str]) -> list[int]:
    """Attr_D as circuit field elements (0-padded to NA)."""
    return _pad([field_of_str(a) for a in attr_names], NA)


def policy_encoding(required_attrs: list[str]) -> list[int]:
    """Encode(A): canonical (sorted, de-duplicated) field encoding of a
    conjunctive policy, 0-padded to NP."""
    return _pad([field_of_str(a) for a in sorted(set(required_attrs))], NP)


@functools.lru_cache(maxsize=64)
def _pid_cached(req: tuple) -> int:
    return oracle(req=list(req))["pid"]


def policy_pid(required_attrs: list[str]) -> str:
    """pid = H(Encode(A)) as a 64-hex-digit string (Poseidon digest)."""
    return format(_pid_cached(tuple(policy_encoding(required_attrs))), "064x")


@dataclasses.dataclass
class VC:
    """Verifiable credential of a doctor (eq. 5), in circuit form."""

    attr_names: list[str]
    attrs: list[int]   # Attr_D as field elements
    did: int           # DID_D as a field element
    t_exp: int
    r8x: int
    r8y: int
    s: int


def issue_vc(attr_names: list[str], did_field: int, t_exp: int) -> VC:
    """Credential issuer: VC_D = Sign_skCI(Attr_D || DID_D || t_exp)."""
    ci = ci_key()
    attrs = attr_fields(attr_names)
    r = secrets.randbelow(SUBORDER - 1) + 1
    o = oracle(a=ci["a"], r=r, attrs=attrs, did=did_field, texp=t_exp)
    if (o["Ax"], o["Ay"]) != (ci["Ax"], ci["Ay"]):
        raise RuntimeError("oracle public key does not match build/ci_key.json")
    s = (r + 8 * o["h"] * ci["a"]) % SUBORDER  # S*B8 = R8 + h*(8*A)
    return VC(list(attr_names), attrs, did_field, t_exp, o["R8x"], o["R8y"], s)


def prove(vc: VC, pid: str, rho_field: int, required_attrs: list[str], work_dir: str, tag: str = "p"):
    """pi_i <- ZK.Prove(PK_zk, x_i, w_i). Returns (proof_path, public_path, ms).

    Raises RuntimeError when the witness does not satisfy eq. 22 (for example
    the credential does not hold a required attribute)."""
    inp = {
        "did": str(vc.did), "pid": str(int(pid, 16)), "rho": str(rho_field),
        "attrs": [str(x) for x in vc.attrs], "texp": str(vc.t_exp),
        "sigR8x": str(vc.r8x), "sigR8y": str(vc.r8y), "sigS": str(vc.s),
        "req": [str(x) for x in policy_encoding(required_attrs)],
    }
    ip = os.path.join(work_dir, f"{tag}_input.json")
    pf = os.path.join(work_dir, f"{tag}_proof.json")
    pub = os.path.join(work_dir, f"{tag}_public.json")
    with open(ip, "w") as f:
        json.dump(inp, f)
    for stale in (pf, pub):
        if os.path.exists(stale):
            os.remove(stale)
    t0 = time.perf_counter_ns()
    r = subprocess.run(["snarkjs", "groth16", "fullprove", ip, WASM, ZKEY, pf, pub],
                       capture_output=True, text=True)
    ms = (time.perf_counter_ns() - t0) / 1e6
    if r.returncode != 0 or not os.path.exists(pf):
        raise RuntimeError(f"ZK.Prove failed: {(r.stdout + r.stderr)[-400:]}")
    return pf, pub, ms


def batch_verify(bid: str, items: list[tuple[str, str]]):
    """Valid_B = BatchVerify(VK_zk, B, {r_i}) with recursive partition on failure.

    `items` is [(proof_path, public_path), ...]. Returns
    (valid: list[bool], wall_ms, in_process_ms)."""
    cmd = [VERIFIER_BIN, "verify", bid]
    for pf, pub in items:
        cmd += [pf, pub]
    t0 = time.perf_counter_ns()
    r = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    ms = (time.perf_counter_ns() - t0) / 1e6
    if r.returncode != 0:
        raise RuntimeError(f"batch verifier failed: {r.stderr[-400:]}")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    return [bool(v) for v in out["valid"]], ms, float(out["verify_ms"])


def verifier_bench(mode: str, b: int, reps: int) -> dict:
    """Corpus benchmark used by Experiment 1 (mode = 'batch' | 'individual')."""
    r = subprocess.run([VERIFIER_BIN, "bench", mode, str(b), str(reps)],
                       capture_output=True, text=True, timeout=1800, env=_env())
    if r.returncode != 0:
        raise RuntimeError(f"verifier bench failed: {r.stderr[-400:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])
