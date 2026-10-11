"""baselines.zeng — Ref [20] Zeng et al. 2025, TIFS.

"Efficient Revocable Cross-Domain Anonymous Authentication Scheme for IIoT",
IEEE TIFS, vol. 20, pp. 996-1010, 2025.

Implements the algorithms of Zeng Section IV (group signature with a dynamic
accumulator) as the paper states them, with real keys and a signature that
really verifies:

  Join    C_i = (s_i + x)^-1 P2,  ACC = (s_i + x) W_i
  Sign    T1 = uP1, T2 = uT1, T3 = s_iP1 + uP_pub, A1 = uW_i, A2 = uC_i,
          R1 = r_uP1, R2 = r_uT1, R3 = e(P_pub, A1+A2)^r_u e(T1, A1+A2)^r_s,
          R4 = r_sP1 + r_uP_pub, c = H(M, T1..A2, R1..R4),
          s_u = r_u + c u, s_s = r_s + c s_i
  Verify  recompute R1..R4 from (c, s_u, s_s) and compare the hash. The
          accumulator value enters ONLY here, inside R3 through
          e(T2, ACC + P2)^-c — three pairings in total. There is no separate
          accumulator membership check in the scheme (V2 charged one; removed).
  Revoke  ACC_{j+1} = (s + x)^-1 ACC_j           (one per revoked device)
  Update  w = prod_{j in S1} (s_j + x),  W_i <- w W_i   (once per user, covering
          every revocation since that user's last update)

P_pub = xP1 is a public parameter and is precomputed, not recomputed per
signature. All groups are those of the pairing curve shared with FLEX-DIAM
(FLEX_CURVE, default BN254).
"""

from __future__ import annotations

import hashlib
import os
import time

from charm.toolbox.pairinggroup import G1, G2, ZR, PairingGroup, pair

_CURVE = os.environ.get("FLEX_CURVE", "BN254")
_MSG = b"cross-domain authentication request"

_group: PairingGroup | None = None
_p1 = _p2 = _x = _ppub = None          # public parameters and group secret x
_si = _ci = _wi = _acc = None          # one registered member and the accumulator


def _ensure_setup() -> None:
    global _group, _p1, _p2, _x, _ppub, _si, _ci, _wi, _acc
    if _group is not None:
        return
    _group = PairingGroup(_CURVE)
    _p1 = _group.random(G1)
    _p2 = _group.random(G2)
    _x = _group.random(ZR)
    _ppub = _p1 ** _x
    # Join: certificate C_i and evidence W_i with ACC = (s_i + x) W_i
    _si = _group.random(ZR)
    _ci = _p2 ** ((_si + _x) ** -1)
    _wi = _group.random(G2)
    _acc = _wi ** (_si + _x)


def _challenge(msg: bytes, *elems):
    h = hashlib.sha256(msg)
    for e in elems:
        h.update(_group.serialize(e))
    return _group.hash(h.hexdigest(), ZR)


def sign(msg: bytes = _MSG):
    """Zeng Sign(s_i, C_i, W_i, params, M)."""
    _ensure_setup()
    u, ru, rs = _group.random(ZR), _group.random(ZR), _group.random(ZR)
    t1 = _p1 ** u
    t2 = t1 ** u
    t3 = (_p1 ** _si) * (_ppub ** u)
    a1 = _wi ** u
    a2 = _ci ** u
    a = a1 * a2
    r1 = _p1 ** ru
    r2 = t1 ** ru
    r3 = (pair(_ppub, a) ** ru) * (pair(t1, a) ** rs)
    r4 = (_p1 ** rs) * (_ppub ** ru)
    c = _challenge(msg, t1, t2, t3, a1, a2, r1, r2, r3, r4)
    return (t1, t2, t3, a1, a2, c, ru + c * u, rs + c * _si)


def verify(sig, msg: bytes = _MSG, acc=None) -> bool:
    """Zeng Verify(M, sigma, params) against accumulator value `acc`."""
    _ensure_setup()
    t1, t2, t3, a1, a2, c, su, ss = sig
    acc = _acc if acc is None else acc
    a = a1 * a2
    r1 = (_p1 ** su) * (t1 ** (-c))
    r2 = (t1 ** su) * (t2 ** (-c))
    r3 = (pair(_ppub, a) ** su) * (pair(t1, a) ** ss) * (pair(t2, acc * _p2) ** (-c))
    r4 = (_p1 ** ss) * (_ppub ** su) * (t3 ** (-c))
    return c == _challenge(msg, t1, t2, t3, a1, a2, r1, r2, r3, r4)


def _group_sig_gen_ns() -> int:
    _ensure_setup()
    t0 = time.perf_counter_ns()
    sign()
    return time.perf_counter_ns() - t0


def _group_sig_verify_ns() -> int:
    _ensure_setup()
    sig = sign()
    t0 = time.perf_counter_ns()
    ok = verify(sig)
    dt = time.perf_counter_ns() - t0
    if not ok:
        raise RuntimeError("Zeng group signature failed to verify")
    return dt


# ---------------------------------------------------------------------------
# Revocation (Revoke) and evidence update (Update)
# ---------------------------------------------------------------------------


def _gm_revoke_one_ns() -> int:
    """Revoke: ACC_{j+1} = (s + x)^-1 ACC_j — one inversion + one G2 scalar mult."""
    _ensure_setup()
    s_star = _group.random(ZR)
    acc_old = _group.random(G2)

    t0 = time.perf_counter_ns()
    inv = (s_star + _x) ** -1
    _acc_new = acc_old ** inv
    return time.perf_counter_ns() - t0


def _witness_update_one_user_ns(N_revoked: int) -> int:
    """Update: w = prod_{j=1..N} (s_j + x), W_i <- w W_i — N field mults + one G2
    scalar mult, covering all N revocations since the user's last update."""
    _ensure_setup()
    sjs = [_group.random(ZR) for _ in range(N_revoked)]
    w_i = _group.random(G2)

    t0 = time.perf_counter_ns()
    w = sjs[0] + _x
    for j in range(1, N_revoked):
        w = w * (sjs[j] + _x)
    _w_new = w_i ** w
    return time.perf_counter_ns() - t0


# ---------------------------------------------------------------------------
# What the experiments charge
# ---------------------------------------------------------------------------


def auth_verify_one_ns() -> int:
    """Experiment 1 — server-side verification of one authorization request:
    the group-signature Verify. The verifier's on-chain read of the latest
    accumulator value is charged by the driver."""
    return _group_sig_verify_ns()


def authority_revoke_ns(N: int) -> int:
    """Experiment 2 — the domain manager revokes N devices: N accumulator
    updates, fully executed. Publishing the result on the blockchain is charged
    by the driver."""
    _ensure_setup()
    return sum(_gm_revoke_one_ns() for _ in range(N))


def user_maintenance_ns(N: int) -> int:
    """Experiment 3 — ONE unaffected member's evidence update after N revocations."""
    if N <= 0:
        return 0
    return _witness_update_one_user_ns(N)


def access_auth_ns() -> int:
    """Experiment 3 — one cross-domain authentication, both ends: Sign (device)
    + Verify (edge server). The verifier's on-chain read is charged by the driver."""
    return _group_sig_gen_ns() + _group_sig_verify_ns()
