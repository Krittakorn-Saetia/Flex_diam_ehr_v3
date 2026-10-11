"""baselines.wang — Ref [28] Wang et al. 2024, TCSS.

"Revocable Certificateless Cross-Domain Authentication Scheme Based on
Primary-Secondary Blockchain", IEEE TCSS, Oct 2024.

Cost-dominant operations identified from Wang Section V.A (closed-form cost
analysis given in the paper itself):

- POST-REVOCATION UPDATE (Fig 4):
    per revocation = 3*T_sm + T_h + T_pa
    (3 EC scalar mults + 1 SHA-256 + 1 EC point addition)
    Linear in N. Wang's i5-10300H number: ~1.5 ms per revocation.

- CROSS-DOMAIN SHARING (Fig 5, per record):
    T_V^CL + T_BC
    (certificateless verify = ~3 EC scalar mults + 1 hash, plus 1 chain TX)

All EC operations use SS512's G1 for consistency with FLEX-DIAM and the
other baselines.
"""

from __future__ import annotations

import hashlib
import os
import statistics
import time

from charm.toolbox.pairinggroup import G1, ZR, PairingGroup

# Same curve as FLEX-DIAM (FLEX_CURVE env var, default BN254). Wang is EC/field
# only (no pairings), so any curve works.
_CURVE = os.environ.get("FLEX_CURVE", "BN254")


_group: PairingGroup | None = None
_g = None


def _ensure_setup() -> None:
    global _group, _g
    if _group is None:
        _group = PairingGroup(_CURVE)
        _g = _group.random(G1)


# ---------------------------------------------------------------------------
# Fig 4 cost-dominant op: chameleon-hash forge per revocation
# ---------------------------------------------------------------------------


def revoke_one_ns() -> int:
    """One revocation: 3 * T_sm + T_h + T_pa."""
    _ensure_setup()
    # Pre-generate inputs outside the timer
    a = _group.random(ZR)
    b = _group.random(ZR)
    c = _group.random(ZR)

    t0 = time.perf_counter_ns()
    # 3 EC scalar multiplications
    P1 = _g ** a
    P2 = _g ** b
    P3 = _g ** c
    # 1 EC point addition
    P_sum = P1 * P2
    # 1 hash
    _ = hashlib.sha256(_group.serialize(P_sum) + _group.serialize(P3)).digest()
    return time.perf_counter_ns() - t0


def measure_revocation_cumulative(N: int, M_users: int = 1000) -> dict:
    """Total time for N cumulative revocations (FULL execution).

    For Wang, there's no per-user witness redistribution — the revocation list
    lives on the blockchain and remaining users just query it. So cumulative
    cost is N * per-op. M_users is accepted for API symmetry but unused.
    Kept for validation against the composed estimate (revocation_cost_ms).
    """
    _ensure_setup()
    ts = [revoke_one_ns() for _ in range(N)]
    total = sum(ts)
    return {
        "scheme": "Ref [28]",
        "N": N,
        "M_users": M_users,
        "total_ns": total,
        "total_ms": total / 1e6,
        "mean_per_op_ms": (total / N) / 1e6,
        "p10_ms": sorted(ts)[max(0, N // 10)] / 1e6,
        "p90_ms": sorted(ts)[min(N - 1, (N * 9) // 10)] / 1e6,
    }


def revocation_cost_ms(N: int, M_users: int = 1000, samples: int = 30) -> float:
    """Composed post-revocation maintenance: N chameleon-hash forges.

    Wang has no per-user redistribution (remaining users query the on-chain
    CRL), so cost is N * forge-unit. Forge unit measured over `samples` reps.
    M_users accepted for API symmetry but unused.
    """
    _ensure_setup()
    forge = statistics.mean([revoke_one_ns() / 1e6 for _ in range(samples)])
    return forge * N


# ---------------------------------------------------------------------------
# Fig 5 cost-dominant op: per-record certificateless verification
# ---------------------------------------------------------------------------


def cross_domain_verify_one_ns() -> int:
    """T_V^CL: certificateless verify = ~3 EC scalar mults + 1 hash + 1 point add."""
    _ensure_setup()
    # Pre-gen
    sig1 = _group.random(ZR)
    sig2 = _group.random(ZR)
    pk_x = _group.random(ZR)
    pk_y = _group.random(ZR)

    t0 = time.perf_counter_ns()
    # Reconstruct the verification check: c'*P =? X*D + R + h0(...)*P_pub
    P_pub = _g ** _group.init(ZR, 7)  # static system pubkey
    R = _g ** sig1
    X = _g ** sig2
    h0 = _group.init(ZR, int.from_bytes(hashlib.sha256(b"id|R|X").digest(), "big") % (2 ** 250))
    rhs = (X ** pk_x) * R * (P_pub ** h0)
    lhs = _g ** pk_y
    # Equality check (formal; cost is dominated by the mults above)
    _ = (lhs == rhs)
    return time.perf_counter_ns() - t0


def auth_verify_one_ns() -> int:
    """Fig 2 (authorization throughput) — server-side verification per request.

    Table III auth row: T_CL^S + T_CL^V + T_BC. Signature generation runs on
    the requester's device; the server pays the certificateless verification
    (the T_BC read is charged by the driver via chain_meter).
    """
    return cross_domain_verify_one_ns()


def measure_share_cumulative(N: int) -> dict:
    """Total per-record verification time for N cross-domain shares.

    Excludes T_BC (chain TX) — the measurement driver adds it on Day 4.
    """
    _ensure_setup()
    ts = [cross_domain_verify_one_ns() for _ in range(N)]
    total = sum(ts)
    return {
        "scheme": "Ref [28]",
        "N": N,
        "total_ns": total,
        "total_ms": total / 1e6,
        "mean_per_op_ms": (total / N) / 1e6,
    }


# ---------------------------------------------------------------------------
# V3 role split for the revised Experiments 2 and 3. The operations are the
# ones defined above (unchanged from V2); only WHO pays them is separated.
# ---------------------------------------------------------------------------


def client_auth_one_ns() -> int:
    """Client side of one CAMS cross-domain authentication.

    Wang Table I, row "Ours", client computational overhead:
    3*T_pa + 4*T_h + 6*T_sm."""
    _ensure_setup()
    ks = [_group.random(ZR) for _ in range(6)]

    t0 = time.perf_counter_ns()
    pts = [_g ** k for k in ks]                       # 6 scalar multiplications
    acc = pts[0] * pts[1]                             # 3 point additions
    acc = acc * pts[2]
    acc = acc * pts[3]
    d = _group.serialize(acc)
    for p in (pts[4], pts[5], acc, pts[0]):           # 4 hashes
        d = hashlib.sha256(d + _group.serialize(p)).digest()
    return time.perf_counter_ns() - t0


def authority_revoke_ns(N: int) -> int:
    """Experiment 2 — the authority nodes revoke N identities: N chameleon-hash
    forges (3*T_sm + T_h + T_pa each), fully executed. Broadcasting the
    transaction on the primary chain is charged by the driver."""
    _ensure_setup()
    return sum(revoke_one_ns() for _ in range(N))


def user_maintenance_ns(N: int) -> int:
    """Experiment 3 — CAMS has no per-user update: revoked identities sit in the
    on-chain blacklist tree that the verifier queries."""
    return 0


def access_auth_ns() -> int:
    """Experiment 3 — one cross-domain authentication, both ends: client side
    (Table I) + server-side certificateless verification. The server's on-chain
    blacklist / public-key query is charged by the driver."""
    return client_auth_one_ns() + auth_verify_one_ns()
