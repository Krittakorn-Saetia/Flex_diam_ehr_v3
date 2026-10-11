"""baselines.li — Ref [24] Li et al. 2026, TII.

"SRAA: A Secure and Revocable Access Authentication Scheme in Cross-Domain
Vehicular Twin Networks", IEEE TII, May 2026.

Revocation (SRAA Section IV.C.5, "DT Revocation Phase") is implemented in full,
with a real bivariate polynomial, so that a legitimate twin really recovers the
update factor and a revoked twin really cannot:

  Gateway (Step 1)
      u <-$ Z_q
      Phi(theta) = prod_{i<=m} (theta - MID_i)              (m revoked twins)
      Psi(theta) = u*Phi(theta) + f(theta, Phi(theta))      (broadcast with Phi)
      f*(x, y)   = u * f(x, y)                              (new function)
  Twin DT_i (Step 2), holding g_i(y) = f(PID_i, y)
      u = (Psi(PID_i) - g_i(Phi(PID_i))) / Phi(PID_i)
      g_i*(y) = u * g_i(y)
  A revoked twin has Phi(MID) = 0 and cannot divide, so it never learns u.

f is the symmetric bivariate polynomial of degree t = 100 in each variable that
SRAA uses (Section VI.A). Psi must be broadcast in expanded form, because a twin
does not know f; it therefore has t*(m+1)+1 coefficients, and expanding it is
the gateway's dominant cost. V2 left that expansion and the twin's evaluation of
Psi out of the model; both are executed here.

How a workload of N revocations is grouped into update rounds is the gateway's
choice. The expansion grows with the square of the batch size m, so small
batches are far cheaper for the gateway. SRAA_BATCH sets m (default 1: one
update round per revoked twin, which is also how Refs [20] and [28] are charged
— per revocation). SRAA_BATCH=0 means a single round containing all N.

Authentication (SRAA Section IV.C.3-4) is unchanged from V2.
"""

from __future__ import annotations

import hashlib
import os
import time

from charm.toolbox.pairinggroup import G1, ZR, PairingGroup

# Same curve as FLEX-DIAM (FLEX_CURVE, default BN254). SRAA needs only the field
# and an elliptic-curve group, no pairings.
_CURVE = os.environ.get("FLEX_CURVE", "BN254")
T_DEG = 100  # bivariate polynomial degree (SRAA Section VI.A)

_group: PairingGroup | None = None
_g = None
_zero = _one = None
_f = None  # the gateway's current authentication polynomial, (T+1) x (T+1), symmetric


class Revoked(Exception):
    """Phi(PID) = 0: the twin is in the revocation polynomial and cannot update."""


def _ensure_setup() -> None:
    global _group, _g, _zero, _one
    if _group is None:
        _group = PairingGroup(_CURVE)
        _g = _group.random(G1)
        _zero = _group.init(ZR, 0)
        _one = _group.init(ZR, 1)


def batch_size(n: int) -> int:
    """Revoked twins per update round for a workload of n (SRAA_BATCH)."""
    m = int(os.environ.get("SRAA_BATCH", "1"))
    return n if m <= 0 else min(m, n)


# ---------------------------------------------------------------------------
# Polynomial helpers (coefficients in ascending order over Z_q)
# ---------------------------------------------------------------------------


def new_f() -> list:
    """A fresh symmetric bivariate polynomial f(x, y) = sum a[i][j] x^i y^j."""
    _ensure_setup()
    a = [[None] * (T_DEG + 1) for _ in range(T_DEG + 1)]
    for i in range(T_DEG + 1):
        for j in range(i, T_DEG + 1):
            a[i][j] = a[j][i] = _group.random(ZR)
    return a


def horner(coeffs: list, x):
    acc = coeffs[-1]
    for c in reversed(coeffs[:-1]):
        acc = acc * x + c
    return acc


def slice_of(f: list, pid) -> list:
    """g_i(y) = f(PID_i, y): the authentication function a twin receives."""
    return [horner([f[i][n] for i in range(T_DEG + 1)], pid) for n in range(T_DEG + 1)]


def _phi_coeffs(mids: list) -> list:
    """Phi(theta) = prod (theta - MID_i), monic."""
    coeffs = [_one]
    for mid in mids:
        new = [_zero] + coeffs                      # theta * Phi
        for i, c in enumerate(coeffs):
            new[i] = new[i] - c * mid
        coeffs = new
    return coeffs


def _mul_by_monic(acc: list, phi: list) -> list:
    """acc(theta) * Phi(theta) for monic Phi of degree m."""
    m = len(phi) - 1
    out = [_zero] * m + acc                         # theta^m * acc
    for j in range(m):
        pj = phi[j]
        for i, a_i in enumerate(acc):
            out[i + j] = out[i + j] + a_i * pj
    return out


# ---------------------------------------------------------------------------
# The revocation phase
# ---------------------------------------------------------------------------


def gateway_round(f: list, mids: list):
    """SRAA Step 1 for one update round revoking `mids`.

    Returns (u, Phi, Psi) and replaces f by f* = u*f in place."""
    u = _group.random(ZR)
    phi = _phi_coeffs(mids)
    # f(theta, Phi(theta)) = sum_n c_n(theta) Phi(theta)^n with
    # c_n(theta) = sum_i a[i][n] theta^i, expanded by Horner's rule in Phi.
    acc = [f[i][T_DEG] for i in range(T_DEG + 1)]
    for n in range(T_DEG - 1, -1, -1):
        acc = _mul_by_monic(acc, phi)
        for i in range(T_DEG + 1):
            acc[i] = acc[i] + f[i][n]
    for j, p in enumerate(phi):                     # Psi = u*Phi + f(theta, Phi)
        acc[j] = acc[j] + u * p
    for i in range(T_DEG + 1):                      # f* = u * f (symmetric half)
        row = f[i]
        for j in range(i, T_DEG + 1):
            v = u * row[j]
            row[j] = v
            f[j][i] = v
    return u, phi, acc


def twin_round(g_i: list, pid, phi: list, psi: list):
    """SRAA Step 2 for one twin. Returns (u, g_i*). Raises Revoked if Phi(PID)=0."""
    phi_pid = horner(phi, pid)
    if phi_pid == _zero:
        raise Revoked()
    g_val = horner(g_i, phi_pid)
    psi_pid = horner(psi, pid)
    u = (psi_pid - g_val) * (phi_pid ** -1)
    return u, [u * c for c in g_i]


def selftest() -> None:
    """Functional check of the revocation phase with real polynomials."""
    _ensure_setup()
    f = new_f()
    pid = _group.random(ZR)
    g_i = slice_of(f, pid)
    for m in (1, 3):
        mids = [_group.random(ZR) for _ in range(m)]
        g_bad = slice_of(f, mids[0])                # a twin that is being revoked
        u, phi, psi = gateway_round(f, mids)
        if len(psi) != T_DEG * (m + 1) + 1:
            raise AssertionError("unexpected degree of Psi")
        u_rec, g_new = twin_round(g_i, pid, phi, psi)
        if u_rec != u:
            raise AssertionError("legitimate twin did not recover u")
        if g_new != slice_of(f, pid):
            raise AssertionError("updated g_i is not the slice of f*")
        try:
            twin_round(g_bad, mids[0], phi, psi)
            raise AssertionError("revoked twin was able to update")
        except Revoked:
            pass
        g_i = g_new


# ---------------------------------------------------------------------------
# What the experiments charge
# ---------------------------------------------------------------------------


def authority_revoke_ns(N: int) -> int:
    """Experiment 2 — the gateway revokes N twins in ceil(N/m) update rounds,
    every round fully executed on the real polynomial (Phi, the expansion of
    Psi, and f* = u*f). SRAA broadcasts through the RTA; the scheme has no
    blockchain, so the driver adds no confirmation."""
    global _f
    if N <= 0:
        return 0
    _ensure_setup()
    if _f is None:
        _f = new_f()
    m = batch_size(N)
    total = 0
    for start in range(0, N, m):
        mids = [_group.random(ZR) for _ in range(min(m, N - start))]
        t0 = time.perf_counter_ns()
        gateway_round(_f, mids)
        total += time.perf_counter_ns() - t0
    return total


def user_maintenance_ns(N: int) -> int:
    """Experiment 3 — ONE unaffected twin processes the update rounds of N
    revocations (Step 2 once per round).

    The twin's work depends only on the SIZES of Phi and Psi, so the rounds are
    timed on polynomials of exactly those sizes with random coefficients;
    producing the real ones is the gateway's cost, measured in Experiment 2.
    selftest() checks the same code on real polynomials."""
    if N <= 0:
        return 0
    _ensure_setup()
    m = batch_size(N)
    pid = _group.random(ZR)
    g_i = [_group.random(ZR) for _ in range(T_DEG + 1)]
    cache: dict[int, tuple] = {}
    total = 0
    for start in range(0, N, m):
        b = min(m, N - start)
        if b not in cache:
            phi = [_group.random(ZR) for _ in range(b)] + [_one]
            psi = [_group.random(ZR) for _ in range(T_DEG * (b + 1) + 1)]
            cache[b] = (phi, psi)
        phi, psi = cache[b]
        t0 = time.perf_counter_ns()
        _u, g_i = twin_round(g_i, pid, phi, psi)
        total += time.perf_counter_ns() - t0
    return total


def access_auth_ns() -> int:
    """Experiment 3 — one cross-domain access authentication, both ends: key
    agreement (twin) + verification and local revocation check (gateway)."""
    return cross_domain_share_one_ns() + auth_verify_one_ns()


# ---------------------------------------------------------------------------
# Authentication — unchanged from V2
# ---------------------------------------------------------------------------


def cross_domain_share_one_ns() -> int:
    """Twin side of one access: ~3-4 EC scalar mults + 2 hashes."""
    _ensure_setup()
    a = _group.random(ZR)
    sk = _group.random(ZR)
    pk_target_exp = _group.random(ZR)
    b = _group.random(ZR)

    t0 = time.perf_counter_ns()
    A = _g ** a
    K_shared = (_g ** pk_target_exp) ** (a * sk)
    h1 = hashlib.sha256(_group.serialize(K_shared) + _group.serialize(A)).digest()
    # Second message direction
    B = _g ** b
    K_check = B ** (a * sk)
    _h2 = hashlib.sha256(_group.serialize(K_check) + h1).digest()
    return time.perf_counter_ns() - t0


def auth_verify_one_ns() -> int:
    """Experiment 1 — server-side verification of one SRAA request:
    bivariate-slice evaluation (degree t, Horner), chameleon-hash
    reconstruction (2 EC scalar mults + point add + hash), signature check via
    the shared secret, local revocation-state check. No blockchain."""
    _ensure_setup()
    # Pre-generate inputs outside the timer
    pid = _group.random(ZR)
    gi_coeffs = [_group.random(ZR) for _ in range(T_DEG + 1)]
    m = _group.random(ZR)
    r_ch = _group.random(ZR)
    h_pt = _g ** _group.init(ZR, 5)  # second chameleon base (static)

    t0 = time.perf_counter_ns()
    # bivariate-slice eval g*_i(PID_j), Horner over degree-100 coefficients
    val = gi_coeffs[-1]
    for c in reversed(gi_coeffs[:-1]):
        val = val * pid + c
    # chameleon hash reconstruction ch = g^m * h^r
    ch = (_g ** m) * (h_pt ** r_ch)
    pid_hat = hashlib.sha256(_group.serialize(ch)).digest()
    # signature check via shared authentication value (hash compare)
    sig_ok = hashlib.sha256(_group.serialize(val) + pid_hat).digest()
    # local revocation-state check (T_REV)
    _rev = hashlib.sha256(sig_ok + b"rev-state").digest()
    return time.perf_counter_ns() - t0
