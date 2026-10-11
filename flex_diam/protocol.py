"""flex_diam.protocol — FLEX-DIAM Phases 1-5, equation by equation.

Every method names the paper step and equation it implements. All roles
(authorization service, delegation service, KMS, proxy gateway, cloud, doctor)
run in this one process, but each role performs its OWN blockchain read where
the paper says that role checks the current scoped state.

`FlexDiam.access()` runs one unaffected doctor's full path

    authorization (Phase 3) -> delegation (Phase 4) -> retrieval (Phase 5 Step 1)

and times it from authorization-request submission to the release of the
transformed key material, which is the latency Experiment 3 reports.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from flex_diam import zkp
from flex_diam.abpre import ABPRE
from flex_diam.chain import ScopedState
from flex_diam.hashing import H, encode, field_of_digest, field_of_str

_ECDSA = ec.ECDSA(hashes.SHA256())
# AEAD of eq. 9 / 48. Fig. 1 of the paper labels the EHR encryption
# "ChaCha20 Poly1305", so that is the default; FLEX_AEAD=aesgcm selects
# AES-256-GCM. Both take a 256-bit key (the paper's K_AES) and a 96-bit nonce.
_AEAD = AESGCM if os.environ.get("FLEX_AEAD", "chacha20poly1305") == "aesgcm" else ChaCha20Poly1305
_ATTR_RE = re.compile(r"^[A-Z][A-Z0-9]*$")


class Rejected(Exception):
    """A validation predicate of the protocol evaluated to 0."""

    def __init__(self, stage: str, reason: str):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


# ---------------------------------------------------------------------------
# Identities (Phase 1 Steps 2-3)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Entity:
    kind: str            # "patient" | "doctor" | "hospital"
    did: str             # DID_E = H(pk_E)                                (eq. 3)
    pk: bytes
    sk: ec.EllipticCurvePrivateKey

    @property
    def pk_hex(self) -> str:
        return self.pk.hex()


@dataclasses.dataclass
class Doctor(Entity):
    hospital_did: str = ""
    attrs: list = dataclasses.field(default_factory=list)   # Attr_D       (eq. 4)
    vc: zkp.VC | None = None                                # VC_D         (eq. 5)
    sk_abe: dict | None = None                              # SK_D         (eq. 6)


def new_entity(kind: str) -> Entity:
    """(pk_E, sk_E) and DID_E = H(pk_E) (eq. 2-3)."""
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return Entity(kind, "did:flex:" + H(pk).hex()[:32], pk, sk)


# ---------------------------------------------------------------------------
# Protocol objects
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Req:
    """Req_i = <DID_Di, DID_Hs, DID_Hd, cid, pid> (eq. 15)."""

    did_d: str
    did_hs: str
    did_hd: str
    cid: str
    pid: str

    def fields(self):
        return (self.did_d, self.did_hs, self.did_hd, self.cid, self.pid)


def scoped_digest(req: Req, sigma) -> str:
    """rho = H(DID_Di || DID_Hs || DID_Hd || cid || pid || sigma) (eq. 17/33/44)."""
    return H(*req.fields(), tuple(sigma)).hex()


@dataclasses.dataclass(frozen=True)
class AuthTok:
    """AuthTok_i = Sign_skSC(DID_Di||DID_Hs||DID_Hd||cid||pid||rho_i||t_exp) (eq. 28)."""

    did_d: str
    did_hs: str
    did_hd: str
    cid: str
    pid: str
    rho: str
    t_exp: int
    sig: bytes = b""

    def body(self) -> bytes:
        return encode("AuthTok", self.did_d, self.did_hs, self.did_hd,
                      self.cid, self.pid, self.rho, self.t_exp)

    def digest(self) -> bytes:
        return H(self.body(), self.sig)


@dataclasses.dataclass(frozen=True)
class DAC:
    """DAC_i = Sign_skSC(DID_Di||DID_Hs||DID_Hd||cid||pid||rho_cur||t_del) (eq. 35)."""

    did_d: str
    did_hs: str
    did_hd: str
    cid: str
    pid: str
    rho: str
    t_del: int
    sig: bytes = b""

    def body(self) -> bytes:
        return encode("DAC", self.did_d, self.did_hs, self.did_hd,
                      self.cid, self.pid, self.rho, self.t_del)

    def digest(self) -> bytes:
        return H(self.body(), self.sig)


@dataclasses.dataclass
class EHRRecord:
    """CT = <CT_m, CT_k> (eq. 12) with its metadata (eq. 13-14)."""

    cid: str
    nonce: bytes
    ct_m: bytes
    ct_k: dict
    policy_attrs: list
    policy: str
    pid: str
    did_p: str
    did_h: str
    com: str


@dataclasses.dataclass
class Trace:
    """Stage timings (ms) of one access."""

    stages: dict = dataclasses.field(default_factory=dict)
    chain_read_ms: float = 0.0
    chain_write_ms: float = 0.0
    released_ms: float = 0.0          # request submission -> release (Exp 3 metric)
    post_release: dict = dataclasses.field(default_factory=dict)
    plaintext: bytes = b""       # M recovered after release (correctness check)


def conjunction(attrs: list) -> str:
    """Charm policy string of a conjunctive policy A."""
    for a in attrs:
        if not _ATTR_RE.match(a):
            raise ValueError(f"attribute {a!r} must match [A-Z][A-Z0-9]*")
    canon = sorted(set(attrs))
    return canon[0] if len(canon) == 1 else "(" + " and ".join(canon) + ")"


class FlexDiam:
    """One FLEX-DIAM deployment: trusted services plus the shared ledger."""

    def __init__(self, ledger, work_dir: str, token_ttl: int = 600, dac_ttl: int = 120,
                 b_max: int = 5000, delta_b_ms: float = 0.0):
        self.ledger = ledger
        self.work_dir = work_dir
        self.token_ttl = token_ttl
        self.dac_ttl = dac_ttl
        self.b_max = b_max            # maximum batch size b_max
        self.delta_b_ms = delta_b_ms  # verification window Delta_b
        # Phase 1 Step 1 — (PK, MSK) <- CPABE.Setup(1^lambda)               (eq. 1)
        self.abpre = ABPRE()
        self.pk, self.msk = self.abpre.setup()
        # signing key of the authorization / delegation services (sk_SC, pk_SC)
        self.sk_sc = ec.generate_private_key(ec.SECP256R1())
        self.pk_sc = self.sk_sc.public_key()
        self.cloud: dict[str, EHRRecord] = {}        # encrypted storage CS
        self.transformed: dict[tuple, dict] = {}     # (cid, DID_D) -> CT~_{k,Hd}
        self.entities: dict[str, Entity] = {}

    # ----- Phase 1: system setup and identity initialization -----------------

    def register(self, kind: str) -> Entity:
        """Step 2 — DID registration (eq. 2-3)."""
        e = new_entity(kind)
        self.ledger.register_did(e.did, e.pk_hex)
        self.entities[e.did] = e
        return e

    def register_many(self, kind: str, n: int) -> list:
        """Step 2 for n entities, registered in one setup transaction."""
        es = [new_entity(kind) for _ in range(n)]
        self.ledger.register_dids([(e.did, e.pk_hex) for e in es])
        for e in es:
            self.entities[e.did] = e
        return es

    def enroll_doctor(self, hospital: Entity, attrs: list, t_exp: int | None = None) -> Doctor:
        """Steps 2-3 — DID, VC_D (eq. 4-5) and SK_D (eq. 6) of one doctor."""
        e = new_entity("doctor")
        self.ledger.register_did(e.did, e.pk_hex)
        t_exp = t_exp if t_exp is not None else int(time.time()) + 365 * 86400
        d = Doctor(e.kind, e.did, e.pk, e.sk, hospital_did=hospital.did, attrs=list(attrs))
        d.vc = zkp.issue_vc(d.attrs, field_of_str(d.did), t_exp)
        d.sk_abe = self.abpre.keygen(self.pk, self.msk, d.attrs)
        self.entities[d.did] = d
        return d

    # ----- Phase 2: EHR encryption and policy registration ------------------

    def encrypt_ehr(self, patient: Entity, hospital: Entity, m: bytes, policy_attrs: list) -> EHRRecord:
        k_aes = secrets.token_bytes(32)                       # Step 1 (eq. 8)
        nonce = secrets.token_bytes(12)
        ct_m = _AEAD(k_aes).encrypt(nonce, m, None)           # Step 2 (eq. 9)
        policy = conjunction(policy_attrs)                    # Step 3: policy A
        pid = zkp.policy_pid(policy_attrs)                    #         pid (eq. 10)
        ct_k = self.abpre.encrypt_key(self.pk, k_aes, policy)  # Step 4 (eq. 11)
        cid = "cid:" + secrets.token_hex(16)
        # Step 5 — Com = H(cid || DID_P || DID_H || pid || H(CT))   (eq. 13-14)
        h_ct = H(nonce, ct_m, self.abpre.group.serialize(ct_k["abe"]["C_tilde"]),
                 ct_k["wrap"], ct_k["kc"])
        com = H(cid, patient.did, hospital.did, pid, h_ct).hex()
        self.ledger.register_metadata(cid, patient.did, hospital.did, pid, com)
        rec = EHRRecord(cid, nonce, ct_m, ct_k, sorted(set(policy_attrs)), policy, pid,
                        patient.did, hospital.did, com)
        self.cloud[cid] = rec
        return rec

    # ----- scoped revocation (eq. 7, eq. 50) --------------------------------

    def revoke_user(self, did: str):
        """RL <- RL U {DID_Di}, v_Di <- v_Di + 1."""
        return self.ledger.revoke_user(did)

    def revoke_users(self, dids):
        return self.ledger.revoke_users(dids)

    def revoke_domain(self, did_h: str):
        return self.ledger.revoke_domain(did_h)

    def revoke_policy(self, pid: str):
        return self.ledger.revoke_policy(pid)

    # ----- shared helpers ----------------------------------------------------

    def _resolve(self, req: Req):
        """Read the current scoped versions and RL bits from the blockchain."""
        return self.ledger.resolve_state(*req.fields())

    def _sign(self, body: bytes) -> bytes:
        return self.sk_sc.sign(body, _ECDSA)

    def _verify(self, body: bytes, sig: bytes) -> bool:
        try:
            self.pk_sc.verify(sig, body, _ECDSA)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def _not_revoked(st: ScopedState) -> bool:
        return not (st.rl_d or st.rl_hs or st.rl_hd)

    # ----- Phase 3: authentication and batch authorization ------------------

    def valid_rev(self, req: Req, st: ScopedState) -> bool:
        """Valid_rev (eq. 18)."""
        return self._not_revoked(st) and req.pid == st.pid_ct

    def authz_resolve(self, req: Req):
        """Step 1 — sigma_i from the blockchain (eq. 16), rho_i (eq. 17)."""
        st, ms = self._resolve(req)
        return st, scoped_digest(req, st.sigma), ms

    def zk_prove(self, doctor: Doctor, req: Req, rho: str, policy_attrs: list, tag: str = "p"):
        """Step 3 — pi_i <- ZK.Prove(PK_zk, x_i, w_i), x_i = <DID, pid, rho> (eq. 19-22)."""
        rho_f = field_of_digest(bytes.fromhex(rho))
        return zkp.prove(doctor.vc, req.pid, rho_f, policy_attrs, self.work_dir, tag)

    def expected_public(self, req: Req, rho: str) -> list:
        """x_i as the verifier derives it from the request and its own rho_i."""
        return [str(field_of_str(req.did_d)), str(int(req.pid, 16)),
                str(field_of_digest(bytes.fromhex(rho)))]

    def issue_token(self, req: Req, rho: str) -> AuthTok:
        """Step 5 — AuthTok_i (eq. 28)."""
        tok = AuthTok(*req.fields(), rho, int(time.time()) + self.token_ttl)
        return dataclasses.replace(tok, sig=self._sign(tok.body()))

    def anchor_batch(self, bid: str, tokens: list):
        """Step 6 — BatchCom = H(bid || H(AuthTok_i)...) anchored on chain (eq. 29-30)."""
        batch_com = H(bid, *[t.digest() for t in tokens]).hex()
        return self.ledger.anchor_batch(bid, batch_com, int(time.time()))

    def authorize_batch(self, submissions: list) -> list:
        """Steps 1-6 for a batch of concurrent requests.

        `submissions` is [(doctor, Req, policy_attrs), ...]. Returns one AuthTok
        or Rejected per request; accepted tokens share one batch audit anchor."""
        results: list = [None] * len(submissions)
        pending = []  # (index, req, rho, proof_path, public_path)
        for i, (doctor, req, policy_attrs) in enumerate(submissions):
            st, rho, _ = self.authz_resolve(req)
            if not self.valid_rev(req, st):                       # Step 2
                results[i] = Rejected("p3_s2", "Valid_rev = 0")
                continue
            try:
                pf, pub, _ = self.zk_prove(doctor, req, rho, policy_attrs, tag=f"b{i}")
            except RuntimeError as e:
                results[i] = Rejected("p3_s3", f"no valid witness: {str(e)[:80]}")
                continue
            pending.append((i, req, rho, pf, pub))
        if not pending:
            return results
        if len(pending) > self.b_max:
            raise ValueError("batch exceeds b_max")
        if self.delta_b_ms > 0:
            time.sleep(self.delta_b_ms / 1000.0)  # the batch closes after Delta_b
        bid = "bid:" + secrets.token_hex(16)
        valid, _, _ = zkp.batch_verify(bid, [(pf, pub) for _, _, _, pf, pub in pending])  # Step 4
        tokens = []
        for (i, req, rho, _pf, pub), ok in zip(pending, valid):
            with open(pub) as f:
                bound = json.load(f) == self.expected_public(req, rho)
            if ok and bound:                                      # Valid_auth (eq. 27)
                results[i] = self.issue_token(req, rho)
                tokens.append(results[i])
            else:
                results[i] = Rejected("p3_s4", "Valid_zk = 0")
        if tokens:
            self.anchor_batch(bid, tokens)                        # Step 6
        return results

    # ----- Phase 4: authorization-bound cross-domain delegation -------------

    def valid_del(self, req: Req, rho_claimed: str, tok: AuthTok, st: ScopedState, rho_cur: str,
                  now: int) -> tuple:
        """Valid_del (eq. 34)."""
        checks = (
            ("Verify(AuthTok)", self._verify(tok.body(), tok.sig)),
            ("t < t_exp", now < tok.t_exp),
            ("DID_Di,tok", tok.did_d == req.did_d),
            ("DID_Hs,tok", tok.did_hs == req.did_hs),
            ("DID_Hd,tok", tok.did_hd == req.did_hd),
            ("cid_tok", tok.cid == req.cid),
            ("pid_tok", tok.pid == req.pid),
            ("pid = pid_CT", req.pid == st.pid_ct),
            ("rho_tok = rho_cur", tok.rho == rho_cur and rho_claimed == tok.rho),
            ("not in RL", self._not_revoked(st)),
        )
        failed = [name for name, ok in checks if not ok]
        return (not failed), failed

    def issue_dac(self, req: Req, rho_cur: str, tok: AuthTok) -> DAC:
        """Step 3 — DAC_i (eq. 35), t_del <= t_exp."""
        t_del = min(int(time.time()) + self.dac_ttl, tok.t_exp)
        dac = DAC(*req.fields(), rho_cur, t_del)
        return dataclasses.replace(dac, sig=self._sign(dac.body()))

    def _dac_current(self, req: Req, dac: DAC, stage: str):
        """A role validates the DAC and its binding to the CURRENT scoped state."""
        st, ms = self._resolve(req)
        rho_cur = scoped_digest(req, st.sigma)
        ok = (self._verify(dac.body(), dac.sig) and int(time.time()) < dac.t_del
              and dac.rho == rho_cur and self._not_revoked(st)
              and (dac.did_d, dac.did_hs, dac.did_hd, dac.cid, dac.pid) == req.fields())
        if not ok:
            raise Rejected(stage, "DAC invalid, expired, or not bound to the current scoped state")
        return rho_cur, ms

    @staticmethod
    def context(req: Req, rho_cur: str, dac: DAC) -> bytes:
        """ctx_i = H(DID_Di||DID_Hs||DID_Hd||cid||pid||rho_cur||H(DAC_i)) (eq. 36/46)."""
        return H(*req.fields(), rho_cur, dac.digest())

    def kms_rekeygen(self, req: Req, dac: DAC):
        """Step 4 — rk <- ReKeyGen(MSK, pk_Hd, ctx_i) (eq. 36-37)."""
        rho_cur, ms = self._dac_current(req, dac, "p4_s4")
        ctx = self.context(req, rho_cur, dac)
        pk_hd = self.entities[req.did_hd].pk
        policy = self.cloud[req.cid].policy  # A resolved from the authenticated metadata
        return self.abpre.rekeygen(self.pk, self.msk, pk_hd, ctx, policy), ctx, ms

    def proxy_reenc(self, req: Req, dac: DAC, rk: dict, ctx: bytes):
        """Step 5 — CT'_k <- ReEnc(rk, CT_k, ctx_i); CT~ = <CT'_k, ctx_i, DAC_i> (eq. 40-41)."""
        _, ms = self._dac_current(req, dac, "p4_s5")
        ct_kp = self.abpre.reenc(self.pk, rk, self.cloud[req.cid].ct_k, ctx)
        bundle = {"ct_kp": ct_kp, "ctx": ctx, "dac": dac}
        self.transformed[(req.cid, req.did_d)] = bundle  # forwarded to the cloud
        return bundle, ms

    def delegation_audit(self, req: Req, rho_cur: str, dac: DAC, tok: AuthTok):
        """Step 6 — DelCom_i recorded with t_del (eq. 42)."""
        del_com = H(*req.fields(), rho_cur, dac.digest(), tok.digest()).hex()
        return self.ledger.record_delegation(del_com, dac.t_del)

    # ----- Phase 5: authorized retrieval and decryption ---------------------

    def valid_acc(self, req: Req, tok: AuthTok, dac: DAC, st: ScopedState, rho_cur: str,
                  now: int) -> tuple:
        """Valid_acc (eq. 45)."""
        checks = (
            ("Verify(AuthTok)", self._verify(tok.body(), tok.sig)),
            ("Verify(DAC)", self._verify(dac.body(), dac.sig)),
            ("t < t_exp", now < tok.t_exp),
            ("t < t_del", now < dac.t_del),
            ("DID_Di", tok.did_d == req.did_d and dac.did_d == req.did_d),
            ("DID_Hs", tok.did_hs == req.did_hs and dac.did_hs == req.did_hs),
            ("DID_Hd", tok.did_hd == req.did_hd and dac.did_hd == req.did_hd),
            ("cid", tok.cid == req.cid and dac.cid == req.cid),
            ("pid", tok.pid == req.pid and dac.pid == req.pid),
            ("pid = pid_CT", req.pid == st.pid_ct),
            ("rho_tok = rho_cur", tok.rho == rho_cur),
            ("rho_DAC = rho_cur", dac.rho == rho_cur),
            ("not in RL", self._not_revoked(st)),
        )
        failed = [name for name, ok in checks if not ok]
        return (not failed), failed

    def cloud_release(self, req: Req, tok: AuthTok, dac: DAC):
        """Step 1 — final current-state validation, then release (eq. 43-45)."""
        st, ms = self._resolve(req)
        rho_cur = scoped_digest(req, st.sigma)
        ok, failed = self.valid_acc(req, tok, dac, st, rho_cur, int(time.time()))
        if not ok:
            raise Rejected("p5_s1", "Valid_acc = 0: " + ", ".join(failed))
        bundle = self.transformed.get((req.cid, req.did_d))
        if bundle is None or bundle["dac"] != dac:
            raise Rejected("p5_s1", "no transformed key material for this DAC")
        return self.cloud[req.cid], bundle, rho_cur, ms

    def doctor_recover(self, doctor: Doctor, req: Req, rec: EHRRecord, bundle: dict, rho_cur: str):
        """Steps 2-3 — ctx* check, K_AES <- ReDec (eq. 46-47), M <- AEAD.Dec (eq. 48)."""
        ctx_star = self.context(req, rho_cur, bundle["dac"])
        if ctx_star != bundle["ctx"]:
            raise Rejected("p5_s2", "ctx_i != ctx_i*")
        k_aes = self.abpre.redec(self.pk, doctor.sk_abe, bundle["ct_kp"], ctx_star)
        if k_aes is None:
            raise Rejected("p5_s2", "ReDec = bottom")
        try:
            return _AEAD(k_aes).decrypt(rec.nonce, rec.ct_m, None)
        except InvalidTag:
            raise Rejected("p5_s3", "AEAD authentication failed") from None

    def access_audit(self, req: Req, rho_cur: str, tok: AuthTok, dac: DAC):
        """Step 4 — AccCom_i recorded on chain (eq. 49)."""
        t_acc = int(time.time())
        acc_com = H(*req.fields(), rho_cur, tok.digest(), dac.digest(), t_acc).hex()
        return self.ledger.record_access(acc_com, t_acc)

    # ----- delegation + retrieval for an already-issued token ---------------

    def delegate_and_release(self, req: Req, tok: AuthTok, trace: Trace | None = None):
        """Phase 4 Steps 1-6 and Phase 5 Step 1 for token `tok`."""
        tr = trace if trace is not None else Trace()

        def stage(name, t0, read=0.0, write=0.0):
            tr.stages[name] = (time.perf_counter_ns() - t0) / 1e6
            tr.chain_read_ms += read
            tr.chain_write_ms += write

        # Phase 4 Step 2 — sigma_cur, rho_cur (eq. 32-33), Valid_del (eq. 34)
        t0 = time.perf_counter_ns()
        st, r_ms = self._resolve(req)
        rho_cur = scoped_digest(req, st.sigma)
        ok, failed = self.valid_del(req, tok.rho, tok, st, rho_cur, int(time.time()))
        stage("p4_s2_state_validation", t0, read=r_ms)
        if not ok:
            raise Rejected("p4_s2", "Valid_del = 0: " + ", ".join(failed))

        t0 = time.perf_counter_ns()
        dac = self.issue_dac(req, rho_cur, tok)                    # Step 3
        stage("p4_s3_dac_issue", t0)

        t0 = time.perf_counter_ns()
        rk, ctx, r_ms = self.kms_rekeygen(req, dac)                # Step 4
        stage("p4_s4_rekeygen", t0, read=r_ms)

        t0 = time.perf_counter_ns()
        _, r_ms = self.proxy_reenc(req, dac, rk, ctx)              # Step 5
        stage("p4_s5_reenc", t0, read=r_ms)

        t0 = time.perf_counter_ns()
        _, w_ms = self.delegation_audit(req, rho_cur, dac, tok)    # Step 6
        stage("p4_s6_delegation_audit", t0, write=w_ms)

        t0 = time.perf_counter_ns()
        rec, bundle, rho_rel, r_ms = self.cloud_release(req, tok, dac)  # Phase 5 Step 1
        stage("p5_s1_release_validation", t0, read=r_ms)
        return rec, bundle, rho_rel, dac

    # ----- one complete access (Experiment 3 unit) --------------------------

    def access(self, doctor: Doctor, rec: EHRRecord, did_hs: str, did_hd: str) -> Trace:
        """Authorization -> cross-domain delegation -> retrieval for one doctor.

        The clock starts when the authorization request is submitted and stops
        when the cloud releases the transformed key material (end of Phase 5
        Step 1). Phase 5 Steps 2-4 run afterwards and are reported separately."""
        tr = Trace()
        req = Req(doctor.did, did_hs, did_hd, rec.cid, rec.pid)

        def stage(name, t0, read=0.0, write=0.0):
            tr.stages[name] = (time.perf_counter_ns() - t0) / 1e6
            tr.chain_read_ms += read
            tr.chain_write_ms += write

        t_start = time.perf_counter_ns()

        # Phase 3 Step 1 — scoped-state resolution
        t0 = time.perf_counter_ns()
        st, rho, r_ms = self.authz_resolve(req)
        stage("p3_s1_resolve_state", t0, read=r_ms)

        # Step 2 — Valid_rev
        t0 = time.perf_counter_ns()
        ok = self.valid_rev(req, st)
        stage("p3_s2_validate", t0)
        if not ok:
            raise Rejected("p3_s2", "Valid_rev = 0")

        # Step 3 — scoped-state-bound ZKP
        t0 = time.perf_counter_ns()
        try:
            pf, pub, _ = self.zk_prove(doctor, req, rho, rec.policy_attrs)
        except RuntimeError as e:
            raise Rejected("p3_s3", f"no valid witness: {str(e)[:80]}") from None
        stage("p3_s3_zk_prove", t0)

        # Step 4 — batch verification (this window holds b = 1 request)
        t0 = time.perf_counter_ns()
        if self.delta_b_ms > 0:
            time.sleep(self.delta_b_ms / 1000.0)
        bid = "bid:" + secrets.token_hex(16)
        valid, _, _ = zkp.batch_verify(bid, [(pf, pub)])
        with open(pub) as f:
            bound = json.load(f) == self.expected_public(req, rho)
        stage("p3_s4_batch_verify", t0)
        if not (valid[0] and bound):
            raise Rejected("p3_s4", "Valid_zk = 0")

        # Step 5 — token
        t0 = time.perf_counter_ns()
        tok = self.issue_token(req, rho)
        stage("p3_s5_token_issue", t0)

        # Step 6 — batch audit registration
        t0 = time.perf_counter_ns()
        _, w_ms = self.anchor_batch(bid, [tok])
        stage("p3_s6_batch_anchor", t0, write=w_ms)

        # Phase 4 + Phase 5 Step 1
        rec_out, bundle, rho_rel, dac = self.delegate_and_release(req, tok, tr)
        tr.released_ms = (time.perf_counter_ns() - t_start) / 1e6

        # ---- after release: Phase 5 Steps 2-4 (not part of the reported latency)
        t0 = time.perf_counter_ns()
        m = self.doctor_recover(doctor, req, rec_out, bundle, rho_rel)
        tr.post_release["p5_s2_s3_recover_decrypt"] = (time.perf_counter_ns() - t0) / 1e6
        t0 = time.perf_counter_ns()
        self.access_audit(req, rho_rel, tok, dac)
        tr.post_release["p5_s4_access_audit"] = (time.perf_counter_ns() - t0) / 1e6
        tr.plaintext = m
        return tr


def default_work_dir() -> str:
    d = os.environ.get("FLEX_WORK_DIR")
    if d:
        os.makedirs(d, exist_ok=True)
        return d
    import tempfile
    return tempfile.mkdtemp(prefix="flexdiam_")
