"""flex_diam.abpre — CP-ABE (BSW07) and the context-bound ABPRE of Phase 4.

The paper fixes the interfaces but not the construction:

    (PK, MSK)  <- CPABE.Setup(1^lambda)                    (eq. 1)
    SK_D       <- CPABE.KeyGen(MSK, Attr_D)                (eq. 6)
    CT_k       <- CPABE.Enc(PK, K_AES, A)                  (eq. 11)
    rk         <- ReKeyGen(MSK, pk_Hd, ctx)                (eq. 37)
    CT'_k      <- ReEnc(rk, CT_k, ctx)                     (eq. 40)
    K_AES      <- ReDec(SK_D, CT'_k, ctx)                  (eq. 47)
    ReDec(SK_D, ReEnc(rk, CT_k, ctx), ctx') = bottom  for ctx' != ctx   (eq. 39)

Instantiation used here (recorded as an implementation choice in
PAPER_FIDELITY.md, since the paper does not give one):

  CP-ABE      Bethencourt-Sahai-Waters 2007 from Charm-Crypto. BSW07 encrypts a
              GT element, so K_AES in {0,1}^256 is carried as a hybrid KEM:
              CT_k = <BSW07.Enc(PK, R, A), K_AES xor KDF(R), kc = H("kc"||K_AES)>.

  ReKeyGen    The KMS (holder of MSK) derives a one-time BSW07 key SK* for the
              attribute set of A, blinds every component with 1/z, and encrypts
              the seed Z of z under A:
                  Z <-$ GT,  z = H_Zr(Z || ctx || pk_Hd),
                  rk = <TK = SK*^(1/z),  HDR = BSW07.Enc(PK, Z, A)>.
              (Blinded transformation key in the style of Green-Hohenberger-
              Waters outsourced decryption.)

  ReEnc       The proxy partially decrypts CT_k with TK:
                  Q = e(g,g)^(alpha*s/z),
                  CT'_k = <C~, Q, HDR, wrap, kc, pk_Hd, tau = H("tau"||ctx||Q)>.
              It never sees R or K_AES: stripping the mask needs z.

  ReDec       The doctor opens HDR with SK_D (so the policy A is still enforced
              on the requester), recomputes z from Z and ITS OWN ctx, and
              unblinds: R = C~ / Q^z. A different ctx gives a different z, the
              recovered key fails the confirmation tag kc, and bottom is returned.

Only the encrypted symmetric-key component is transformed; CT_m is untouched.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import GT, ZR, PairingGroup, pair
from charm.toolbox.secretutil import SecretUtil

from flex_diam.hashing import H

CURVE = os.environ.get("FLEX_CURVE", "BN254")  # same curve as the baselines


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class ABPRE:
    def __init__(self, curve: str = CURVE):
        self.group = PairingGroup(curve)
        self.cpabe = CPabe_BSW07(self.group)
        self.util = SecretUtil(self.group, verbose=False)

    # ----- CP-ABE (eq. 1, 6, 11) -------------------------------------------

    def setup(self):
        """(PK, MSK) <- CPABE.Setup(1^lambda)."""
        return self.cpabe.setup()

    def keygen(self, pk: dict, msk: dict, attrs: list[str]) -> dict:
        """SK_D <- CPABE.KeyGen(MSK, Attr_D)."""
        return self.cpabe.keygen(pk, msk, attrs)

    def _kdf(self, elem: Any) -> bytes:
        return hashlib.sha256(self.group.serialize(elem)).digest()

    def encrypt_key(self, pk: dict, k_aes: bytes, policy: str) -> dict:
        """CT_k <- CPABE.Enc(PK, K_AES, A)."""
        if len(k_aes) != 32:
            raise ValueError("K_AES must be 32 bytes")
        r = self.group.random(GT)
        return {
            "abe": self.cpabe.encrypt(pk, r, policy),
            "wrap": _xor(k_aes, self._kdf(r)),
            "kc": H("FLEX-DIAM/kc", k_aes),
            "policy": policy,
        }

    def _satisfies(self, sk: dict, abe_ct: dict) -> bool:
        """Does the attribute set of SK satisfy the policy of a BSW07 ciphertext?"""
        policy = self.util.createPolicy(abe_ct["policy"])
        return self.util.prune(policy, sk["S"]) is not False

    def _unwrap(self, r: Any, wrap: bytes, kc: bytes):
        k_aes = _xor(wrap, self._kdf(r))
        return k_aes if H("FLEX-DIAM/kc", k_aes) == kc else None

    def decrypt_key(self, pk: dict, sk: dict, ct_k: dict):
        """Direct CP-ABE decryption of an untransformed CT_k (None = bottom).

        Not on the cross-domain path of Phases 4-5; kept for in-domain access
        and for tests."""
        if not self._satisfies(sk, ct_k["abe"]):
            return None
        r = self.cpabe.decrypt(pk, sk, ct_k["abe"])
        return self._unwrap(r, ct_k["wrap"], ct_k["kc"])

    # ----- context-bound ABPRE (eq. 37-41, 47) ------------------------------

    def _z(self, z_seed: Any, ctx: bytes, pk_hd: bytes):
        digest = H("FLEX-DIAM/abpre/z", self.group.serialize(z_seed), ctx, pk_hd)
        z = self.group.hash(digest.hex(), ZR)
        if z == self.group.init(ZR, 0):
            raise RuntimeError("degenerate blinding factor")
        return z

    def rekeygen(self, pk: dict, msk: dict, pk_hd: bytes, ctx: bytes, policy: str) -> dict:
        """rk <- ReKeyGen(MSK, pk_Hd, ctx).

        `policy` is the access policy A of the ciphertext named in ctx; the KMS
        resolves it from pid in the authenticated metadata."""
        attrs = self.util.getAttributeList(self.util.createPolicy(policy))
        sk_star = self.cpabe.keygen(pk, msk, attrs)
        z_seed = self.group.random(GT)
        z_inv = self._z(z_seed, ctx, pk_hd) ** -1
        tk = {
            "D": sk_star["D"] ** z_inv,
            "Dj": {j: v ** z_inv for j, v in sk_star["Dj"].items()},
            "Djp": {j: v ** z_inv for j, v in sk_star["Djp"].items()},
            "S": attrs,
        }
        return {"tk": tk, "hdr": self.cpabe.encrypt(pk, z_seed, policy), "pk_hd": pk_hd}

    def reenc(self, pk: dict, rk: dict, ct_k: dict, ctx: bytes) -> dict:
        """CT'_k <- ReEnc(rk, CT_k, ctx)."""
        abe, tk = ct_k["abe"], rk["tk"]
        policy = self.util.createPolicy(abe["policy"])
        pruned = self.util.prune(policy, tk["S"])
        if pruned is False:
            raise ValueError("transformation key does not satisfy the ciphertext policy")
        coeff = self.util.getCoefficients(policy)
        a = 1
        for node in pruned:
            j = node.getAttributeAndIndex()
            k = node.getAttribute()
            a *= (pair(abe["Cy"][j], tk["Dj"][k]) / pair(tk["Djp"][k], abe["Cyp"][j])) ** coeff[j]
        q = pair(abe["C"], tk["D"]) / a  # e(g,g)^(alpha*s/z)
        return {
            "c_tilde": abe["C_tilde"],
            "q": q,
            "hdr": rk["hdr"],
            "wrap": ct_k["wrap"],
            "kc": ct_k["kc"],
            "pk_hd": rk["pk_hd"],
            "tau": H("FLEX-DIAM/abpre/tau", ctx, self.group.serialize(q)),
        }

    def redec(self, pk: dict, sk: dict, ct_kp: dict, ctx: bytes):
        """K_AES <- ReDec(SK_D, CT'_k, ctx); None is the paper's bottom."""
        if H("FLEX-DIAM/abpre/tau", ctx, self.group.serialize(ct_kp["q"])) != ct_kp["tau"]:
            return None  # context mismatch, rejected before any pairing
        if not self._satisfies(sk, ct_kp["hdr"]):
            return None  # Attr_D does not satisfy A
        z_seed = self.cpabe.decrypt(pk, sk, ct_kp["hdr"])
        z = self._z(z_seed, ctx, ct_kp["pk_hd"])
        r = ct_kp["c_tilde"] / (ct_kp["q"] ** z)
        return self._unwrap(r, ct_kp["wrap"], ct_kp["kc"])
