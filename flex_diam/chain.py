"""flex_diam.chain — client for the FLEX-DIAM chaincode.

`FabricLedger` talks to the running Hyperledger Fabric test-network through the
`peer` CLI, exactly as V2 did: a write is timed from submit to commit
(`--waitForEvent`), a read is a `peer chaincode query`. Every call returns
`(result, elapsed_ms)` measured with perf_counter around the real subprocess.

`MemoryLedger` mirrors the contract logic in a Python dict. It exists ONLY so the
protocol logic can be unit-tested without Docker (smoke_protocol.py --offline).
It has no latency and the experiment drivers refuse to use it.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import time


@dataclasses.dataclass(frozen=True)
class ScopedState:
    """Result of one current-state resolution (chaincode ResolveState)."""

    v_d: int
    v_p: int
    v_hs: int
    v_hd: int
    rl_d: bool
    rl_hs: bool
    rl_hd: bool
    pid_ct: str

    @property
    def sigma(self) -> tuple[int, int, int, int]:
        """Scoped version tuple sigma = <v_Di, v_pid, v_Hs, v_Hd> (eq. 16)."""
        return (self.v_d, self.v_p, self.v_hs, self.v_hd)


class _LedgerAPI:
    """Typed wrappers shared by both back ends. Each returns (result, ms)."""

    is_real = False

    def invoke(self, fn: str, *args: str):
        raise NotImplementedError

    def query(self, fn: str, *args: str):
        raise NotImplementedError

    # --- Phase 1 Step 2 (eq. 3) ---
    def register_did(self, did: str, pk_hex: str):
        return self.invoke("RegisterDID", did, pk_hex)

    def register_dids(self, pairs):
        recs = [{"did": d, "pk": p} for d, p in pairs]
        return self.invoke("RegisterDIDs", json.dumps(recs, separators=(",", ":")))

    # --- Phase 2 Step 5 (eq. 13-14) ---
    def register_metadata(self, cid: str, did_p: str, did_h: str, pid: str, com: str):
        return self.invoke("RegisterMetadata", cid, did_p, did_h, pid, com)

    # --- scoped revocation (eq. 7, eq. 50) ---
    def revoke_user(self, did: str):
        return self.invoke("RevokeUser", did)

    def revoke_users(self, dids):
        return self.invoke("RevokeUsers", json.dumps(list(dids), separators=(",", ":")))

    def revoke_domain(self, did_h: str):
        return self.invoke("RevokeDomain", did_h)

    def revoke_policy(self, pid: str):
        return self.invoke("RevokePolicy", pid)

    # --- current-state resolution (eq. 16/18, 32/34, 43/45) ---
    def resolve_state(self, did_d: str, did_hs: str, did_hd: str, cid: str, pid: str):
        raw, ms = self.query("ResolveState", did_d, did_hs, did_hd, cid, pid)
        d = json.loads(raw)
        return ScopedState(
            v_d=int(d["v_d"]), v_p=int(d["v_p"]), v_hs=int(d["v_hs"]), v_hd=int(d["v_hd"]),
            rl_d=bool(d["rl_d"]), rl_hs=bool(d["rl_hs"]), rl_hd=bool(d["rl_hd"]),
            pid_ct=d.get("pid_ct", ""),
        ), ms

    # --- audit anchors (eq. 30, 42, 49) ---
    def anchor_batch(self, bid: str, batch_com: str, t_batch: int):
        return self.invoke("AnchorBatch", bid, batch_com, str(t_batch))

    def record_delegation(self, del_com: str, t_del: int):
        return self.invoke("RecordDelegation", del_com, str(t_del))

    def record_access(self, acc_com: str, t_acc: int):
        return self.invoke("RecordAccess", acc_com, str(t_acc))

    # --- generic one-key anchor (calibration unit, baseline anchors) ---
    def anchor(self, key: str, value: str):
        return self.invoke("Anchor", key, value)

    def get_anchor(self, key: str):
        return self.query("GetAnchor", key)


# Linux caps ONE command-line argument at 128 KiB (MAX_ARG_STRLEN). A
# RevokeUsers call for 2,000 DIDs is ~92 KB, inside the limit.
_MAX_ARG_BYTES = 126_000


class FabricLedger(_LedgerAPI):
    """Real Hyperledger Fabric back end (peer CLI, submit -> commit)."""

    is_real = True

    def __init__(self, tn: str | None = None, channel: str | None = None, cc: str | None = None):
        self.tn = tn or os.environ["FLEX_TN"]
        self.channel = channel or os.environ.get("FLEX_CHANNEL", "mychannel")
        self.cc = cc or os.environ.get("FLEX_CC", "flexv3")
        tn_ = self.tn
        orderer_ca = (f"{tn_}/organizations/ordererOrganizations/example.com/orderers/"
                      "orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem")
        org1_ca = (f"{tn_}/organizations/peerOrganizations/org1.example.com/peers/"
                   "peer0.org1.example.com/tls/ca.crt")
        org2_ca = (f"{tn_}/organizations/peerOrganizations/org2.example.com/peers/"
                   "peer0.org2.example.com/tls/ca.crt")
        self._invoke = [
            "peer", "chaincode", "invoke",
            "-o", "localhost:7050", "--ordererTLSHostnameOverride", "orderer.example.com",
            "--channelID", self.channel, "--name", self.cc, "--tls", "--cafile", orderer_ca,
            "--peerAddresses", "localhost:7051", "--tlsRootCertFiles", org1_ca,
            "--peerAddresses", "localhost:9051", "--tlsRootCertFiles", org2_ca,
            "--waitForEvent",
        ]
        self._query = ["peer", "chaincode", "query", "--channelID", self.channel, "--name", self.cc]

    @staticmethod
    def _ctor(fn: str, args) -> str:
        return json.dumps({"function": fn, "Args": [str(a) for a in args]}, separators=(",", ":"))

    def invoke(self, fn: str, *args: str):
        c_arg = self._ctor(fn, args)
        if len(c_arg.encode()) > _MAX_ARG_BYTES:
            raise ValueError(f"{fn}: argument of {len(c_arg)} bytes exceeds the single-argument "
                             "limit of the peer CLI — split the workload into smaller transactions")
        t0 = time.perf_counter_ns()
        r = subprocess.run(self._invoke + ["-c", c_arg], capture_output=True, text=True, timeout=120)
        ms = (time.perf_counter_ns() - t0) / 1e6
        out = r.stdout + r.stderr
        if "status:200" not in out:
            raise RuntimeError(f"{fn} failed: {out[-600:]}")
        return out, ms

    def query(self, fn: str, *args: str):
        c_arg = self._ctor(fn, args)
        t0 = time.perf_counter_ns()
        r = subprocess.run(self._query + ["-c", c_arg], capture_output=True, text=True, timeout=60)
        ms = (time.perf_counter_ns() - t0) / 1e6
        if r.returncode != 0:
            raise RuntimeError(f"{fn} query failed: {r.stderr[-600:]}")
        return r.stdout.strip(), ms


class MemoryLedger(_LedgerAPI):
    """In-process mirror of flex_contract.go for offline logic tests only."""

    is_real = False

    def __init__(self):
        self.kv: dict[str, str] = {}

    def _ver(self, key: str) -> int:
        return int(self.kv.get(key, "0"))

    def _bump(self, key: str) -> int:
        v = self._ver(key) + 1
        self.kv[key] = str(v)
        return v

    def invoke(self, fn: str, *args: str):
        kv = self.kv
        if fn == "RegisterDID":
            kv["did_" + args[0]] = args[1]
        elif fn == "RegisterDIDs":
            for r in json.loads(args[0]):
                kv["did_" + r["did"]] = r["pk"]
        elif fn == "RegisterMetadata":
            cid, did_p, did_h, pid, com = args
            kv["meta_" + cid] = json.dumps(
                {"cid": cid, "did_p": did_p, "did_h": did_h, "pid": pid, "com": com})
        elif fn == "RevokeUser":
            kv["rl_" + args[0]] = "1"
            self._bump("vd_" + args[0])
        elif fn == "RevokeUsers":
            for did in json.loads(args[0]):
                kv["rl_" + did] = "1"
                self._bump("vd_" + did)
        elif fn == "RevokeDomain":
            kv["rl_" + args[0]] = "1"
            self._bump("vh_" + args[0])
        elif fn == "RevokePolicy":
            self._bump("vp_" + args[0])
        elif fn == "AnchorBatch":
            kv["batch_" + args[0]] = json.dumps({"batch_com": args[1], "t_batch": args[2]})
        elif fn == "RecordDelegation":
            kv["del_" + args[0]] = args[1]
        elif fn == "RecordAccess":
            kv["acc_" + args[0]] = args[1]
        elif fn == "Anchor":
            kv["anchor_" + args[0]] = args[1]
        else:
            raise RuntimeError(f"MemoryLedger: unknown invoke {fn}")
        return "status:200", 0.0

    def query(self, fn: str, *args: str):
        kv = self.kv
        if fn == "ResolveState":
            did_d, did_hs, did_hd, cid, pid = args
            meta = json.loads(kv["meta_" + cid]) if ("meta_" + cid) in kv else {}
            return json.dumps({
                "v_d": self._ver("vd_" + did_d), "v_p": self._ver("vp_" + pid),
                "v_hs": self._ver("vh_" + did_hs), "v_hd": self._ver("vh_" + did_hd),
                "rl_d": ("rl_" + did_d) in kv, "rl_hs": ("rl_" + did_hs) in kv,
                "rl_hd": ("rl_" + did_hd) in kv, "pid_ct": meta.get("pid", ""),
            }), 0.0
        if fn == "GetAnchor":
            return kv.get("anchor_" + args[0], ""), 0.0
        if fn == "GetDID":
            return kv["did_" + args[0]], 0.0
        if fn == "IsRevoked":
            return ("true" if ("rl_" + args[0]) in kv else "false"), 0.0
        raise RuntimeError(f"MemoryLedger: unknown query {fn}")


def require_real(ledger) -> None:
    """Experiment drivers call this: measurements must come from real Fabric."""
    if not getattr(ledger, "is_real", False):
        raise SystemExit("refusing to measure against MemoryLedger — a live Fabric network is required")
