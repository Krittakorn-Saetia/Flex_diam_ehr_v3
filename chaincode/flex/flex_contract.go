// Package main — FLEX-DIAM chaincode (V3, scoped revocation).
//
// On-chain state required by the revised paper:
//
//   - DID registry            (eq. 3:  DID_E = H(pk_E), pair registered on chain)
//   - Scoped revocation state (eq. 7:  RS = <RL, {v_D}, {v_p}, {v_H}>)
//   - Ciphertext metadata     (eq. 13-14: <Meta, Com>)
//   - Audit anchors           (eq. 30 batch, eq. 42 delegation, eq. 49 access)
//
// There is NO global epoch. A revocation touches only the keys of the affected
// scope, so revocations of different users never share a key (no MVCC conflict)
// and never change another user's scoped-state digest rho.
//
// Versions are stored only once they are non-zero: an absent version key reads
// as 0 ("All versions are initialized to zero", Phase 1 Step 4).
//
// Deployed as chaincode-as-a-service (ccaas), same as V2.
package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	didPrefix    = "did_"    // DID registry: did -> pk
	rlPrefix     = "rl_"     // RL membership: did -> "1"
	vdPrefix     = "vd_"     // user version v_D
	vpPrefix     = "vp_"     // policy version v_p
	vhPrefix     = "vh_"     // domain version v_H
	metaPrefix   = "meta_"   // cid -> Metadata
	batchPrefix  = "batch_"  // bid -> BatchAnchor
	delPrefix    = "del_"    // DelCom -> t_del
	accPrefix    = "acc_"    // AccCom -> t_acc
	anchorPrefix = "anchor_" // generic one-key anchor (unit calibration)
)

// FlexContract is the chaincode contract for FLEX-DIAM.
type FlexContract struct {
	contractapi.Contract
}

// Metadata is <Meta, Com> of eq. 13-14.
type Metadata struct {
	Cid  string `json:"cid"`
	DidP string `json:"did_p"`
	DidH string `json:"did_h"`
	Pid  string `json:"pid"`
	Com  string `json:"com"`
}

// ScopedState is what one current-state resolution returns: the scoped version
// tuple sigma = <v_D, v_pid, v_Hs, v_Hd> (eq. 16/32/43), the three RL membership
// bits and the registered policy digest pid_CT used by eq. 18/34/45.
type ScopedState struct {
	VD    int    `json:"v_d"`
	VP    int    `json:"v_p"`
	VHs   int    `json:"v_hs"`
	VHd   int    `json:"v_hd"`
	RLD   bool   `json:"rl_d"`
	RLHs  bool   `json:"rl_hs"`
	RLHd  bool   `json:"rl_hd"`
	PidCT string `json:"pid_ct"`
}

// BatchAnchor is <bid, BatchCom, t_batch> of eq. 30.
type BatchAnchor struct {
	Bid      string `json:"bid"`
	BatchCom string `json:"batch_com"`
	TBatch   string `json:"t_batch"`
}

// DIDRecord is one (DID_E, pk_E) pair for batched registration.
type DIDRecord struct {
	Did string `json:"did"`
	Pk  string `json:"pk"`
}

func getVersion(ctx contractapi.TransactionContextInterface, key string) (int, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", key, err)
	}
	if b == nil {
		return 0, nil
	}
	v, err := strconv.Atoi(string(b))
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q: %w", key, string(b), err)
	}
	return v, nil
}

// bumpVersion performs v <- v + 1 on one scoped version key.
func bumpVersion(ctx contractapi.TransactionContextInterface, key string) (int, error) {
	v, err := getVersion(ctx, key)
	if err != nil {
		return 0, err
	}
	v++
	if err := ctx.GetStub().PutState(key, []byte(strconv.Itoa(v))); err != nil {
		return 0, fmt.Errorf("put %s: %w", key, err)
	}
	return v, nil
}

func isRevoked(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	b, err := ctx.GetStub().GetState(rlPrefix + id)
	if err != nil {
		return false, fmt.Errorf("read rl %s: %w", id, err)
	}
	return b != nil, nil
}

// ---------------------------------------------------------------------------
// Phase 1 Step 2 — DID registration (eq. 3)
// ---------------------------------------------------------------------------

// RegisterDID binds a decentralized identifier to its verification key.
func (s *FlexContract) RegisterDID(ctx contractapi.TransactionContextInterface, did string, pk string) error {
	if did == "" || pk == "" {
		return fmt.Errorf("RegisterDID: did and pk must be non-empty")
	}
	return ctx.GetStub().PutState(didPrefix+did, []byte(pk))
}

// RegisterDIDs registers several (DID, pk) pairs in one transaction. Setup-time
// convenience only; it is never inside a measured window.
func (s *FlexContract) RegisterDIDs(ctx contractapi.TransactionContextInterface, recordsJSON string) (int, error) {
	var recs []DIDRecord
	if err := json.Unmarshal([]byte(recordsJSON), &recs); err != nil {
		return 0, fmt.Errorf("RegisterDIDs: bad JSON: %w", err)
	}
	for _, r := range recs {
		if r.Did == "" || r.Pk == "" {
			return 0, fmt.Errorf("RegisterDIDs: empty did or pk")
		}
		if err := ctx.GetStub().PutState(didPrefix+r.Did, []byte(r.Pk)); err != nil {
			return 0, fmt.Errorf("RegisterDIDs: put %s: %w", r.Did, err)
		}
	}
	return len(recs), nil
}

// GetDID returns the verification key registered for a DID.
func (s *FlexContract) GetDID(ctx contractapi.TransactionContextInterface, did string) (string, error) {
	b, err := ctx.GetStub().GetState(didPrefix + did)
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", fmt.Errorf("DID %s not registered", did)
	}
	return string(b), nil
}

// ---------------------------------------------------------------------------
// Phase 2 Step 5 — metadata and audit registration (eq. 13-14)
// ---------------------------------------------------------------------------

// RegisterMetadata anchors <Meta, Com> for ciphertext cid.
func (s *FlexContract) RegisterMetadata(
	ctx contractapi.TransactionContextInterface,
	cid string, didP string, didH string, pid string, com string,
) error {
	if cid == "" || pid == "" {
		return fmt.Errorf("RegisterMetadata: cid and pid must be non-empty")
	}
	b, err := json.Marshal(Metadata{Cid: cid, DidP: didP, DidH: didH, Pid: pid, Com: com})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(metaPrefix+cid, b)
}

// GetMetadata returns the anchored <Meta, Com> of cid.
func (s *FlexContract) GetMetadata(ctx contractapi.TransactionContextInterface, cid string) (*Metadata, error) {
	b, err := ctx.GetStub().GetState(metaPrefix + cid)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("metadata for %s not found", cid)
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ---------------------------------------------------------------------------
// Scoped revocation (eq. 7, eq. 50)
// ---------------------------------------------------------------------------

// revokeUser applies eq. 50 to one doctor: RL <- RL U {DID_Di}, v_Di <- v_Di + 1.
func revokeUser(ctx contractapi.TransactionContextInterface, did string) (int, error) {
	if did == "" {
		return 0, fmt.Errorf("empty DID")
	}
	if err := ctx.GetStub().PutState(rlPrefix+did, []byte("1")); err != nil {
		return 0, fmt.Errorf("put rl %s: %w", did, err)
	}
	return bumpVersion(ctx, vdPrefix+did)
}

// RevokeUser revokes one doctor (eq. 50) and returns the new v_Di.
func (s *FlexContract) RevokeUser(ctx contractapi.TransactionContextInterface, did string) (int, error) {
	return revokeUser(ctx, did)
}

// RevokeUsers applies eq. 50 to every doctor in the list within ONE transaction
// (one endorsement, one ordering, one commit). Each doctor still gets its own RL
// entry and its own version increment — no shared key is written. Returns the
// number of doctors processed.
func (s *FlexContract) RevokeUsers(ctx contractapi.TransactionContextInterface, didsJSON string) (int, error) {
	var dids []string
	if err := json.Unmarshal([]byte(didsJSON), &dids); err != nil {
		return 0, fmt.Errorf("RevokeUsers: bad JSON: %w", err)
	}
	if len(dids) == 0 {
		return 0, fmt.Errorf("RevokeUsers: empty list")
	}
	for _, did := range dids {
		if _, err := revokeUser(ctx, did); err != nil {
			return 0, fmt.Errorf("RevokeUsers: %w", err)
		}
	}
	return len(dids), nil
}

// RevokeDomain revokes a healthcare domain: RL <- RL U {DID_H}, v_H <- v_H + 1.
func (s *FlexContract) RevokeDomain(ctx contractapi.TransactionContextInterface, didH string) (int, error) {
	if didH == "" {
		return 0, fmt.Errorf("RevokeDomain: empty DID")
	}
	if err := ctx.GetStub().PutState(rlPrefix+didH, []byte("1")); err != nil {
		return 0, err
	}
	return bumpVersion(ctx, vhPrefix+didH)
}

// RevokePolicy invalidates artifacts issued under policy scope pid: v_p <- v_p + 1.
// A policy is not an entity, so nothing is added to RL.
func (s *FlexContract) RevokePolicy(ctx contractapi.TransactionContextInterface, pid string) (int, error) {
	if pid == "" {
		return 0, fmt.Errorf("RevokePolicy: empty pid")
	}
	return bumpVersion(ctx, vpPrefix+pid)
}

// IsRevoked reports RL membership of one entity.
func (s *FlexContract) IsRevoked(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	return isRevoked(ctx, id)
}

// ResolveState returns, in one query, everything a current-state validation
// needs for request <DID_Di, DID_Hs, DID_Hd, cid, pid>: the scoped versions
// (eq. 16/32/43), RL membership of the three entities and pid_CT (eq. 18/34/45).
func (s *FlexContract) ResolveState(
	ctx contractapi.TransactionContextInterface,
	didD string, didHs string, didHd string, cid string, pid string,
) (*ScopedState, error) {
	var st ScopedState
	var err error
	if st.VD, err = getVersion(ctx, vdPrefix+didD); err != nil {
		return nil, err
	}
	if st.VP, err = getVersion(ctx, vpPrefix+pid); err != nil {
		return nil, err
	}
	if st.VHs, err = getVersion(ctx, vhPrefix+didHs); err != nil {
		return nil, err
	}
	if st.VHd, err = getVersion(ctx, vhPrefix+didHd); err != nil {
		return nil, err
	}
	if st.RLD, err = isRevoked(ctx, didD); err != nil {
		return nil, err
	}
	if st.RLHs, err = isRevoked(ctx, didHs); err != nil {
		return nil, err
	}
	if st.RLHd, err = isRevoked(ctx, didHd); err != nil {
		return nil, err
	}
	mb, err := ctx.GetStub().GetState(metaPrefix + cid)
	if err != nil {
		return nil, err
	}
	if mb != nil {
		var m Metadata
		if err := json.Unmarshal(mb, &m); err != nil {
			return nil, err
		}
		st.PidCT = m.Pid
	}
	return &st, nil
}

// ---------------------------------------------------------------------------
// Audit anchors
// ---------------------------------------------------------------------------

// AnchorBatch records <bid, BatchCom, t_batch> (eq. 30).
func (s *FlexContract) AnchorBatch(
	ctx contractapi.TransactionContextInterface,
	bid string, batchCom string, tBatch string,
) error {
	if bid == "" || batchCom == "" {
		return fmt.Errorf("AnchorBatch: bid and batchCom must be non-empty")
	}
	b, err := json.Marshal(BatchAnchor{Bid: bid, BatchCom: batchCom, TBatch: tBatch})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(batchPrefix+bid, b)
}

// RecordDelegation records (DelCom_i, t_del) (eq. 42).
func (s *FlexContract) RecordDelegation(ctx contractapi.TransactionContextInterface, delCom string, tDel string) error {
	if delCom == "" {
		return fmt.Errorf("RecordDelegation: empty commitment")
	}
	return ctx.GetStub().PutState(delPrefix+delCom, []byte(tDel))
}

// RecordAccess records AccCom_i (eq. 49).
func (s *FlexContract) RecordAccess(ctx contractapi.TransactionContextInterface, accCom string, tAcc string) error {
	if accCom == "" {
		return fmt.Errorf("RecordAccess: empty commitment")
	}
	return ctx.GetStub().PutState(accPrefix+accCom, []byte(tAcc))
}

// Anchor is a generic one-key write. It is the unit measured by chain_meter and
// the shape charged to a baseline scheme for one on-chain anchor.
func (s *FlexContract) Anchor(ctx contractapi.TransactionContextInterface, key string, value string) error {
	if key == "" {
		return fmt.Errorf("Anchor: empty key")
	}
	return ctx.GetStub().PutState(anchorPrefix+key, []byte(value))
}

// GetAnchor is the matching one-key read.
func (s *FlexContract) GetAnchor(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	b, err := ctx.GetStub().GetState(anchorPrefix + key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
