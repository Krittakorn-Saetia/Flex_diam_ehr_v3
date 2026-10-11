pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";

// Scoped-state-bound authorization proof (FLEX-DIAM Phase 3 Step 3, eq. 19-22).
//
//   public input   x_i = <DID_Di, pid, rho_i>                          (eq. 19)
//   private witness w_i = <Attr_Di, VC_Di>                             (eq. 20)
//
//   relation (eq. 22):
//       A(Attr_Di) = 1  AND  Verify_pkCI(VC_Di) = 1  AND  DID(VC_Di) = DID_Di
//
// VC_Di = Sign_skCI(Attr_Di || DID_Di || t_exp) (eq. 5) is an EdDSA-Poseidon
// signature over m = Poseidon(Attr_Di, DID_Di, t_exp). Because the PUBLIC did is
// hashed into m, a credential issued to another DID does not verify: that is
// the DID(VC) = DID check.
//
// The policy A is conjunctive: req[] lists its required attributes (0 = unused
// slot) and pid = Poseidon(req) binds that list to the public policy digest
// (eq. 10, H instantiated with Poseidon so the binding is provable in-circuit).
//
// rho_i is the scoped-state digest of eq. 17. It is computed outside the circuit
// and bound here as a public input, so a proof made for one scoped state does
// not verify against another.
//
// CI_AX, CI_AY: the credential issuer's public key pk_CI, fixed at setup.
template Authz(NA, NP, CI_AX, CI_AY) {
    signal input did;          // public: DID_Di
    signal input pid;          // public: policy digest
    signal input rho;          // public: scoped-state digest rho_i

    signal input attrs[NA];    // private: Attr_Di (0-padded)
    signal input texp;         // private: credential expiry t_exp
    signal input sigR8x;       // private: VC signature (R8, S)
    signal input sigR8y;
    signal input sigS;
    signal input req[NP];      // private: Encode(A), opened against pid

    var i;
    var j;

    // --- Verify_pkCI(VC) = 1 and DID(VC) = DID_Di ---
    component vcHash = Poseidon(NA + 2);
    for (i = 0; i < NA; i++) {
        vcHash.inputs[i] <== attrs[i];
    }
    vcHash.inputs[NA] <== did;
    vcHash.inputs[NA + 1] <== texp;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== CI_AX;
    sig.Ay <== CI_AY;
    sig.S <== sigS;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.M <== vcHash.out;

    // --- pid = H(Encode(A)) ---
    component polHash = Poseidon(NP);
    for (i = 0; i < NP; i++) {
        polHash.inputs[i] <== req[i];
    }
    pid === polHash.out;

    // --- A(Attr_Di) = 1: every required attribute is one of the credential's ---
    signal acc[NP][NA + 1];
    for (i = 0; i < NP; i++) {
        acc[i][0] <== 1;
        for (j = 0; j < NA; j++) {
            acc[i][j + 1] <== acc[i][j] * (attrs[j] - req[i]);
        }
        req[i] * acc[i][NA] === 0;
    }

    // --- bind rho_i into the constraint system ---
    signal rhoSq;
    rhoSq <== rho * rho;
}
