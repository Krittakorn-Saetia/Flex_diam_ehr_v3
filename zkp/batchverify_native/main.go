// batchverify_native — native (gnark-crypto) Groth16 batch verification for
// FLEX-DIAM Phase 3 Step 4 (eq. 23-26).
//
//	B        = {(x_i, pi_i)}, b <= b_max                               (eq. 23)
//	eta_B    <-$ {0,1}^lambda, sampled AFTER the batch is closed        (eq. 24)
//	r_i      = H_FS(eta_B || bid || i || x_i || pi_i) in Z_p^*          (eq. 25)
//	Valid_B  = BatchVerify(VK_zk, B, {r_i})                             (eq. 26)
//
// BatchVerify is one gnark PairingCheck over b+3 pairs (a single final
// exponentiation) instead of b independent 4-pair checks. If Valid_B = 0 the
// batch is recursively partitioned and rechecked until the invalid proofs are
// isolated; singletons are verified individually.
//
// H_FS is SHA-256 reduced into the BN254 scalar field. By default the full
// field width is used, as eq. 25 states. FLEX_FS_BITS=128 truncates the
// coefficients to 128 bits (standard small-exponent batching, soundness error
// 2^-128, roughly half the scalar-multiplication work).
//
// Reads the artifacts snarkjs produced: build/authz_vk.json and proof / public
// JSON files (decimal-coordinate G1/G2 points).
//
// Modes:
//
//	batchverify_native verify <bid> <proof.json> <public.json> [<proof.json> <public.json> ...]
//	batchverify_native selftest
//	batchverify_native bench individual <b> <reps>
//	batchverify_native bench batch      <b> <reps>
//
// Prints one JSON line. FLEX_ZKP_BUILD overrides the build dir (default zkp/build).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var swapFp2 = false

type vkJSON struct {
	VkAlpha1 []string   `json:"vk_alpha_1"`
	VkBeta2  [][]string `json:"vk_beta_2"`
	VkGamma2 [][]string `json:"vk_gamma_2"`
	VkDelta2 [][]string `json:"vk_delta_2"`
	IC       [][]string `json:"IC"`
}

type proofJSON struct {
	PiA []string   `json:"pi_a"`
	PiB [][]string `json:"pi_b"`
	PiC []string   `json:"pi_c"`
}

type VK struct {
	Alpha bn254.G1Affine
	Beta  bn254.G2Affine
	Gamma bn254.G2Affine
	Delta bn254.G2Affine
	IC    []bn254.G1Affine
}

type entryRaw struct {
	proof proofJSON
	pubs  []string
}

// Entry is a parsed (x_i, pi_i).
type Entry struct {
	A    bn254.G1Affine
	B    bn254.G2Affine
	C    bn254.G1Affine
	Pubs []string
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "ERROR:", msg)
	os.Exit(1)
}

func fe(s string) fp.Element {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		fail("bad field element: " + s)
	}
	var e fp.Element
	e.SetBigInt(b)
	return e
}

func g1From(s []string) bn254.G1Affine {
	return bn254.G1Affine{X: fe(s[0]), Y: fe(s[1])}
}

func g2From(s [][]string) bn254.G2Affine {
	var p bn254.G2Affine
	if !swapFp2 {
		p.X.A0 = fe(s[0][0])
		p.X.A1 = fe(s[0][1])
		p.Y.A0 = fe(s[1][0])
		p.Y.A1 = fe(s[1][1])
	} else {
		p.X.A0 = fe(s[0][1])
		p.X.A1 = fe(s[0][0])
		p.Y.A0 = fe(s[1][1])
		p.Y.A1 = fe(s[1][0])
	}
	return p
}

func buildVK(j vkJSON) *VK {
	vk := &VK{
		Alpha: g1From(j.VkAlpha1),
		Beta:  g2From(j.VkBeta2),
		Gamma: g2From(j.VkGamma2),
		Delta: g2From(j.VkDelta2),
	}
	for _, ic := range j.IC {
		vk.IC = append(vk.IC, g1From(ic))
	}
	return vk
}

func buildEntry(r entryRaw) Entry {
	return Entry{
		A:    g1From(r.proof.PiA),
		B:    g2From(r.proof.PiB),
		C:    g1From(r.proof.PiC),
		Pubs: r.pubs,
	}
}

func computeL(ic []bn254.G1Affine, pubs []string) bn254.G1Affine {
	if len(pubs)+1 != len(ic) {
		fail(fmt.Sprintf("public input count %d does not match VK (%d)", len(pubs), len(ic)-1))
	}
	var acc bn254.G1Affine
	acc.Set(&ic[0])
	for j, ps := range pubs {
		b, ok := new(big.Int).SetString(ps, 10)
		if !ok {
			fail("bad public signal: " + ps)
		}
		var term bn254.G1Affine
		term.ScalarMultiplication(&ic[j+1], b)
		acc.Add(&acc, &term)
	}
	return acc
}

// validPoints does the soundness-required membership checks a real verifier
// performs (G1 has cofactor 1 on BN254, so on-curve => in prime-order subgroup;
// G2 needs an explicit subgroup check).
func validPoints(e *Entry) bool {
	return e.A.IsOnCurve() && e.C.IsOnCurve() && e.B.IsInSubGroup()
}

// sampleEta draws eta_B after batch closure (eq. 24).
func sampleEta() []byte {
	eta := make([]byte, 32)
	if _, err := rand.Read(eta); err != nil {
		fail("rand: " + err.Error())
	}
	return eta
}

func fsBits() int {
	if v := os.Getenv("FLEX_FS_BITS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 64 || n > 256 {
			fail("FLEX_FS_BITS must be an integer in [64, 256]")
		}
		return n
	}
	return 0 // full field width
}

func hashPart(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// fsCoeff is r_i = H_FS(eta_B || bid || i || x_i || pi_i) in Z_p^* (eq. 25).
func fsCoeff(eta []byte, bid string, i int, e *Entry, bits int) *big.Int {
	h := sha256.New()
	hashPart(h, eta)
	hashPart(h, []byte(bid))
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(i))
	hashPart(h, idx[:])
	for _, p := range e.Pubs {
		hashPart(h, []byte(p))
	}
	a := e.A.Marshal()
	b := e.B.Marshal()
	c := e.C.Marshal()
	hashPart(h, a)
	hashPart(h, b)
	hashPart(h, c)
	r := new(big.Int).SetBytes(h.Sum(nil))
	if bits > 0 && bits < 256 {
		r.Rsh(r, uint(256-bits))
	}
	r.Mod(r, fr.Modulus())
	if r.Sign() == 0 {
		r.SetInt64(1) // Z_p^*: nonzero
	}
	return r
}

func coeffs(bid string, batch []Entry) []*big.Int {
	eta := sampleEta()
	bits := fsBits()
	rs := make([]*big.Int, len(batch))
	for i := range batch {
		rs[i] = fsCoeff(eta, bid, i, &batch[i], bits)
	}
	return rs
}

func verifyOne(vk *VK, e *Entry) bool {
	if !validPoints(e) {
		return false
	}
	L := computeL(vk.IC, e.Pubs)
	var negA bn254.G1Affine
	negA.Neg(&e.A)
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{negA, vk.Alpha, L, e.C},
		[]bn254.G2Affine{e.B, vk.Beta, vk.Gamma, vk.Delta},
	)
	return err == nil && ok
}

// batchVerifyWith evaluates the b independent Groth16 equations combined with
// the given coefficients r_i (eq. 26):
//
//	prod_i e(-r_i A_i, B_i) * e(sum r_i L_i, gamma) * e(sum r_i C_i, delta)
//	       * e((sum r_i) alpha, beta) = 1
func batchVerifyWith(vk *VK, batch []Entry, rs []*big.Int) bool {
	g1s := make([]bn254.G1Affine, 0, len(batch)+3)
	g2s := make([]bn254.G2Affine, 0, len(batch)+3)
	sumR := big.NewInt(0)
	var sumL, sumC bn254.G1Affine
	for i := range batch {
		e := &batch[i]
		if !validPoints(e) {
			return false
		}
		ri := rs[i]
		sumR.Add(sumR, ri)

		L := computeL(vk.IC, e.Pubs)
		var negA, rNegA, rL, rC bn254.G1Affine
		negA.Neg(&e.A)
		rNegA.ScalarMultiplication(&negA, ri)
		rL.ScalarMultiplication(&L, ri)
		rC.ScalarMultiplication(&e.C, ri)

		g1s = append(g1s, rNegA)
		g2s = append(g2s, e.B)
		if i == 0 {
			sumL.Set(&rL)
			sumC.Set(&rC)
		} else {
			sumL.Add(&sumL, &rL)
			sumC.Add(&sumC, &rC)
		}
	}
	sumR.Mod(sumR, fr.Modulus())
	var rAlpha bn254.G1Affine
	rAlpha.ScalarMultiplication(&vk.Alpha, sumR)
	g1s = append(g1s, sumL, sumC, rAlpha)
	g2s = append(g2s, vk.Gamma, vk.Delta, vk.Beta)

	ok, err := bn254.PairingCheck(g1s, g2s)
	return err == nil && ok
}

// batchVerify closes the batch, derives the Fiat-Shamir coefficients and
// evaluates eq. 26 once.
func batchVerify(vk *VK, bid string, batch []Entry) bool {
	return batchVerifyWith(vk, batch, coeffs(bid, batch))
}

// resolve returns Valid_zk^(i) for every request: accept all when the batch
// verifies, otherwise partition recursively until invalid proofs are isolated.
func resolve(vk *VK, batch []Entry, rs []*big.Int, out []bool) {
	if len(batch) == 0 {
		return
	}
	if len(batch) == 1 {
		out[0] = verifyOne(vk, &batch[0])
		return
	}
	if batchVerifyWith(vk, batch, rs) {
		for i := range out {
			out[i] = true
		}
		return
	}
	mid := len(batch) / 2
	resolve(vk, batch[:mid], rs[:mid], out[:mid])
	resolve(vk, batch[mid:], rs[mid:], out[mid:])
}

// decide is the full Step 4: batch check + recursive partition on failure.
func decide(vk *VK, bid string, batch []Entry) []bool {
	out := make([]bool, len(batch))
	resolve(vk, batch, coeffs(bid, batch), out)
	return out
}

func cycle(corpus []Entry, b int) []Entry {
	out := make([]Entry, b)
	for i := 0; i < b; i++ {
		// copy so callers can mutate Pubs without touching the corpus
		out[i] = corpus[i%len(corpus)]
	}
	return out
}

func readVK(build string) vkJSON {
	var vk vkJSON
	raw, err := os.ReadFile(filepath.Join(build, "authz_vk.json"))
	if err != nil {
		fail("read vk: " + err.Error())
	}
	if err := json.Unmarshal(raw, &vk); err != nil {
		fail("parse vk: " + err.Error())
	}
	return vk
}

func readEntry(proofPath, publicPath string) (entryRaw, error) {
	var er entryRaw
	pb, err := os.ReadFile(proofPath)
	if err != nil {
		return er, err
	}
	sb, err := os.ReadFile(publicPath)
	if err != nil {
		return er, err
	}
	if err := json.Unmarshal(pb, &er.proof); err != nil {
		return er, err
	}
	if err := json.Unmarshal(sb, &er.pubs); err != nil {
		return er, err
	}
	return er, nil
}

func loadCorpus(build string) []entryRaw {
	var corpus []entryRaw
	dir := filepath.Join(build, "corpus")
	for i := 0; ; i++ {
		er, err := readEntry(
			filepath.Join(dir, fmt.Sprintf("proof_%d.json", i)),
			filepath.Join(dir, fmt.Sprintf("public_%d.json", i)))
		if err != nil {
			break
		}
		corpus = append(corpus, er)
	}
	if len(corpus) == 0 {
		fail("empty corpus in " + dir + " (run zkp/gen_corpus.py)")
	}
	return corpus
}

// loadVK parses VK_zk, choosing the Fq2 coordinate order under which its G2
// points lie in the prime-order subgroup. A wrong order yields points that are
// not even on the twist, so the choice is unambiguous and independent of any
// proof — an invalid proof can never be mistaken for an encoding mismatch.
func loadVK(raw vkJSON) *VK {
	for _, swap := range []bool{false, true} {
		swapFp2 = swap
		vk := buildVK(raw)
		if vk.Beta.IsInSubGroup() && vk.Gamma.IsInSubGroup() && vk.Delta.IsInSubGroup() {
			return vk
		}
	}
	fail("VK G2 points are not in the subgroup under either Fq2 ordering")
	return nil
}

func buildEntries(raws []entryRaw) []Entry {
	es := make([]Entry, len(raws))
	for i, r := range raws {
		es[i] = buildEntry(r)
	}
	return es
}

func printJSON(m map[string]interface{}) {
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
}

func stats(times []float64, b int) map[string]interface{} {
	sorted := append([]float64(nil), times...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	var sum float64
	for _, t := range times {
		sum += t
	}
	return map[string]interface{}{
		"median_ms":    median,
		"mean_ms":      sum / float64(len(times)),
		"per_proof_ms": median / float64(b),
	}
}

func allTrue(v []bool) bool {
	for _, x := range v {
		if !x {
			return false
		}
	}
	return true
}

func selftest(vk *VK, corpus []Entry) {
	for i := range corpus {
		if !verifyOne(vk, &corpus[i]) {
			fail("individual verify failed on corpus proof")
		}
	}
	for _, b := range []int{1, 2, 8, len(corpus), 3 * len(corpus)} {
		if !batchVerify(vk, "selftest", cycle(corpus, b)) {
			fail(fmt.Sprintf("valid batch of size %d rejected", b))
		}
	}
	// corrupt one public signal -> the batch must fail and bisection must
	// isolate exactly that request
	bad := cycle(corpus, 8)
	bad[5].Pubs = append([]string(nil), bad[5].Pubs...)
	v, _ := new(big.Int).SetString(bad[5].Pubs[0], 10)
	bad[5].Pubs[0] = new(big.Int).Add(v, big.NewInt(1)).String()
	if batchVerify(vk, "selftest", bad) {
		fail("batch with corrupted PUBLIC accepted — UNSOUND")
	}
	d := decide(vk, "selftest", bad)
	for i, ok := range d {
		if ok == (i == 5) {
			fail(fmt.Sprintf("recursive partition mis-decided request %d", i))
		}
	}
	// corrupt one proof point -> must fail
	bad2 := cycle(corpus, 8)
	bad2[3].A = corpus[(3+1)%len(corpus)].A
	if len(corpus) > 1 && batchVerify(vk, "selftest", bad2) {
		fail("batch with corrupted PROOF accepted — UNSOUND")
	}
	if !allTrue(decide(vk, "selftest", cycle(corpus, 8))) {
		fail("valid batch rejected by decide()")
	}
	printJSON(map[string]interface{}{
		"selftest": "PASS", "backend": "gnark-native",
		"corpus": len(corpus), "swapFp2": swapFp2, "fs_bits": fsBits(),
	})
}

func benchIndividual(vk *VK, corpus []Entry, b, reps int) []float64 {
	batch := cycle(corpus, b)
	verifyOne(vk, &batch[0]) // warm
	var times []float64
	for r := 0; r < reps; r++ {
		t0 := time.Now()
		for i := range batch {
			if !verifyOne(vk, &batch[i]) {
				fail("individual verify returned false")
			}
		}
		times = append(times, float64(time.Since(t0).Nanoseconds())/1e6)
	}
	return times
}

func benchBatch(vk *VK, corpus []Entry, b, reps int) []float64 {
	batch := cycle(corpus, b)
	batchVerify(vk, "warm", cycle(corpus, min(b, 4))) // warm
	var times []float64
	for r := 0; r < reps; r++ {
		t0 := time.Now()
		// timed: eta_B sampling + r_i derivation + the single pairing check
		if !batchVerify(vk, "bench", batch) {
			fail("batch verify returned false")
		}
		times = append(times, float64(time.Since(t0).Nanoseconds())/1e6)
	}
	return times
}

func main() {
	build := os.Getenv("FLEX_ZKP_BUILD")
	if build == "" {
		build = "zkp/build"
	}
	vk := loadVK(readVK(build))

	args := os.Args[1:]
	if len(args) >= 4 && args[0] == "verify" && len(args)%2 == 0 {
		bid := args[1]
		var raws []entryRaw
		for i := 2; i < len(args); i += 2 {
			er, err := readEntry(args[i], args[i+1])
			if err != nil {
				fail("read proof: " + err.Error())
			}
			raws = append(raws, er)
		}
		batch := buildEntries(raws)
		t0 := time.Now()
		valid := decide(vk, bid, batch)
		ms := float64(time.Since(t0).Nanoseconds()) / 1e6
		printJSON(map[string]interface{}{
			"valid": valid, "b": len(batch), "verify_ms": ms,
			"backend": "gnark-native", "fs_bits": fsBits(),
		})
		return
	}
	if len(args) >= 1 && args[0] == "selftest" {
		selftest(vk, buildEntries(loadCorpus(build)))
		return
	}
	if len(args) == 4 && args[0] == "bench" && (args[1] == "individual" || args[1] == "batch") {
		var b, reps int
		fmt.Sscan(args[2], &b)
		fmt.Sscan(args[3], &reps)
		if b <= 0 || reps <= 0 {
			fail("bench needs positive b and reps")
		}
		corpus := buildEntries(loadCorpus(build))
		var times []float64
		if args[1] == "individual" {
			times = benchIndividual(vk, corpus, b, reps)
		} else {
			times = benchBatch(vk, corpus, b, reps)
		}
		out := stats(times, b)
		out["mode"] = args[1]
		out["b"] = b
		out["reps"] = reps
		out["backend"] = "gnark-native"
		out["fs_bits"] = fsBits()
		printJSON(out)
		return
	}
	fail("usage: verify <bid> <proof> <public> ... | selftest | bench individual|batch <b> <reps>")
}
