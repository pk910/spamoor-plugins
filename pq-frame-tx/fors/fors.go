// Package fors implements the FORS+C few-time signature scheme used by the NiceTry
// post-quantum accounts (RivaLabs-Core/Post-Quantum-AA-Infra, docs/signing-spec.md §4),
// byte-compatible with the on-chain ForsVerifier and the repository's Python reference
// signer.
//
// Parameters: n=16, k=26 trees of which 25 are real (the 26th is replaced by a grinding
// condition), a=5 (32 leaves per tree), keccak256 everywhere. A signature is 2,448 bytes.
//
// A FORS+C key signs ONE message safely. Security degrades with reuse (128 bits at one
// use, 104 at two, 70 at five), which is why the frame account burns a key after it signs.
package fors

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// Scheme parameters.
const (
	N         = 16
	K         = 26
	A         = 5
	RealTrees = K - 1
	Leaves    = 1 << A

	treeOpeningLen = N + A*N // sk || auth[0..A)
	sigRLen        = N
	sigPkSeedLen   = N
	sigCounterLen  = N

	// SigLen is the FORS+C signature length: R || pkSeed || 25 openings || counter.
	SigLen = sigRLen + sigPkSeedLen + RealTrees*treeOpeningLen + sigCounterLen

	adrsTypeForsTree  = 3
	adrsTypeForsRoots = 4
)

// ErrBadSignature is returned by Recover for a malformed signature.
var ErrBadSignature = errors.New("fors: malformed signature")

var (
	// forsDom is the H_msg domain separator word.
	forsDom = common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd")

	domainSkSeed = []byte("NiceTry/FORS/skSeed/v1")
	domainPkSeed = []byte("NiceTry/FORS/pkSeed/v1")
	domainR      = []byte("NiceTry/FORS/R/v1")
)

// Key is one FORS+C key pair with its Merkle trees precomputed.
type Key struct {
	Index   uint64
	SkSeed  [N]byte
	PkSeed  [N]byte
	PkRoot  [N]byte
	Address common.Address

	// levels[t][cp] holds the 2^(A-cp) nodes of tree t at height cp; levels[t][A][0] is
	// the root.
	levels [RealTrees][A + 1][][N]byte
}

// pad32 places a 16-byte value in the first half of a 32-byte slot.
func pad32(x [N]byte) []byte {
	out := make([]byte, 32)
	copy(out, x[:])

	return out
}

// left16 truncates a hash to its first 16 bytes.
func left16(h []byte) [N]byte {
	var out [N]byte

	copy(out[:], h[:N])

	return out
}

// adrsWord builds a 32-byte ADRS word: `typ` in bytes 16..20, `low` in bytes 24..32.
func adrsWord(typ uint32, low uint64) []byte {
	out := make([]byte, 32)
	binary.BigEndian.PutUint32(out[16:20], typ)
	binary.BigEndian.PutUint64(out[24:32], low)

	return out
}

// adrsLeaf is ADRS_LEAF(t, leafIdx) = (3 << 96) | ((t << A) | leafIdx).
func adrsLeaf(t, leafIdx uint64) []byte {
	return adrsWord(adrsTypeForsTree, (t<<A)|leafIdx)
}

// adrsNode is ADRS_NODE(t, cp, parentIdx) = (3 << 96) | (cp << 32) | ((t << (A-cp)) | parentIdx).
func adrsNode(t, cp, parentIdx uint64) []byte {
	return adrsWord(adrsTypeForsTree, (cp<<32)|((t<<(A-cp))|parentIdx))
}

// adrsRoots is ADRS_ROOTS = 4 << 96.
func adrsRoots() []byte {
	return adrsWord(adrsTypeForsRoots, 0)
}

// prf expands a leaf secret: left16(keccak(pad32(skSeed) || adrs)).
func prf(skSeed [N]byte, adrs []byte) [N]byte {
	return left16(crypto.Keccak256(pad32(skSeed), adrs))
}

// f hashes a leaf: left16(keccak(pad32(pkSeed) || adrs || pad32(sk))).
func f(pkSeed [N]byte, adrs []byte, sk [N]byte) [N]byte {
	return left16(crypto.Keccak256(pad32(pkSeed), adrs, pad32(sk)))
}

// h hashes two children: left16(keccak(pad32(pkSeed) || adrs || pad32(left) || pad32(right))).
func h(pkSeed [N]byte, adrs []byte, left, right [N]byte) [N]byte {
	return left16(crypto.Keccak256(pad32(pkSeed), adrs, pad32(left), pad32(right)))
}

// hmsg is the (untruncated) message hash whose 5-bit digits select the leaves.
func hmsg(pkSeed, r [N]byte, digest common.Hash, counter [N]byte) []byte {
	return crypto.Keccak256(pad32(pkSeed), pad32(r), digest[:], forsDom[:], pad32(counter))
}

// compressRoots is T_roots(pkSeed, roots[0..25)).
func compressRoots(pkSeed [N]byte, roots [RealTrees][N]byte) [N]byte {
	buf := make([]byte, 0, 32*(RealTrees+2))
	buf = append(buf, pad32(pkSeed)...)
	buf = append(buf, adrsRoots()...)

	for t := 0; t < RealTrees; t++ {
		buf = append(buf, pad32(roots[t])...)
	}

	return left16(crypto.Keccak256(buf))
}

// addressOf is last20(keccak(pad32(pkSeed) || pad32(pkRoot))).
func addressOf(pkSeed, pkRoot [N]byte) common.Address {
	return common.BytesToAddress(crypto.Keccak256(pad32(pkSeed), pad32(pkRoot))[12:])
}

// digits extracts md[0..K) from dVal, LSB first: md[t] = (dVal >> 5t) & 31.
func digits(dVal []byte) [K]uint64 {
	var md [K]uint64

	d := new(uint256.Int).SetBytes(dVal)
	tmp := new(uint256.Int)

	for t := 0; t < K; t++ {
		md[t] = tmp.Rsh(d, uint(A*t)).Uint64() & (Leaves - 1)
	}

	return md
}

// DeriveSeeds returns the (skSeed, pkSeed) pair of chain key `index` for a master secret.
func DeriveSeeds(masterSecret common.Hash, index uint64) (skSeed, pkSeed [N]byte) {
	var idx [8]byte

	binary.BigEndian.PutUint64(idx[:], index)

	skSeed = left16(crypto.Keccak256(domainSkSeed, masterSecret[:], idx[:]))
	pkSeed = left16(crypto.Keccak256(domainPkSeed, masterSecret[:], idx[:]))

	return skSeed, pkSeed
}

// DeriveKey derives chain key `index` from a master secret and builds its trees.
func DeriveKey(masterSecret common.Hash, index uint64) *Key {
	skSeed, pkSeed := DeriveSeeds(masterSecret, index)
	key := NewKey(skSeed, pkSeed)
	key.Index = index

	return key
}

// NewKey builds the trees of a key from its seeds.
func NewKey(skSeed, pkSeed [N]byte) *Key {
	key := &Key{SkSeed: skSeed, PkSeed: pkSeed}

	var roots [RealTrees][N]byte

	for t := uint64(0); t < RealTrees; t++ {
		leaves := make([][N]byte, Leaves)

		for leafIdx := uint64(0); leafIdx < Leaves; leafIdx++ {
			adrs := adrsLeaf(t, leafIdx)
			leaves[leafIdx] = f(pkSeed, adrs, prf(skSeed, adrs))
		}

		key.levels[t][0] = leaves

		for cp := uint64(1); cp <= A; cp++ {
			prev := key.levels[t][cp-1]
			count := uint64(1) << (A - cp)
			level := make([][N]byte, count)

			for parentIdx := uint64(0); parentIdx < count; parentIdx++ {
				level[parentIdx] = h(pkSeed, adrsNode(t, cp, parentIdx), prev[2*parentIdx], prev[2*parentIdx+1])
			}

			key.levels[t][cp] = level
		}

		roots[t] = key.levels[t][A][0]
	}

	key.PkRoot = compressRoots(pkSeed, roots)
	key.Address = addressOf(pkSeed, key.PkRoot)

	return key
}

// findCounter grinds the 16-byte counter until the omitted tree's digit is zero.
func findCounter(pkSeed, r [N]byte, digest common.Hash) ([N]byte, [K]uint64) {
	var counter [N]byte

	for c := uint64(0); ; c++ {
		binary.BigEndian.PutUint64(counter[8:], c)

		md := digits(hmsg(pkSeed, r, digest, counter))
		if md[RealTrees] == 0 {
			return counter, md
		}
	}
}

// Sign produces the 2,448-byte FORS+C signature of a 32-byte digest. The randomizer R is
// derived deterministically from the secret seed and the digest, matching the reference
// signer, so signing is a pure function of (key, digest).
func (k *Key) Sign(digest common.Hash) []byte {
	r := left16(crypto.Keccak256(domainR, k.SkSeed[:], digest[:]))
	counter, md := findCounter(k.PkSeed, r, digest)

	sig := make([]byte, 0, SigLen)
	sig = append(sig, r[:]...)
	sig = append(sig, k.PkSeed[:]...)

	for t := uint64(0); t < RealTrees; t++ {
		leafIdx := md[t]
		sk := prf(k.SkSeed, adrsLeaf(t, leafIdx))
		sig = append(sig, sk[:]...)

		idx := leafIdx
		for cp := uint64(0); cp < A; cp++ {
			sibling := k.levels[t][cp][idx^1]
			sig = append(sig, sibling[:]...)
			idx >>= 1
		}
	}

	sig = append(sig, counter[:]...)

	return sig
}

// Recover mirrors ForsVerifier.recover: it returns the signer address a signature
// authenticates for `digest`, or an error when the blob is malformed or fails the
// grinding check. Like the contract it does not know the expected key; a signature by a
// different key simply recovers a different address.
func Recover(sig []byte, digest common.Hash) (common.Address, error) {
	if len(sig) != SigLen {
		return common.Address{}, fmt.Errorf("%w: length %d, want %d", ErrBadSignature, len(sig), SigLen)
	}

	var r, pkSeed, counter [N]byte

	copy(r[:], sig[0:N])
	copy(pkSeed[:], sig[N:2*N])
	copy(counter[:], sig[SigLen-N:])

	md := digits(hmsg(pkSeed, r, digest, counter))
	if md[RealTrees] != 0 {
		return common.Address{}, fmt.Errorf("%w: grinding check failed", ErrBadSignature)
	}

	var roots [RealTrees][N]byte

	for t := uint64(0); t < RealTrees; t++ {
		off := 2*N + int(t)*treeOpeningLen

		var sk [N]byte

		copy(sk[:], sig[off:off+N])

		leafIdx := md[t]
		node := f(pkSeed, adrsLeaf(t, leafIdx), sk)
		idx := leafIdx

		for cp := uint64(1); cp <= A; cp++ {
			var sibling [N]byte

			copy(sibling[:], sig[off+N+int(cp-1)*N:off+N+int(cp)*N])

			parentIdx := idx >> 1
			if idx&1 == 0 {
				node = h(pkSeed, adrsNode(t, cp, parentIdx), node, sibling)
			} else {
				node = h(pkSeed, adrsNode(t, cp, parentIdx), sibling, node)
			}

			idx = parentIdx
		}

		roots[t] = node
	}

	return addressOf(pkSeed, compressRoots(pkSeed, roots)), nil
}
