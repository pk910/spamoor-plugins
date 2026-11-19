// Package sphincsg implements the SPHINCS-G signature scheme in the one parameter set
// the EIP-8288 leanSPHINCS dependency (scheme 0x10) of daisugi-devnet-0 verifies:
// n=16, h=20 over d=5 layers of height 4, FORS with k=19 trees of height a=9, WOTS+ with
// w=16 (l=35), keccak256 everywhere. A signature is 6,176 bytes.
//
// It is byte-compatible with the reference signer of the NiceTry wallet
// (asanso/AA-PQ, aggregation/frames/extension/src/crypto/sphincs.js, the
// "ledger_prepared_16_20" set), including the key derivation from a 32-byte secret.
//
// SPHINCS-G is stateless and many-time: one key signs any number of messages, so an
// account never has to rotate it.
package sphincsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Scheme parameters.
const (
	N = 16 // hash output and secret length in bytes

	H        = 20 // total hypertree height
	D        = 5  // hypertree layers
	SubtreeH = 4  // height of one layer's Merkle tree
	K        = 19 // FORS trees
	A        = 9  // FORS tree height
	W        = 16 // Winternitz parameter
	L        = 35 // WOTS+ chains: 32 message digits and a 3-digit checksum

	logW       = 4
	wotsLen1   = 2 * N // message digits
	wotsLen2   = L - wotsLen1
	leaves     = 1 << SubtreeH
	forsLeaves = 1 << A

	forsOpeningLen = N + A*N // secret || auth path
	wotsSigLen     = L * N
	layerLen       = wotsSigLen + SubtreeH*N

	forsOffset = N
	htOffset   = forsOffset + K*forsOpeningLen

	// SigLen is the signature length: R || K FORS openings || D * (WOTS+ || auth path).
	SigLen = htOffset + D*layerLen

	// PublicKeyLen is the length of the public key PK.seed || PK.root.
	PublicKeyLen = 2 * N

	adrsWotsHash  = 0
	adrsWotsPk    = 1
	adrsTree      = 2
	adrsForsTree  = 3
	adrsForsRoots = 4
)

// ErrBadSignature is returned by Verify for a signature that does not open to the key.
var ErrBadSignature = errors.New("sphincsg: invalid signature")

var (
	// paramDomain separates the keys of this parameter set from the reference signer's
	// other sets.
	paramDomain = []byte("ledger_prepared_16_20")

	tagSkSeed = []byte("sphincs+c:sk-seed:v1")
	tagPkSeed = []byte("sphincs+c:pk-seed:v1")
	tagWotsSk = []byte("sphincs+c:wots-sk:v1")
	tagForsSk = []byte("sphincs+c:fors-sk:v1")
	tagR      = []byte("sphincs+c:r:v1")

	// hMsgPad is the first word of the compact H_msg preimage.
	hMsgPad = bytes.Repeat([]byte{0xff}, 32)
)

// cachedLayers is the number of top hypertree layers whose WOTS+ public keys a key
// remembers: the root tree and the 16 trees below it. Deeper layers are too many to hit.
const cachedLayers = 2

// Key is a SPHINCS-G key pair.
type Key struct {
	skSeed [32]byte
	pkSeed [N]byte
	pkRoot [N]byte

	// mu guards subtrees, the WOTS+ public keys of the cached hypertree layers.
	mu       sync.Mutex
	subtrees map[uint64][]byte
}

// hasher computes the scheme's tweakable hash T(PK.seed, ADRS, words...), reusing one
// preimage buffer. It is not safe for concurrent use.
type hasher struct {
	buf []byte // pad32(PK.seed) || ADRS || up to L 32-byte words
}

func newHasher(pkSeed []byte) *hasher {
	h := &hasher{buf: make([]byte, 64+L*32)}
	copy(h.buf, pkSeed[:N])

	return h
}

// adrs sets the 32-byte address: layer, the tree index in the low 8 bytes of the tree
// field, the type and three type-specific words.
func (h *hasher) adrs(layer uint32, tree uint64, typ, w1, w2, w3 uint32) {
	a := h.buf[32:64]
	binary.BigEndian.PutUint32(a[0:4], layer)
	binary.BigEndian.PutUint32(a[4:8], 0)
	binary.BigEndian.PutUint64(a[8:16], tree)
	binary.BigEndian.PutUint32(a[16:20], typ)
	binary.BigEndian.PutUint32(a[20:24], w1)
	binary.BigEndian.PutUint32(a[24:28], w2)
	binary.BigEndian.PutUint32(a[28:32], w3)
}

// setWord places a 16-byte value in the top half of payload word i.
func (h *hasher) setWord(i int, v []byte) {
	off := 64 + i*32
	copy(h.buf[off:off+N], v[:N])
}

// sum writes the hash over the address and the first `words` payload words to out.
func (h *hasher) sum(words int, out []byte) {
	copy(out[:N], crypto.Keccak256(h.buf[:64+words*32]))
}

// f hashes one payload word, the chain and leaf function.
func (h *hasher) f(in, out []byte) {
	h.setWord(0, in)
	h.sum(1, out)
}

// node hashes two children into their parent.
func (h *hasher) node(left, right, out []byte) {
	h.setWord(0, left)
	h.setWord(1, right)
	h.sum(2, out)
}

// DeriveKey derives the key pair of a 32-byte secret, as the reference signer derives it
// from an HD private key.
func DeriveKey(secret common.Hash) *Key {
	key := &Key{subtrees: make(map[uint64][]byte, 1+leaves)}

	copy(key.skSeed[:], crypto.Keccak256(tagSkSeed, paramDomain, secret.Bytes()))
	copy(key.pkSeed[:], crypto.Keccak256(tagPkSeed, paramDomain, secret.Bytes()))

	// The public root is the root of the single tree of the top layer.
	h := newHasher(key.pkSeed[:])
	root, _ := key.subtree(h, D-1, 0, 0)
	copy(key.pkRoot[:], root)

	return key
}

// PkSeed returns the public seed.
func (k *Key) PkSeed() [N]byte { return k.pkSeed }

// PkRoot returns the public root.
func (k *Key) PkRoot() [N]byte { return k.pkRoot }

// PublicKey returns PK.seed || PK.root, the 32-byte key an EIP-8288 dependency carries.
func (k *Key) PublicKey() common.Hash {
	var pk common.Hash

	copy(pk[:N], k.pkSeed[:])
	copy(pk[N:], k.pkRoot[:])

	return pk
}

// wotsSk is the secret start of one WOTS+ chain.
func (k *Key) wotsSk(layer uint32, tree uint64, keypair, chain uint32) []byte {
	var idx [20]byte

	binary.BigEndian.PutUint32(idx[0:4], layer)
	binary.BigEndian.PutUint64(idx[4:12], tree)
	binary.BigEndian.PutUint32(idx[12:16], keypair)
	binary.BigEndian.PutUint32(idx[16:20], chain)

	return crypto.Keccak256(k.skSeed[:], tagWotsSk, idx[:])[:N]
}

// forsSk is the secret of one FORS leaf.
func (k *Key) forsSk(tree uint64, leaf, forsTree, leafIdx uint32) []byte {
	var idx [20]byte

	binary.BigEndian.PutUint64(idx[0:8], tree)
	binary.BigEndian.PutUint32(idx[8:12], leaf)
	binary.BigEndian.PutUint32(idx[12:16], forsTree)
	binary.BigEndian.PutUint32(idx[16:20], leafIdx)

	return crypto.Keccak256(k.skSeed[:], tagForsSk, idx[:])[:N]
}

// chain advances a WOTS+ chain value in place from position `from` to position `to`.
func chain(h *hasher, layer uint32, tree uint64, keypair, chainIdx uint32, val []byte, from, to uint32) {
	for p := from; p < to; p++ {
		h.adrs(layer, tree, adrsWotsHash, keypair, chainIdx, p)
		h.f(val, val)
	}
}

// wotsPk writes the compressed WOTS+ public key of one keypair to out.
func (k *Key) wotsPk(h *hasher, layer uint32, tree uint64, keypair uint32, out []byte) {
	ends := make([]byte, L*N)

	for i := uint32(0); i < L; i++ {
		end := ends[i*N : (i+1)*N]
		copy(end, k.wotsSk(layer, tree, keypair, i))
		chain(h, layer, tree, keypair, i, end, 0, W-1)
	}

	compressWotsPk(h, layer, tree, keypair, ends, out)
}

// compressWotsPk hashes the L chain ends of a keypair into its public key.
func compressWotsPk(h *hasher, layer uint32, tree uint64, keypair uint32, ends, out []byte) {
	h.adrs(layer, tree, adrsWotsPk, keypair, 0, 0)

	for i := 0; i < L; i++ {
		h.setWord(i, ends[i*N:(i+1)*N])
	}

	h.sum(L, out)
}

// subtreeLeaves returns the 16 WOTS+ public keys of one hypertree tree, from the cache
// for the top layers.
func (k *Key) subtreeLeaves(h *hasher, layer uint32, tree uint64) []byte {
	cached := layer >= D-cachedLayers
	cacheKey := uint64(layer)<<32 | tree

	if cached {
		k.mu.Lock()
		nodes, ok := k.subtrees[cacheKey]
		k.mu.Unlock()

		if ok {
			return nodes
		}
	}

	nodes := make([]byte, leaves*N)
	for j := uint32(0); j < leaves; j++ {
		k.wotsPk(h, layer, tree, j, nodes[j*N:(j+1)*N])
	}

	if cached {
		k.mu.Lock()
		k.subtrees[cacheKey] = nodes
		k.mu.Unlock()
	}

	return nodes
}

// subtree returns the root of one hypertree tree and the authentication path of a leaf.
func (k *Key) subtree(h *hasher, layer uint32, tree uint64, leafIdx uint32) (root, auth []byte) {
	level := append([]byte(nil), k.subtreeLeaves(h, layer, tree)...)
	auth = make([]byte, 0, SubtreeH*N)
	idx := leafIdx

	for height := uint32(0); height < SubtreeH; height++ {
		sibling := idx ^ 1
		auth = append(auth, level[sibling*N:(sibling+1)*N]...)

		parents := uint32(len(level)/N) / 2
		for p := uint32(0); p < parents; p++ {
			h.adrs(layer, tree, adrsTree, 0, height+1, p)
			// The parent overwrites the left child's slot, which is not read again.
			h.node(level[2*p*N:(2*p+1)*N], level[(2*p+1)*N:(2*p+2)*N], level[p*N:(p+1)*N])
		}

		level = level[:parents*N]
		idx >>= 1
	}

	return level[:N], auth
}

// forsTree returns the root of one FORS tree and the authentication path of a leaf.
func (k *Key) forsTree(h *hasher, tree uint64, leaf, forsTree, revealIdx uint32) (root, auth []byte) {
	level := make([]byte, forsLeaves*N)

	for j := uint32(0); j < forsLeaves; j++ {
		h.adrs(0, tree, adrsForsTree, leaf, 0, forsTree<<A|j)
		h.f(k.forsSk(tree, leaf, forsTree, j), level[j*N:(j+1)*N])
	}

	auth = make([]byte, 0, A*N)
	idx := revealIdx

	for height := uint32(0); height < A; height++ {
		sibling := idx ^ 1
		auth = append(auth, level[sibling*N:(sibling+1)*N]...)

		parents := uint32(len(level)/N) / 2
		for p := uint32(0); p < parents; p++ {
			h.adrs(0, tree, adrsForsTree, leaf, height+1, forsTree<<(A-1-height)|p)
			h.node(level[2*p*N:(2*p+1)*N], level[(2*p+1)*N:(2*p+2)*N], level[p*N:(p+1)*N])
		}

		level = level[:parents*N]
		idx >>= 1
	}

	return level[:N], auth
}

// digest is a decoded H_msg: the hypertree leaf the message selects and the leaf each
// FORS tree reveals.
type digest struct {
	tree   uint64
	leaf   uint32
	fields [K]uint32
}

// hashMessage computes the compact H_msg and decodes it. FORS field i is bits
// [i*A, (i+1)*A) of the digest counted from its low end, the hypertree index the H bits
// above them.
func hashMessage(pkSeed, pkRoot, r []byte, msg common.Hash) digest {
	d := crypto.Keccak256(hMsgPad, r[:N], pkSeed[:N], pkRoot[:N], msg.Bytes())

	var out digest

	for i := range out.fields {
		out.fields[i] = uint32(bitField(d, uint(i*A), A))
	}

	htIdx := bitField(d, K*A, H)
	out.leaf = uint32(htIdx & (leaves - 1))
	out.tree = htIdx >> SubtreeH

	return out
}

// bitField reads `width` bits of a big-endian 256-bit value starting `shift` bits above
// its least significant bit.
func bitField(d []byte, shift, width uint) uint64 {
	var v uint64

	for i := uint(0); i < width; i++ {
		bit := shift + i
		if d[31-bit/8]>>(bit%8)&1 == 1 {
			v |= 1 << i
		}
	}

	return v
}

// wotsDigits splits a node into the 32 base-16 message digits and the 3 checksum digits
// a WOTS+ signature opens.
func wotsDigits(node []byte) [L]uint32 {
	var digits [L]uint32

	csum := uint32(0)

	for i := 0; i < wotsLen1; i++ {
		b := uint32(node[i/2])
		if i%2 == 0 {
			digits[i] = b >> logW
		} else {
			digits[i] = b & (W - 1)
		}

		csum += W - 1 - digits[i]
	}

	// The checksum is shifted to a byte boundary before it is split, most significant
	// digit first.
	csum <<= (8 - (wotsLen2*logW)%8) % 8

	for i := 0; i < wotsLen2; i++ {
		digits[wotsLen1+i] = csum >> ((wotsLen2 - i) * logW) & (W - 1)
	}

	return digits
}

// forsPk compresses the K FORS roots into the FORS public key.
func forsPk(h *hasher, tree uint64, leaf uint32, roots, out []byte) {
	h.adrs(0, tree, adrsForsRoots, leaf, 0, 0)

	for i := 0; i < K; i++ {
		h.setWord(i, roots[i*N:(i+1)*N])
	}

	h.sum(K, out)
}

// Sign signs a 32-byte message. The signature is deterministic in the key and message.
func (k *Key) Sign(msg common.Hash) []byte {
	h := newHasher(k.pkSeed[:])
	sig := make([]byte, SigLen)

	copy(sig[:N], crypto.Keccak256(k.skSeed[:], tagR, msg.Bytes()))

	d := hashMessage(k.pkSeed[:], k.pkRoot[:], sig[:N], msg)

	// FORS: every tree opens the leaf its digest field selects.
	roots := make([]byte, K*N)

	for i := uint32(0); i < K; i++ {
		opening := sig[forsOffset+int(i)*forsOpeningLen:]
		copy(opening[:N], k.forsSk(d.tree, d.leaf, i, d.fields[i]))

		root, auth := k.forsTree(h, d.tree, d.leaf, i, d.fields[i])
		copy(opening[N:forsOpeningLen], auth)
		copy(roots[i*N:(i+1)*N], root)
	}

	node := make([]byte, N)
	forsPk(h, d.tree, d.leaf, roots, node)

	// Hypertree: each layer signs the node below it and authenticates its own leaf.
	tree, leaf := d.tree, d.leaf

	for layer := uint32(0); layer < D; layer++ {
		layerSig := sig[htOffset+int(layer)*layerLen:]
		digits := wotsDigits(node)

		for i := uint32(0); i < L; i++ {
			val := layerSig[i*N : (i+1)*N]
			copy(val, k.wotsSk(layer, tree, leaf, i))
			chain(h, layer, tree, leaf, i, val, 0, digits[i])
		}

		root, auth := k.subtree(h, layer, tree, leaf)
		copy(layerSig[wotsSigLen:layerLen], auth)
		copy(node, root)

		leaf = uint32(tree & (leaves - 1))
		tree >>= SubtreeH
	}

	return sig
}

// Verify checks a signature of msg against the public key pkSeed, pkRoot.
func Verify(pkSeed, pkRoot [N]byte, msg common.Hash, sig []byte) error {
	if len(sig) != SigLen {
		return ErrBadSignature
	}

	h := newHasher(pkSeed[:])
	d := hashMessage(pkSeed[:], pkRoot[:], sig[:N], msg)

	roots := make([]byte, K*N)
	node := make([]byte, N)

	for i := uint32(0); i < K; i++ {
		opening := sig[forsOffset+int(i)*forsOpeningLen:]
		idx := d.fields[i]

		h.adrs(0, d.tree, adrsForsTree, d.leaf, 0, i<<A|idx)
		h.f(opening[:N], node)

		for height := uint32(0); height < A; height++ {
			sibling := opening[N+height*N : N+(height+1)*N]
			h.adrs(0, d.tree, adrsForsTree, d.leaf, height+1, i<<(A-1-height)|idx>>1)

			if idx&1 == 1 {
				h.node(sibling, node, node)
			} else {
				h.node(node, sibling, node)
			}

			idx >>= 1
		}

		copy(roots[i*N:(i+1)*N], node)
	}

	forsPk(h, d.tree, d.leaf, roots, node)

	tree, leaf := d.tree, d.leaf
	ends := make([]byte, L*N)

	for layer := uint32(0); layer < D; layer++ {
		layerSig := sig[htOffset+int(layer)*layerLen:]
		digits := wotsDigits(node)

		copy(ends, layerSig[:wotsSigLen])

		for i := uint32(0); i < L; i++ {
			chain(h, layer, tree, leaf, i, ends[i*N:(i+1)*N], digits[i], W-1)
		}

		compressWotsPk(h, layer, tree, leaf, ends, node)

		idx := leaf

		for height := uint32(0); height < SubtreeH; height++ {
			sibling := layerSig[wotsSigLen+height*N : wotsSigLen+(height+1)*N]
			h.adrs(layer, tree, adrsTree, 0, height+1, idx>>1)

			if idx&1 == 1 {
				h.node(sibling, node, node)
			} else {
				h.node(node, sibling, node)
			}

			idx >>= 1
		}

		leaf = uint32(tree & (leaves - 1))
		tree >>= SubtreeH
	}

	if !bytes.Equal(node, pkRoot[:]) {
		return ErrBadSignature
	}

	return nil
}
