package sphincsg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

// vector is a signature produced by the reference signer. It carries no secret, so it
// pins the verifier; the signer is then held to that verifier.
type vector struct {
	Params struct {
		N               int `json:"n"`
		H               int `json:"h"`
		D               int `json:"d"`
		HPrime          int `json:"hPrime"`
		A               int `json:"a"`
		K               int `json:"k"`
		W               int `json:"w"`
		L               int `json:"l"`
		SignatureLength int `json:"signatureLength"`
	} `json:"params"`
	PkSeed    common.Hash   `json:"pkSeed"`
	PkRoot    common.Hash   `json:"pkRoot"`
	Message   common.Hash   `json:"message"`
	Signature hexutil.Bytes `json:"signature"`
}

func loadVectors(t *testing.T) map[string]*vector {
	t.Helper()

	files, err := filepath.Glob("testdata/sphincs-*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	vectors := make(map[string]*vector, len(files))

	for _, file := range files {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)

		v := &vector{}
		require.NoError(t, json.Unmarshal(raw, v))

		vectors[filepath.Base(file)] = v
	}

	return vectors
}

func half(word common.Hash) [N]byte {
	var out [N]byte

	copy(out[:], word[:N])

	return out
}

func TestParameters(t *testing.T) {
	for name, v := range loadVectors(t) {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, N, v.Params.N)
			require.Equal(t, H, v.Params.H)
			require.Equal(t, D, v.Params.D)
			require.Equal(t, SubtreeH, v.Params.HPrime)
			require.Equal(t, A, v.Params.A)
			require.Equal(t, K, v.Params.K)
			require.Equal(t, W, v.Params.W)
			require.Equal(t, L, v.Params.L)
			require.Equal(t, SigLen, v.Params.SignatureLength)
			require.Equal(t, H, D*SubtreeH)
		})
	}

	require.Equal(t, 6176, SigLen)
}

func TestReferenceVectors(t *testing.T) {
	for name, v := range loadVectors(t) {
		t.Run(name, func(t *testing.T) {
			pkSeed, pkRoot := half(v.PkSeed), half(v.PkRoot)

			require.NoError(t, Verify(pkSeed, pkRoot, v.Message, v.Signature))

			tests := []struct {
				name   string
				mutate func(msg *common.Hash, seed, root *[N]byte, sig []byte) []byte
			}{
				{"message", func(msg *common.Hash, _, _ *[N]byte, sig []byte) []byte { msg[31] ^= 1; return sig }},
				{"pkSeed", func(_ *common.Hash, seed, _ *[N]byte, sig []byte) []byte { seed[0] ^= 1; return sig }},
				{"pkRoot", func(_ *common.Hash, _, root *[N]byte, sig []byte) []byte { root[N-1] ^= 1; return sig }},
				{"R", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { sig[0] ^= 1; return sig }},
				{"fors secret", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { sig[forsOffset] ^= 1; return sig }},
				{"fors auth", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { sig[htOffset-1] ^= 1; return sig }},
				{"wots", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { sig[htOffset] ^= 1; return sig }},
				{"last auth", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { sig[SigLen-1] ^= 1; return sig }},
				{"truncated", func(_ *common.Hash, _, _ *[N]byte, sig []byte) []byte { return sig[:SigLen-1] }},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					msg, seed, root := v.Message, pkSeed, pkRoot
					sig := tt.mutate(&msg, &seed, &root, append([]byte(nil), v.Signature...))

					require.ErrorIs(t, Verify(seed, root, msg, sig), ErrBadSignature)
				})
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	secrets := []common.Hash{
		common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000aa"),
		common.HexToHash("0x4f1c9e0b7d3a5c2e8f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e"),
	}

	for _, secret := range secrets {
		t.Run(secret.Hex()[:10], func(t *testing.T) {
			key := DeriveKey(secret)
			again := DeriveKey(secret)

			require.Equal(t, key.PublicKey(), again.PublicKey())

			pk := key.PublicKey()
			seed, root := key.PkSeed(), key.PkRoot()

			require.Equal(t, seed[:], pk[:N])
			require.Equal(t, root[:], pk[N:])

			// Several messages exercise different hypertree leaves, and with them both
			// the cached and the uncached layers.
			for i := byte(0); i < 4; i++ {
				msg := common.Hash{0xde, 0xad, i}

				sig := key.Sign(msg)
				require.Len(t, sig, SigLen)
				require.NoError(t, Verify(seed, root, msg, sig))
				require.Equal(t, sig, key.Sign(msg), "signing is deterministic")
				require.Equal(t, sig, again.Sign(msg), "a fresh key signs identically")

				other := msg
				other[5] ^= 1
				require.ErrorIs(t, Verify(seed, root, other, sig), ErrBadSignature)
			}
		})
	}

	a, b := DeriveKey(secrets[0]), DeriveKey(secrets[1])
	require.NotEqual(t, a.PublicKey(), b.PublicKey())
}

func BenchmarkSign(b *testing.B) {
	key := DeriveKey(common.HexToHash("0xaa"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key.Sign(common.Hash{byte(i), byte(i >> 8)})
	}
}
