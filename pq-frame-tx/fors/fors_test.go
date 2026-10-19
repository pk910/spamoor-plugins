package fors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

// vector is the JSON emitted by scripts/signing_reference.py --scheme fors of
// RivaLabs-Core/Post-Quantum-AA-Infra, the oracle this package has to match.
type vector struct {
	Index     uint64         `json:"index"`
	Digest    common.Hash    `json:"digest"`
	SkSeed    hexutil.Bytes  `json:"skSeed"`
	PkSeed    hexutil.Bytes  `json:"pkSeed"`
	PkRoot    hexutil.Bytes  `json:"pkRoot"`
	Address   common.Address `json:"address"`
	Signature hexutil.Bytes  `json:"signature"`
	Counter   hexutil.Bytes  `json:"counter"`
	R         hexutil.Bytes  `json:"R"`
}

// masterSecrets are the --master-secret values the testdata vectors were generated with,
// keyed by file name.
var masterSecrets = map[string]common.Hash{
	"fors-0.json": common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000aa"),
	"fors-1.json": common.HexToHash("0x4f1c9e0b7d3a5c2e8f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e"),
	"fors-2.json": common.HexToHash("0x4f1c9e0b7d3a5c2e8f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e"),
	"fors-3.json": common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}

func loadVectors(t *testing.T) map[string]*vector {
	t.Helper()

	files, err := filepath.Glob("testdata/fors-*.json")
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

func TestReferenceVectors(t *testing.T) {
	for name, v := range loadVectors(t) {
		t.Run(name, func(t *testing.T) {
			secret, ok := masterSecrets[name]
			require.True(t, ok, "no master secret recorded for %s", name)

			key := DeriveKey(secret, v.Index)

			require.Equal(t, []byte(v.SkSeed), key.SkSeed[:], "skSeed")
			require.Equal(t, []byte(v.PkSeed), key.PkSeed[:], "pkSeed")
			require.Equal(t, []byte(v.PkRoot), key.PkRoot[:], "pkRoot")
			require.Equal(t, v.Address, key.Address, "address")

			sig := key.Sign(v.Digest)
			require.Len(t, sig, SigLen)
			require.Equal(t, []byte(v.R), sig[:N], "R")
			require.Equal(t, []byte(v.Counter), sig[SigLen-N:], "counter")
			require.Equal(t, []byte(v.Signature), sig, "signature")

			recovered, err := Recover(sig, v.Digest)
			require.NoError(t, err)
			require.Equal(t, v.Address, recovered)
		})
	}
}

func TestRecoverRejectsTampering(t *testing.T) {
	key := DeriveKey(common.HexToHash("0x01"), 3)
	digest := common.HexToHash("0xabcdef")
	sig := key.Sign(digest)

	cases := map[string]int{
		"R":        0,
		"pkSeed":   N + 1,
		"leafSk":   2*N + 5,
		"authPath": 2*N + N + 7,
		"lastTree": SigLen - N - 3,
		"counter":  SigLen - 1,
	}

	for name, pos := range cases {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte(nil), sig...)
			bad[pos] ^= 0x01

			recovered, err := Recover(bad, digest)
			if err == nil {
				require.NotEqual(t, key.Address, recovered, "tampered signature must not recover the signer")
			}
		})
	}

	t.Run("wrong digest", func(t *testing.T) {
		recovered, err := Recover(sig, common.HexToHash("0xabcdee"))
		if err == nil {
			require.NotEqual(t, key.Address, recovered)
		}
	})

	t.Run("bad length", func(t *testing.T) {
		_, err := Recover(sig[:SigLen-1], digest)
		require.ErrorIs(t, err, ErrBadSignature)
	})
}

func TestChainKeysAreDistinct(t *testing.T) {
	secret := common.HexToHash("0x42")
	seen := make(map[common.Address]bool, 8)

	for i := uint64(0); i < 8; i++ {
		addr := DeriveKey(secret, i).Address
		require.False(t, seen[addr], "duplicate address at index %d", i)
		seen[addr] = true
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DeriveKey(common.HexToHash("0x01"), uint64(i))
	}
}

func BenchmarkSign(b *testing.B) {
	key := DeriveKey(common.HexToHash("0x01"), 0)
	digest := common.HexToHash("0xabcdef")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		digest[0] = byte(i)
		key.Sign(digest)
	}
}
