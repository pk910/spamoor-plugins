package pqsphincstx

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/sphincsg"
	"github.com/ethpandaops/spamoor/txtypes"
)

func testTx(t *testing.T) (*sphincsg.Key, *txParams, *operation, *signedTx) {
	t.Helper()

	key := sphincsg.DeriveKey(common.HexToHash("0xaa"))
	params := &txParams{
		extensions: txtypes.FrameExtAll,
		chainID:    big.NewInt(701563864),
		sender:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
		nonce:      7,
		verifyGas:  50_000,
		feeCap:     big.NewInt(20_000_000_000),
		tipCap:     big.NewInt(2_000_000_000),
	}
	op := &operation{
		kind:    OperationEth,
		target:  common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		value:   uint256.NewInt(123),
		execGas: ethOpGas,
	}

	signed, err := signFrameTx(key, params, op)
	require.NoError(t, err)

	return key, params, op, signed
}

func TestSignFrameTx(t *testing.T) {
	key, params, op, signed := testTx(t)

	frameTx, ok := signed.tx.Inner().(*txtypes.FrameTx)
	require.True(t, ok)

	require.Equal(t, params.sender, frameTx.Sender)
	require.Equal(t, params.nonce, frameTx.NonceSeq)
	require.Empty(t, frameTx.NonceKeys, "the account nonce is selected by an empty key set")
	require.Empty(t, frameTx.Signatures, "the signature travels in the wrapper")
	require.Len(t, frameTx.Frames, frameCount)

	dep := frameTx.Frames[frameDependency]
	require.Equal(t, txtypes.FrameModeDepVerify, dep.Mode)
	require.Equal(t, []txtypes.FrameDependency{selfDependency(key.PublicKey())}, dep.Dependencies())

	verify := frameTx.Frames[frameVerify]
	require.Equal(t, txtypes.FrameModeVerify, verify.Mode)
	require.Equal(t, uint8(txtypes.ApproveExecutionAndPayment), verify.Flags)
	require.Nil(t, verify.Target)

	call := frameTx.Frames[frameOperation]
	require.Equal(t, txtypes.FrameModeSender, call.Mode)
	require.Equal(t, op.target, *call.Target)
	require.Equal(t, op.value, call.Value)

	// the budget is the maximum gas at the fee cap, the recursive STARK share included
	require.Equal(t, uint64(txtypes.LeanStarkVerificationGas), frameTx.RecursiveStarkGas())

	wantFee := new(big.Int).SetUint64(frameTx.MaxGas())
	wantFee.Mul(wantFee, params.feeCap)
	require.Equal(t, wantFee, frameTx.GetMaxFee())

	require.NoError(t, signed.validate(false), "the transaction passes the local checks")

	sigHash, err := frameTx.SigHash()
	require.NoError(t, err)
	require.Equal(t, signed.sigHash, sigHash)

	wrapper := &txtypes.ProofWrapper{}
	require.NoError(t, wrapper.UnmarshalBinary(signed.wrapper))
	require.NoError(t, wrapper.Validate())
	require.Equal(t, uint8(txtypes.ProofWrapperModeDirect), wrapper.Mode)
	require.Len(t, wrapper.Transactions, 1)

	// the wrapped transaction is the one the node will hash and include
	require.Equal(t, signed.tx.Hash(), wrapper.Transactions[0].Hash())

	// the wrapper lists the resolved dependency and proves it with the signature
	resolved := selfDependency(key.PublicKey())
	resolved.DataHash = sigHash

	require.Equal(t, []txtypes.FrameDependency{resolved}, wrapper.Dependencies)
	require.Len(t, wrapper.Proofs, 1)

	proof := wrapper.Proofs[0]
	require.Len(t, proof, WitnessLen)
	require.Equal(t, key.PublicKey().Bytes(), proof[:sphincsg.PublicKeyLen])
	require.NoError(t, sphincsg.Verify(key.PkSeed(), key.PkRoot(), sigHash, proof[sphincsg.PublicKeyLen:]))
}

// TestWrapperEncoding pins the wire bytes of the fixture: this exact wrapper passed the
// proof verification of a daisugi-devnet-0 node.
func TestWrapperEncoding(t *testing.T) {
	_, _, _, signed := testTx(t)

	require.Equal(t, common.HexToHash("0x2f6d75cfce632cf29228c9bff69a77aa766c83fe15b18742bc9e566a97aab5ea"), signed.tx.Hash())
	require.Len(t, signed.wrapper, 6525)
	require.Equal(t, "e7332d6b0c697edb5c23c453ef4124ccfc7968ed3da75f27ea327b86597ff38a",
		hex.EncodeToString(sha256Sum(signed.wrapper)))
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

func TestSignFrameTxBindsFields(t *testing.T) {
	_, params, op, signed := testTx(t)

	tests := []struct {
		name   string
		mutate func(p *txParams, o *operation)
	}{
		{"nonce", func(p *txParams, _ *operation) { p.nonce++ }},
		{"sender", func(p *txParams, _ *operation) { p.sender[0] ^= 1 }},
		{"chain", func(p *txParams, _ *operation) { p.chainID = big.NewInt(1) }},
		{"fee", func(p *txParams, _ *operation) { p.feeCap = big.NewInt(21_000_000_000) }},
		{"target", func(_ *txParams, o *operation) { o.target[0] ^= 1 }},
		{"value", func(_ *txParams, o *operation) { o.value = uint256.NewInt(124) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, o := *params, *op
			tt.mutate(&p, &o)

			other, err := signFrameTx(sphincsg.DeriveKey(common.HexToHash("0xaa")), &p, &o)
			require.NoError(t, err)
			require.NotEqual(t, signed.sigHash, other.sigHash)
		})
	}
}

func TestSignFrameTxRejectsLegacyFees(t *testing.T) {
	txtypes.LegacyFrameFees = true

	t.Cleanup(func() { txtypes.LegacyFrameFees = false })

	key := sphincsg.DeriveKey(common.HexToHash("0xaa"))
	_, err := signFrameTx(key, &txParams{
		extensions: txtypes.FrameExtAll, chainID: big.NewInt(1), feeCap: big.NewInt(1), tipCap: big.NewInt(1),
	}, &operation{value: new(uint256.Int)})
	require.ErrorContains(t, err, "legacy-frame-fees")
}
