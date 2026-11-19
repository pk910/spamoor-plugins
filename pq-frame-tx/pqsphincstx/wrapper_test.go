package pqsphincstx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/sphincsg"
	"github.com/ethpandaops/spamoor/txtypes"
)

func TestSelfDependency(t *testing.T) {
	key := common.HexToHash("0x5eed5eed5eed5eed5eed5eed5eed5eedb770f57a2c5913e5294a4ccf28e7240e")
	dep := selfDependency(key)

	require.Equal(t, txtypes.DepSchemeLeanSphincs, dep.Scheme)
	require.True(t, dep.SignsTransaction(), "the frame carries a zero data hash")
	require.Equal(t, key, dep.VerificationKey)

	frame := txtypes.DependencyFrame(dep)
	require.Equal(t, txtypes.FrameModeDepVerify, frame.Mode)
	require.Nil(t, frame.Target, "the target is absent, not the zero address")
	require.Equal(t, uint64(txtypes.LeanSphincsVerificationGas), frame.Limits.Execution)
	require.Len(t, frame.Data, txtypes.DependencyTripleBytes)
}

func TestWitness(t *testing.T) {
	key := common.HexToHash("0x5eed5eed5eed5eed5eed5eed5eed5eedb770f57a2c5913e5294a4ccf28e7240e")
	signature := bytes.Repeat([]byte{0x22}, sphincsg.SigLen)

	proof := witness(key, signature)

	require.Equal(t, 6208, WitnessLen)
	require.Len(t, proof, WitnessLen)
	require.Equal(t, key[:], proof[:sphincsg.PublicKeyLen])
	require.Equal(t, signature, proof[sphincsg.PublicKeyLen:])
}

func TestIsKnownError(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"already known", true},
		{"AlreadyKnown", true},
		{"Known transaction: 0x01", true},
		{"a wrapper dependency proof failed verification", false},
		{"Proof admission is busy; retry later.", false},
	}

	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			require.Equal(t, tt.want, isKnownError(errors.New(tt.msg)))
		})
	}
}
