package pqsphincstx

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/sphincsg"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txtypes"
)

// WitnessLen is the length of a direct leanSPHINCS proof: the public key followed by the
// signature.
const WitnessLen = sphincsg.PublicKeyLen + sphincsg.SigLen

// selfDependency is the dependency an account's transaction declares: a leanSPHINCS
// signature of `key` over the transaction's own signature hash, which the zero data hash
// stands for.
func selfDependency(key common.Hash) txtypes.FrameDependency {
	return txtypes.FrameDependency{
		Scheme:          txtypes.DepSchemeLeanSphincs,
		VerificationKey: key,
	}
}

// witness encodes the proof of a leanSPHINCS dependency: PK.seed || PK.root || signature.
func witness(key common.Hash, signature []byte) []byte {
	out := make([]byte, 0, WitnessLen)
	out = append(out, key[:]...)
	out = append(out, signature...)

	return out
}

// wrap builds the direct mempool wrapper of one transaction whose only dependency is
// its own signature, and returns its encoding.
func wrap(tx *txtypes.Transaction, sigHash, key common.Hash, signature []byte) ([]byte, error) {
	// The wrapper lists the resolved dependency: it carries the signature hash where
	// the frame carries zero.
	resolved := selfDependency(key)
	resolved.DataHash = sigHash

	wrapper, err := txtypes.NewDirectProofWrapper(
		[]*txtypes.Transaction{tx},
		map[txtypes.FrameDependency][]byte{resolved: witness(key, signature)},
	)
	if err != nil {
		return nil, err
	}

	if err := wrapper.Validate(); err != nil {
		return nil, err
	}

	return wrapper.MarshalBinary()
}

// submitWrapper hands the wrapper of a signed transaction to one client and checks that
// the node admitted the transaction. It is the tx pool's submit callback: a transaction
// with a dependency frame is refused by eth_sendRawTransaction.
func submitWrapper(ctx context.Context, client *spamoor.Client, signed *signedTx) error {
	hashes, err := client.SendProofWrapper(ctx, signed.wrapper)
	if err != nil {
		if isKnownError(err) {
			return nil
		}

		return err
	}

	want := signed.tx.Hash()
	for _, hash := range hashes {
		if hash == want {
			return nil
		}
	}

	return fmt.Errorf("node answered %v, which does not include the transaction", hashes)
}

// isKnownError reports whether a submission error only says the node already holds the
// transaction, which a redundant submission or a rebroadcast expects.
func isKnownError(err error) bool {
	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "already known") || strings.Contains(msg, "alreadyknown") ||
		strings.Contains(msg, "known transaction")
}
