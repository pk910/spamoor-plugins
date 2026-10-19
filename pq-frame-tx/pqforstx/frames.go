package pqforstx

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/contract"
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/fors"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txtypes"
)

// operation is the user operation frame of one transaction.
type operation struct {
	kind     string
	target   common.Address
	value    *uint256.Int
	data     []byte
	execGas  uint64
	stateGas uint64
}

// buildOperation picks and encodes the user operation for a transaction index.
func (s *Scenario) buildOperation(txIdx uint64, acct *account) (*operation, error) {
	kind := s.options.Operation
	if kind == OperationMixed {
		if txIdx%2 == 0 {
			kind = OperationEth
		} else {
			kind = OperationErc20
		}
	}

	amount := uint256.NewInt(s.options.Amount)
	amount = amount.Mul(amount, uint256.NewInt(1_000_000_000))
	amount = randomAmount(amount, s.options.RandomAmount)

	// default target: the next child wallet, which exists and is cheap to credit
	targetWallet := s.walletPool.GetWallet(spamoor.SelectWalletByIndex, int(txIdx)+1)
	if targetWallet == nil {
		return nil, fmt.Errorf("no target wallet")
	}

	target := targetWallet.GetAddress()
	targetEmpty := false

	if s.options.RandomTarget {
		addrBytes := make([]byte, 20)
		if _, err := rand.Read(addrBytes); err != nil {
			return nil, err
		}

		target = common.BytesToAddress(addrBytes)
		targetEmpty = true
	}

	op := &operation{kind: kind}

	switch kind {
	case OperationEth:
		op.target = target
		op.value = amount
		op.execGas = ethOpGas

		if targetEmpty {
			op.stateGas = txtypes.StateBytesPerNewAccount * txtypes.CostPerStateByte
		}
	case OperationErc20:
		data, err := contract.TestTokenTransferMintCalldata(target, amount.ToBig())
		if err != nil {
			return nil, fmt.Errorf("encode transferMint: %w", err)
		}

		op.target = s.token
		op.value = new(uint256.Int)
		op.data = data
		op.execGas = erc20OpGas
		// up to two fresh balance slots: the account's own on its first mint, and the
		// recipient's
		op.stateGas = 2 * txtypes.StateBytesPerStorageSet * txtypes.CostPerStateByte
	default:
		return nil, fmt.Errorf("unknown operation %q", kind)
	}

	if s.options.OpGas > 0 {
		op.execGas = s.options.OpGas
	}

	if s.options.OpStateGas > 0 {
		op.stateGas = s.options.OpStateGas
	}

	_ = acct

	return op, nil
}

// buildFrameTx assembles [self_verify, rotate, op], signs the canonical signature hash with
// the account's current FORS+C key and self-checks the witness against the verifier logic.
func (s *Scenario) buildFrameTx(acct *account, op *operation, nonce uint64, feeCap, tipCap *big.Int) (*txtypes.FrameTx, common.Hash, error) {
	accountAddr := acct.address
	target := op.target

	frames := []*txtypes.Frame{
		txtypes.SelfVerifyFrame(txtypes.FrameLimits{Execution: s.options.VerifyGas}),
		{
			Mode:   txtypes.FrameModeSender,
			Flags:  txtypes.ApproveNone,
			Target: &accountAddr,
			Limits: txtypes.FrameLimits{Execution: s.options.RotateGas, State: s.options.RotateStateGas},
			Value:  new(uint256.Int),
			Data:   contract.RotateCalldata(acct.current.Address, acct.next.Address),
		},
		txtypes.UserOpFrame(&target, op.value, op.data, txtypes.FrameLimits{Execution: op.execGas, State: op.stateGas}),
	}

	signatures := []*txtypes.FrameSignature{txtypes.ArbitrarySignature(make([]byte, fors.SigLen))}

	fees := txtypes.FrameFees{
		GasTipCap: uint256.MustFromBig(tipCap),
		GasFeeCap: uint256.MustFromBig(feeCap),
	}

	frameTx := txtypes.NewFrameTxWithExtensions(s.extensions, uint256.MustFromBig(s.walletPool.GetChainId()), acct.address, nonce, fees, frames, signatures)

	// The ARBITRARY witness is elided from the signature hash, so the hash of the
	// placeholder transaction is the message to sign.
	sigHash := frameTx.SigHash()
	witness := acct.current.Sign(sigHash)

	recovered, err := fors.Recover(witness, sigHash)
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("self-check of FORS+C witness: %w", err)
	}

	if recovered != acct.current.Address {
		return nil, common.Hash{}, fmt.Errorf("self-check of FORS+C witness recovered %s, want %s", recovered.Hex(), acct.current.Address.Hex())
	}

	frameTx.Signatures[0].Signature = witness

	return frameTx, sigHash, nil
}

// validate runs the local validity and public mempool checks so a malformed transaction
// is reported here rather than as an opaque RPC rejection.
func (s *Scenario) validate(tx *txtypes.FrameTx) error {
	if err := tx.ValidatePayload(); err != nil {
		return err
	}

	if err := tx.VerifySignatures(); err != nil {
		return err
	}

	if s.options.SkipMempoolCheck {
		return nil
	}

	return tx.ValidateMempoolPrefix()
}
