package pqsphincstx

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/contract"
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/sphincsg"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txtypes"
)

// Frame layout of every transaction.
const (
	frameDependency = iota
	frameVerify
	frameOperation
	frameCount
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

// signedTx is a frame transaction with the proof of its dependency.
type signedTx struct {
	tx      *txtypes.Transaction
	frameTx *txtypes.FrameTx
	sigHash common.Hash
	// wrapper is the encoded EIP-8288 mempool wrapper the transaction is submitted in.
	wrapper []byte
}

// validate runs the local validity and public mempool checks so a malformed transaction
// is reported here rather than as an opaque RPC rejection.
func (t *signedTx) validate(skipMempoolCheck bool) error {
	if err := t.frameTx.ValidatePayload(); err != nil {
		return err
	}

	if skipMempoolCheck {
		return nil
	}

	return t.frameTx.ValidateMempoolPrefix()
}

// buildOperation picks and encodes the user operation for a transaction index.
func (s *Scenario) buildOperation(txIdx uint64) (*operation, error) {
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
		addrBytes := make([]byte, common.AddressLength)
		if _, err := rand.Read(addrBytes); err != nil {
			return nil, err
		}

		target = common.BytesToAddress(addrBytes)
		targetEmpty = true
	}

	// zero on a chain without EIP-8037, where state growth is paid from execution gas
	costPerStateByte := s.walletPool.GetTxPool().GetCostPerStateByte()
	op := &operation{kind: kind}

	switch kind {
	case OperationEth:
		op.target = target
		op.value = amount
		op.execGas = ethOpGas

		if targetEmpty {
			op.stateGas = txtypes.StateBytesPerNewAccount * costPerStateByte
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
		op.stateGas = 2 * txtypes.StateBytesPerStorageSet * costPerStateByte
	default:
		return nil, fmt.Errorf("unknown operation %q", kind)
	}

	if s.options.OpGas > 0 {
		op.execGas = s.options.OpGas
	}

	if s.options.OpStateGas >= 0 {
		op.stateGas = uint64(s.options.OpStateGas)
	}

	return op, nil
}

// buildFrameTx builds and signs the transaction of one operation of `acct`.
func (s *Scenario) buildFrameTx(acct *account, op *operation, nonce uint64, feeCap, tipCap *big.Int) (*signedTx, error) {
	return signFrameTx(acct.key, &txParams{
		extensions: s.extensions,
		chainID:    s.walletPool.GetChainId(),
		sender:     acct.address,
		nonce:      nonce,
		verifyGas:  s.options.VerifyGas,
		feeCap:     feeCap,
		tipCap:     tipCap,
	}, op)
}

// txParams are the envelope fields of one transaction.
type txParams struct {
	extensions txtypes.FrameExtensions
	chainID    *big.Int
	sender     common.Address
	nonce      uint64
	verifyGas  uint64
	feeCap     *big.Int
	tipCap     *big.Int
}

// signFrameTx assembles [dependency, self_verify, op], signs the signature hash with the
// SPHINCS key and wraps the transaction with that signature as the proof of its
// dependency. The transaction itself carries no signature.
func signFrameTx(key *sphincsg.Key, params *txParams, op *operation) (*signedTx, error) {
	target := op.target
	publicKey := key.PublicKey()

	frames := make([]*txtypes.Frame, frameCount)
	frames[frameDependency] = txtypes.DependencyFrame(selfDependency(publicKey))
	frames[frameVerify] = txtypes.SelfVerifyFrame(txtypes.FrameLimits{Execution: params.verifyGas})
	frames[frameOperation] = txtypes.UserOpFrame(&target, op.value, op.data,
		txtypes.FrameLimits{Execution: op.execGas, State: op.stateGas})

	fees := txtypes.FrameFees{
		GasTipCap: uint256.MustFromBig(params.tipCap),
		GasFeeCap: uint256.MustFromBig(params.feeCap),
	}

	frameTx := txtypes.NewFrameTxWithExtensions(params.extensions, uint256.MustFromBig(params.chainID),
		params.sender, params.nonce, fees, frames, nil)
	if frameTx.LegacyFees {
		return nil, fmt.Errorf("EIP-8288 chains run the max_fee envelope, drop --legacy-frame-fees")
	}

	// max_fee is part of the signature hash and nothing signs through txtypes here, so
	// the budget is fixed first. It covers the dependency's share of the recursive STARK.
	if err := frameTx.DeriveMaxFee(); err != nil {
		return nil, fmt.Errorf("derive max_fee: %w", err)
	}

	sigHash, err := frameTx.SigHash()
	if err != nil {
		return nil, fmt.Errorf("signature hash: %w", err)
	}

	signature := key.Sign(sigHash)

	if err := sphincsg.Verify(key.PkSeed(), key.PkRoot(), sigHash, signature); err != nil {
		return nil, fmt.Errorf("self-check of SPHINCS signature: %w", err)
	}

	tx := txtypes.NewTx(frameTx)

	wrapper, err := wrap(tx, sigHash, publicKey, signature)
	if err != nil {
		return nil, fmt.Errorf("build proof wrapper: %w", err)
	}

	return &signedTx{
		tx:      tx,
		frameTx: frameTx,
		sigHash: sigHash,
		wrapper: wrapper,
	}, nil
}

// randomAmount returns a random value in [0, max) or max itself.
func randomAmount(max *uint256.Int, random bool) *uint256.Int {
	if !random || max.IsZero() {
		return max
	}

	n, err := rand.Int(rand.Reader, max.ToBig())
	if err != nil {
		return max
	}

	return uint256.MustFromBig(n)
}
