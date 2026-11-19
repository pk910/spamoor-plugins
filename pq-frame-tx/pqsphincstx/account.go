package pqsphincstx

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/contract"
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/sphincsg"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txbuilder"
	"github.com/ethpandaops/spamoor/txtypes"
)

// keySecretDomain separates the SPHINCS key secret from the owner wallet's key.
var keySecretDomain = []byte("pq-sphincs-tx/key-secret/v1")

// accountSaltDomain separates the CREATE2 salt of an account from other deployments.
var accountSaltDomain = []byte("pq-sphincs-tx/account/v1")

// account is one SphincsFrameAccount together with the child wallet that deployed and
// funds it, and its SPHINCS key.
//
// The key is deterministic in the owner wallet: sphincsg.DeriveKey(keccak(domain ||
// ownerPrivKey)). It is stateless, so a restarted scenario has nothing to resume.
type account struct {
	logger *logrus.Entry

	// owner is the spamoor child wallet that deploys and tops up the account.
	owner *spamoor.Wallet
	// wallet tracks the account itself (nonce, balance, confirmations) in the tx pool.
	// It carries the owner's private key only because spamoor wallets need one; the
	// account is authenticated with SPHINCS, never with that key.
	wallet  *spamoor.Wallet
	address common.Address

	key *sphincsg.Key

	// mu serialises transactions of this account: one is in flight at a time, so the
	// chain is always the truth for the next nonce.
	mu sync.Mutex
}

func newAccount(logger *logrus.Entry, owner *spamoor.Wallet) *account {
	return &account{
		logger: logger.WithField("owner", owner.GetAddress().Hex()),
		owner:  owner,
	}
}

// salt is the CREATE2 salt of this owner's account.
func (a *account) salt() [32]byte {
	return crypto.Keccak256Hash(accountSaltDomain, a.owner.GetAddress().Bytes())
}

// prepare derives the key, deploys the account if needed, registers its tracking wallet
// and funds it.
func (a *account) prepare(ctx context.Context, s *Scenario, client *spamoor.Client, feeCap, tipCap *big.Int) error {
	secret := crypto.Keccak256Hash(keySecretDomain, crypto.FromECDSA(a.owner.GetPrivateKey()))
	a.key = sphincsg.DeriveKey(secret)

	initcode := contract.SphincsFrameAccountInitcode(a.key.PublicKey())
	txpool := s.walletPool.GetTxPool()

	addr, tx, err := s.walletPool.GetDeploymentFactory().GetContractDeployment(ctx, initcode, a.salt(), client, a.owner, feeCap, tipCap, false)
	if err != nil {
		return fmt.Errorf("prepare account deployment: %w", err)
	}

	a.address = addr
	a.logger = a.logger.WithField("account", addr.Hex())

	if tx != nil {
		receipt, err := txpool.SendAndAwaitTransaction(ctx, a.owner, tx, &spamoor.SendTransactionOptions{
			Client:      client,
			ClientGroup: s.deployClientGroup(),
			Rebroadcast: true,
		})
		if err != nil {
			return fmt.Errorf("deploy account: %w", err)
		}

		if receipt == nil || receipt.Status != txtypes.ReceiptStatusSuccessful {
			return fmt.Errorf("account deployment reverted")
		}

		a.logger.WithFields(logrus.Fields{
			"key":   a.key.PublicKey().Hex(),
			"block": receipt.BlockNumber.Uint64(),
		}).Info("deployed SphincsFrameAccount")
	}

	stored, err := client.GetStorageAt(ctx, addr, contract.SphincsKeySlot())
	if err != nil {
		return fmt.Errorf("read key slot of %s: %w", addr.Hex(), err)
	}

	if stored != a.key.PublicKey() {
		return fmt.Errorf("account %s holds key %s, not this owner's key %s",
			addr.Hex(), stored.Hex(), a.key.PublicKey().Hex())
	}

	tracker := spamoor.NewWallet(a.owner.GetPrivateKey(), addr)
	tracker.SetChainId(s.walletPool.GetChainId())
	a.wallet = txpool.RegisterWallet(tracker, s.walletPool.GetContext())

	if a.wallet == nil {
		return fmt.Errorf("register account wallet: scenario context is done")
	}

	if err := a.wallet.UpdateWallet(ctx, client, true); err != nil {
		return fmt.Errorf("sync account: %w", err)
	}

	return a.topUp(ctx, s, client, feeCap, tipCap)
}

// topUp sends `account_fund` ETH from the owner when the account is below the refill
// threshold.
func (a *account) topUp(ctx context.Context, s *Scenario, client *spamoor.Client, feeCap, tipCap *big.Int) error {
	if a.wallet.GetBalance().Cmp(s.accountRefillWei) >= 0 {
		return nil
	}

	to := a.address

	txData, err := txbuilder.DynFeeTx(&txbuilder.TxMetadata{
		GasFeeCap: uint256.MustFromBig(feeCap),
		GasTipCap: uint256.MustFromBig(tipCap),
		Gas:       fundingGas,
		To:        &to,
		Value:     uint256.MustFromBig(s.accountFundWei),
	})
	if err != nil {
		return fmt.Errorf("build funding tx: %w", err)
	}

	tx, err := a.owner.BuildDynamicFeeTx(txData)
	if err != nil {
		return fmt.Errorf("sign funding tx: %w", err)
	}

	receipt, err := s.walletPool.GetTxPool().SendAndAwaitTransaction(ctx, a.owner, tx, &spamoor.SendTransactionOptions{
		Client:      client,
		ClientGroup: s.deployClientGroup(),
		Rebroadcast: true,
	})
	if err != nil {
		return fmt.Errorf("fund account: %w", err)
	}

	if receipt == nil || receipt.Status != txtypes.ReceiptStatusSuccessful {
		return fmt.Errorf("account funding reverted")
	}

	a.logger.WithField("amount", s.accountFundWei.String()).Debug("funded account")

	return a.wallet.UpdateWallet(ctx, client, true)
}
