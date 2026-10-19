package pqforstx

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
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/fors"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txbuilder"
	"github.com/ethpandaops/spamoor/txtypes"
)

// masterSecretDomain separates the FORS+C master secret from the owner wallet's key.
var masterSecretDomain = []byte("pq-fors-tx/master-secret/v1")

// accountSaltDomain separates the CREATE2 salt of an account from other deployments.
var accountSaltDomain = []byte("pq-fors-tx/account/v1")

// account is one ForsFrameAccount together with the child wallet that deployed and funds
// it, and the signer state of its FORS+C key chain.
//
// A key chain is deterministic in the owner wallet: masterSecret = keccak(domain ||
// ownerPrivKey), key i = fors.DeriveKey(masterSecret, i). The account stores the chain
// index next to the current owner, so a restarted scenario resumes where it left off.
type account struct {
	logger *logrus.Entry

	// owner is the spamoor child wallet that deploys and tops up the account.
	owner *spamoor.Wallet
	// wallet tracks the account itself (nonce, balance, confirmations) in the tx pool. It
	// carries the owner's private key only because spamoor wallets need one; the account
	// is authenticated with FORS+C, never with that key.
	wallet  *spamoor.Wallet
	address common.Address

	masterSecret common.Hash

	// mu serialises transactions of this account: a key can be burned only once, so the
	// next transaction must wait for the previous one to land.
	mu sync.Mutex

	index      uint64 // chain position of the current owner key
	current    *fors.Key
	next       *fors.Key
	needResync bool
}

func newAccount(logger *logrus.Entry, owner *spamoor.Wallet) *account {
	secret := crypto.Keccak256Hash(masterSecretDomain, crypto.FromECDSA(owner.GetPrivateKey()))

	return &account{
		logger:       logger.WithField("owner", owner.GetAddress().Hex()),
		owner:        owner,
		masterSecret: secret,
	}
}

// salt is the CREATE2 salt of this owner's account.
func (a *account) salt() [32]byte {
	return crypto.Keccak256Hash(accountSaltDomain, a.owner.GetAddress().Bytes())
}

// prepare deploys the account if needed, registers its tracking wallet, funds it and
// reads the key chain position from chain.
func (a *account) prepare(ctx context.Context, s *Scenario, client *spamoor.Client, feeCap, tipCap *big.Int) error {
	key0 := fors.DeriveKey(a.masterSecret, 0)
	initcode := contract.ForsFrameAccountInitcode(s.verifier, key0.Address)

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
			"owner0": key0.Address.Hex(),
			"block":  receipt.BlockNumber.Uint64(),
		}).Info("deployed ForsFrameAccount")
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

	if err := a.topUp(ctx, s, client, feeCap, tipCap); err != nil {
		return err
	}

	return a.syncKeys(ctx, client)
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

// syncKeys reads the packed owner word of the account, checks it belongs to this key
// chain and derives the signer keys for it.
func (a *account) syncKeys(ctx context.Context, client *spamoor.Client) error {
	word, err := client.GetStorageAt(ctx, a.address, contract.OwnerSlot())
	if err != nil {
		return fmt.Errorf("read owner slot of %s: %w", a.address.Hex(), err)
	}

	index, owner, err := resolveChainPosition(a.masterSecret, word)
	if err != nil {
		return fmt.Errorf("account %s: %w", a.address.Hex(), err)
	}

	a.index = index
	a.current = fors.DeriveKey(a.masterSecret, index)
	a.next = fors.DeriveKey(a.masterSecret, index+1)
	a.needResync = false

	a.logger.WithFields(logrus.Fields{
		"index":   index,
		"current": owner.Hex(),
	}).Debug("synced key chain")

	return nil
}

// resolveChainPosition decodes the owner word and verifies that the stored owner is the
// key the chain derives at the stored index.
func resolveChainPosition(masterSecret common.Hash, word common.Hash) (uint64, common.Address, error) {
	index, owner := contract.DecodeOwnerSlot(word)
	if owner == (common.Address{}) {
		return 0, common.Address{}, fmt.Errorf("owner slot is empty: account not initialised")
	}

	expected := fors.DeriveKey(masterSecret, index).Address
	if expected != owner {
		return 0, common.Address{}, fmt.Errorf("owner %s at chain index %d is not this key chain's key %s: wrong owner wallet",
			owner.Hex(), index, expected.Hex())
	}

	return index, owner, nil
}

// advance moves the chain forward after a confirmed rotation.
func (a *account) advance() {
	a.index++
	a.current = a.next
	a.next = fors.DeriveKey(a.masterSecret, a.index+1)
}
