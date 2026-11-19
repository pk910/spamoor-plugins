// Package pqsphincstx is the pq-sphincs-tx scenario: EIP-8141 frame transactions sent
// from smart accounts that authenticate with a post-quantum SPHINCS signature the chain
// aggregates into a recursive STARK (EIP-8288).
//
// Every child wallet owns one SphincsFrameAccount. Each transaction of an account is
//
//	frame 0  DEP_VERIFY  leanSPHINCS dependency: the account's key signed this transaction
//	frame 1  VERIFY      self_verify: frame 0 declares the account's key
//	frame 2  SENDER      the user operation (ETH transfer or ERC20 transferMint)
//
// The 6,176-byte signature is not part of the transaction. It travels beside it in a
// mempool wrapper submitted through eth_sendProofWrapper, and the block that includes
// the transaction carries one recursive STARK proving every such signature. The tx pool
// sends, rebroadcasts and tracks the transaction as usual; only the submission call is
// replaced.
package pqsphincstx

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/contract"
	"github.com/ethpandaops/spamoor/scenario"
	"github.com/ethpandaops/spamoor/spamoor"
	"github.com/ethpandaops/spamoor/txtypes"
	"github.com/ethpandaops/spamoor/utils"
)

// Operation kinds for the user operation frame.
const (
	OperationEth   = "eth"
	OperationErc20 = "erc20"
	OperationMixed = "mixed"
)

// fundingGas is the gas limit of the owner -> account ETH top-up. The account's plain-call
// path is a single STOP, so this is a value transfer to a warm-ish contract.
const fundingGas = 60_000

// Default execution gas of the user operation frame per operation. transferMint mints to
// the account and transfers to a possibly fresh recipient.
const (
	ethOpGas   = 50_000
	erc20OpGas = 350_000
)

// ScenarioOptions configures the scenario (CLI flags and YAML).
type ScenarioOptions struct {
	TotalCount        uint64  `yaml:"total_count"`
	Throughput        uint64  `yaml:"throughput"`
	MaxPending        uint64  `yaml:"max_pending"`
	MaxWallets        uint64  `yaml:"max_wallets"`
	Rebroadcast       uint64  `yaml:"rebroadcast"`
	BaseFee           float64 `yaml:"base_fee"`
	TipFee            float64 `yaml:"tip_fee"`
	BaseFeeWei        string  `yaml:"base_fee_wei"`
	TipFeeWei         string  `yaml:"tip_fee_wei"`
	Timeout           string  `yaml:"timeout"`
	ClientGroup       string  `yaml:"client_group"`
	DeployClientGroup string  `yaml:"deploy_client_group"`
	LogTxs            bool    `yaml:"log_txs"`

	Operation        string  `yaml:"operation"`
	Amount           uint64  `yaml:"amount"`
	RandomAmount     bool    `yaml:"random_amount"`
	RandomTarget     bool    `yaml:"random_target"`
	VerifyGas        uint64  `yaml:"verify_gas"`
	OpGas            uint64  `yaml:"op_gas"`
	OpStateGas       int64   `yaml:"op_state_gas"`
	AccountFund      float64 `yaml:"account_fund"`
	AccountRefill    float64 `yaml:"account_refill"`
	PrepareWorkers   uint64  `yaml:"prepare_workers"`
	VerifyFrames     bool    `yaml:"verify_frames"`
	SkipMempoolCheck bool    `yaml:"skip_mempool_check"`
}

// Scenario is the pq-sphincs-tx scenario instance.
type Scenario struct {
	options    ScenarioOptions
	logger     *logrus.Entry
	walletPool *spamoor.WalletPool

	extensions txtypes.FrameExtensions

	token    common.Address
	accounts []*account

	accountFundWei   *big.Int
	accountRefillWei *big.Int

	framesChecked  atomic.Uint64
	framesMismatch atomic.Uint64
	missingReceipt atomic.Uint64
}

// ScenarioName is the name the scenario is selected by.
var ScenarioName = "pq-sphincs-tx"

// ScenarioDefaultOptions are the defaults for flags and YAML.
var ScenarioDefaultOptions = ScenarioOptions{
	Throughput:     5,
	Rebroadcast:    1,
	BaseFee:        20,
	TipFee:         2,
	Operation:      OperationMixed,
	Amount:         20,
	RandomAmount:   true,
	VerifyGas:      50_000,
	OpGas:          0,
	OpStateGas:     -1,
	AccountFund:    1,
	AccountRefill:  0.2,
	PrepareWorkers: 8,
	VerifyFrames:   true,
}

// ScenarioDescriptor registers the scenario with spamoor.
var ScenarioDescriptor = scenario.Descriptor{
	Name:           ScenarioName,
	Description:    "Send EIP-8141 frame transactions from post-quantum SPHINCS smart accounts, with the signatures aggregated into the block's recursive STARK (EIP-8288)",
	DefaultOptions: ScenarioDefaultOptions,
	NewScenario:    newScenario,
}

func newScenario(logger logrus.FieldLogger) scenario.Scenario {
	return &Scenario{
		options: ScenarioDefaultOptions,
		logger:  logger.WithField("scenario", ScenarioName),
	}
}

// Flags registers the CLI flags.
func (s *Scenario) Flags(flags *pflag.FlagSet) error {
	flags.Uint64VarP(&s.options.TotalCount, "count", "c", ScenarioDefaultOptions.TotalCount, "Total number of frame transactions to send")
	flags.Uint64VarP(&s.options.Throughput, "throughput", "t", ScenarioDefaultOptions.Throughput, "Number of frame transactions to send per slot")
	flags.Uint64Var(&s.options.MaxPending, "max-pending", ScenarioDefaultOptions.MaxPending, "Maximum number of pending transactions")
	flags.Uint64Var(&s.options.MaxWallets, "max-wallets", ScenarioDefaultOptions.MaxWallets, "Maximum number of child wallets (= post-quantum accounts) to use")
	flags.Uint64Var(&s.options.Rebroadcast, "rebroadcast", ScenarioDefaultOptions.Rebroadcast, "Enable reliable rebroadcast system")
	flags.Float64Var(&s.options.BaseFee, "basefee", ScenarioDefaultOptions.BaseFee, "Max fee per gas the fee budget of a frame transaction is sized for (in gwei)")
	flags.Float64Var(&s.options.TipFee, "tipfee", ScenarioDefaultOptions.TipFee, "Max tip per gas to use in frame transactions (in gwei)")
	flags.StringVar(&s.options.BaseFeeWei, "basefee-wei", ScenarioDefaultOptions.BaseFeeWei, "Max fee per gas in wei (overrides --basefee)")
	flags.StringVar(&s.options.TipFeeWei, "tipfee-wei", ScenarioDefaultOptions.TipFeeWei, "Max tip per gas in wei (overrides --tipfee)")
	flags.StringVar(&s.options.Timeout, "timeout", ScenarioDefaultOptions.Timeout, "Timeout for the scenario (e.g. '1h', '30m')")
	flags.StringVar(&s.options.ClientGroup, "client-group", ScenarioDefaultOptions.ClientGroup, "Client group to use for sending transactions")
	flags.StringVar(&s.options.DeployClientGroup, "deploy-client-group", ScenarioDefaultOptions.DeployClientGroup, "Client group to use for deployments")
	flags.BoolVar(&s.options.LogTxs, "log-txs", ScenarioDefaultOptions.LogTxs, "Log all submitted transactions")

	flags.StringVar(&s.options.Operation, "operation", ScenarioDefaultOptions.Operation,
		"User operation per transaction: eth (value transfer), erc20 (TestToken transferMint) or mixed (alternate)")
	flags.Uint64Var(&s.options.Amount, "amount", ScenarioDefaultOptions.Amount, "Transfer amount per operation (in gwei, also used as token units)")
	flags.BoolVar(&s.options.RandomAmount, "random-amount", ScenarioDefaultOptions.RandomAmount, "Use random amounts up to --amount")
	flags.BoolVar(&s.options.RandomTarget, "random-target", ScenarioDefaultOptions.RandomTarget, "Send to random (non-existent) target addresses")
	flags.Uint64Var(&s.options.VerifyGas, "verify-gas", ScenarioDefaultOptions.VerifyGas, "Execution gas limit of the VERIFY frame (it only compares the declared key)")
	flags.Uint64Var(&s.options.OpGas, "op-gas", ScenarioDefaultOptions.OpGas, "Execution gas limit of the user operation frame (0 = derive from the operation: 50k for ETH, 350k for ERC20 transferMint)")
	flags.Int64Var(&s.options.OpStateGas, "op-state-gas", ScenarioDefaultOptions.OpStateGas, "State gas limit of the user operation frame (-1 = derive from the operation)")
	flags.Float64Var(&s.options.AccountFund, "account-fund", ScenarioDefaultOptions.AccountFund, "ETH to send to a post-quantum account when it is below --account-refill")
	flags.Float64Var(&s.options.AccountRefill, "account-refill", ScenarioDefaultOptions.AccountRefill, "ETH balance below which an account is topped up")
	flags.Uint64Var(&s.options.PrepareWorkers, "prepare-workers", ScenarioDefaultOptions.PrepareWorkers, "Accounts to deploy and sync concurrently at startup")
	flags.BoolVar(&s.options.VerifyFrames, "verify-frames", ScenarioDefaultOptions.VerifyFrames, "Check frame receipts: payer is the account and every frame succeeded")
	flags.BoolVar(&s.options.SkipMempoolCheck, "skip-mempool-check", ScenarioDefaultOptions.SkipMempoolCheck, "Skip the local public-mempool policy check before sending")

	return nil
}

// Init applies the configuration and sizes the wallet pool.
func (s *Scenario) Init(options *scenario.Options) error {
	s.walletPool = options.WalletPool

	if options.Config != "" {
		if err := scenario.ParseAndValidateConfig(&ScenarioDescriptor, options.Config, &s.options, s.logger); err != nil {
			return err
		}
	}

	switch s.options.Operation {
	case OperationEth, OperationErc20, OperationMixed:
	default:
		return fmt.Errorf("unknown operation %q (want eth, erc20 or mixed)", s.options.Operation)
	}

	if s.options.AccountFund <= 0 {
		return fmt.Errorf("account_fund must be positive")
	}

	s.accountFundWei = etherToWei(s.options.AccountFund)
	s.accountRefillWei = etherToWei(s.options.AccountRefill)

	if s.options.PrepareWorkers == 0 {
		s.options.PrepareWorkers = 1
	}

	// One account per child wallet, and one transaction in flight per account.
	switch {
	case s.options.MaxWallets > 0:
		s.walletPool.SetWalletCount(s.options.MaxWallets)
	case s.options.TotalCount > 0:
		s.walletPool.SetWalletCount(clamp(s.options.TotalCount/10, 4, 200))
	default:
		s.walletPool.SetWalletCount(clamp(s.options.Throughput*3, 4, 200))
	}

	// Child wallets pay for the account deployment and keep their account funded.
	refill := new(big.Int).Mul(s.accountFundWei, big.NewInt(2))
	refill.Add(refill, etherToWei(1))
	threshold := new(big.Int).Add(s.accountFundWei, etherToWei(0.5))

	s.walletPool.SetRefillAmount(uint256.MustFromBig(refill))
	s.walletPool.SetRefillBalance(uint256.MustFromBig(threshold))

	s.walletPool.AddWellKnownWallet(&spamoor.WellKnownWalletConfig{
		Name:          "deployer",
		RefillAmount:  utils.EtherToWei(uint256.NewInt(5)),
		RefillBalance: utils.EtherToWei(uint256.NewInt(2)),
	})

	if s.options.TotalCount == 0 && s.options.Throughput == 0 {
		return fmt.Errorf("neither total count nor throughput limit set, must define at least one of them (see --help for list of all flags)")
	}

	return nil
}

// Run deploys the token and the accounts, then sends transactions.
func (s *Scenario) Run(ctx context.Context) error {
	s.logger.Infof("starting scenario: %s", ScenarioName)
	defer s.logger.Infof("scenario %s finished.", ScenarioName)

	support, err := s.walletPool.GetTxPool().AwaitFrameSupport(ctx, s.logger)
	if err != nil {
		return err
	}

	s.extensions = support.Extensions
	s.logger.Infof("detected frame transaction envelope: %s", support.Extensions)

	if err := s.deployInfrastructure(ctx); err != nil {
		return err
	}

	if err := s.prepareAccounts(ctx); err != nil {
		return err
	}

	maxPending := s.options.MaxPending
	if maxPending == 0 || maxPending > uint64(len(s.accounts)) {
		// one transaction per account at a time
		maxPending = uint64(len(s.accounts))
	}

	err = scenario.RunTransactionScenario(ctx, scenario.TransactionScenarioOptions{
		TotalCount: s.options.TotalCount,
		Throughput: s.options.Throughput,
		MaxPending: maxPending,
		Timeout:    s.parseTimeout(),
		WalletPool: s.walletPool,
		Logger:     s.logger,

		ProcessNextTxFn: s.processNextTx,
	})

	if s.options.VerifyFrames && s.framesChecked.Load() > 0 {
		s.logger.Infof("frame receipt check: %d transactions verified, %d mismatched, %d without frame receipts",
			s.framesChecked.Load(), s.framesMismatch.Load(), s.missingReceipt.Load())
	}

	return err
}

func (s *Scenario) deployClientGroup() string {
	if s.options.DeployClientGroup != "" {
		return s.options.DeployClientGroup
	}

	return s.options.ClientGroup
}

func (s *Scenario) parseTimeout() time.Duration {
	if s.options.Timeout == "" {
		return 0
	}

	timeout, err := time.ParseDuration(s.options.Timeout)
	if err != nil {
		s.logger.Warnf("invalid timeout value %q, ignoring", s.options.Timeout)

		return 0
	}

	return timeout
}

// deployInfrastructure deploys the ERC20 token through the CREATE2 factory from the
// scenario's deployer wallet. An existing deployment is reused. The accounts need no
// verifier contract: the chain verifies their signatures.
func (s *Scenario) deployInfrastructure(ctx context.Context) error {
	if s.options.Operation == OperationEth {
		return nil
	}

	client := s.walletPool.GetClient(
		spamoor.WithClientSelectionMode(spamoor.SelectClientByIndex, 0),
		spamoor.WithClientGroup(s.deployClientGroup()),
	)
	if client == nil {
		return scenario.ErrNoClients
	}

	deployer := s.walletPool.GetWellKnownWallet("deployer")
	if deployer == nil {
		return scenario.ErrNoWallet
	}

	feeCap, tipCap, err := s.suggestedFees(client)
	if err != nil {
		return err
	}

	// the salt is shared with pq-fors-tx, so both scenarios use one token
	salt := sha256.Sum256([]byte("pq-frame-tx/TestToken/v1"))

	addr, tx, err := s.walletPool.GetDeploymentFactory().GetContractDeployment(ctx, contract.TestTokenInitcode(), salt, client, deployer, feeCap, tipCap, false)
	if err != nil {
		return fmt.Errorf("prepare TestToken deployment: %w", err)
	}

	s.token = addr

	if tx == nil {
		s.logger.Infof("using existing TestToken at %s", addr.Hex())

		return nil
	}

	receipt, err := s.walletPool.GetTxPool().SendAndAwaitTransaction(ctx, deployer, tx, &spamoor.SendTransactionOptions{
		Client:      client,
		ClientGroup: s.deployClientGroup(),
		Rebroadcast: true,
	})
	if err != nil {
		return fmt.Errorf("deploy TestToken: %w", err)
	}

	if receipt == nil || receipt.Status != txtypes.ReceiptStatusSuccessful {
		return fmt.Errorf("TestToken deployment reverted")
	}

	s.logger.Infof("deployed TestToken at %s (block #%v)", addr.Hex(), receipt.BlockNumber.Uint64())

	return nil
}

// prepareAccounts deploys and funds one account per child wallet.
func (s *Scenario) prepareAccounts(ctx context.Context) error {
	count := s.walletPool.GetConfiguredWalletCount()
	s.accounts = make([]*account, count)

	for i := uint64(0); i < count; i++ {
		owner := s.walletPool.GetWallet(spamoor.SelectWalletByIndex, int(i))
		if owner == nil {
			return scenario.ErrNoWallet
		}

		s.accounts[i] = newAccount(s.logger, owner)
	}

	workers := s.options.PrepareWorkers
	if workers > count {
		workers = count
	}

	jobs := make(chan int, count)
	for i := 0; i < int(count); i++ {
		jobs <- i
	}

	close(jobs)

	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)

	for w := uint64(0); w < workers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}

				if err := s.prepareAccount(ctx, idx); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()

					return
				}
			}
		}()
	}

	wg.Wait()

	if firstErr != nil {
		return firstErr
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	s.logger.Infof("%d post-quantum accounts ready", len(s.accounts))

	return nil
}

func (s *Scenario) prepareAccount(ctx context.Context, idx int) error {
	client := s.walletPool.GetClient(
		spamoor.WithClientSelectionMode(spamoor.SelectClientByIndex, idx),
		spamoor.WithClientGroup(s.deployClientGroup()),
	)
	if client == nil {
		return scenario.ErrNoClients
	}

	feeCap, tipCap, err := s.suggestedFees(client)
	if err != nil {
		return err
	}

	acct := s.accounts[idx]
	if err := acct.owner.ResetNoncesIfNeeded(ctx, client); err != nil {
		return err
	}

	return acct.prepare(ctx, s, client, feeCap, tipCap)
}

func (s *Scenario) suggestedFees(client *spamoor.Client) (*big.Int, *big.Int, error) {
	baseFeeWei, tipFeeWei := spamoor.ResolveFees(s.options.BaseFee, s.options.TipFee, s.options.BaseFeeWei, s.options.TipFeeWei)

	return s.walletPool.GetSuggestedFees(client, baseFeeWei, tipFeeWei)
}

// processNextTx is the RunTransactionScenario callback: one frame transaction from the
// account selected by the transaction index.
func (s *Scenario) processNextTx(ctx context.Context, params *scenario.ProcessNextTxParams) error {
	acct := s.accounts[int(params.TxIdx%uint64(len(s.accounts)))]

	acct.mu.Lock()
	defer acct.mu.Unlock()

	receiptChan, tx, client, err := s.sendTx(ctx, acct, params.TxIdx)

	logger := s.logger.WithField("account", acct.address.Hex())

	if client != nil {
		logger = logger.WithField("rpc", client.GetName())
	}

	if tx != nil {
		logger = logger.WithField("nonce", tx.Nonce())
	}

	params.NotifySubmitted()
	params.OrderedLogCb(func() {
		if err != nil {
			logger.Warnf("could not send frame tx #%6d: %v", params.TxIdx+1, err)
		} else if s.options.LogTxs {
			logger.Infof("sent frame tx #%6d: %v", params.TxIdx+1, tx.Hash().String())
		} else {
			logger.Debugf("sent frame tx #%6d: %v", params.TxIdx+1, tx.Hash().String())
		}
	})

	if err != nil {
		return err
	}

	if _, waitErr := receiptChan.Wait(ctx); waitErr != nil {
		return waitErr
	}

	return nil
}

// sendTx builds, signs and submits one transaction of `acct`. Called with acct.mu held.
func (s *Scenario) sendTx(ctx context.Context, acct *account, txIdx uint64) (scenario.ReceiptChan, *txtypes.Transaction, *spamoor.Client, error) {
	client := s.walletPool.GetClient(
		spamoor.WithClientSelectionMode(spamoor.SelectClientByIndex, int(txIdx)),
		spamoor.WithClientGroup(s.options.ClientGroup),
	)
	if client == nil {
		return nil, nil, nil, scenario.ErrNoClients
	}

	feeCap, tipCap, err := s.suggestedFees(client)
	if err != nil {
		return nil, nil, client, err
	}

	// Nothing of this account is in flight here, so the chain is the truth for nonce
	// and balance.
	if err := acct.wallet.UpdateWallet(ctx, client, true); err != nil {
		return nil, nil, client, err
	}

	if err := acct.topUp(ctx, s, client, feeCap, tipCap); err != nil {
		return nil, nil, client, err
	}

	op, err := s.buildOperation(txIdx)
	if err != nil {
		return nil, nil, client, err
	}

	nonce := acct.wallet.GetNextNonce()

	signed, err := s.buildFrameTx(acct, op, nonce, feeCap, tipCap)
	if err != nil {
		acct.wallet.MarkSkippedNonce(nonce)

		return nil, nil, client, err
	}

	if err := signed.validate(s.options.SkipMempoolCheck); err != nil {
		acct.wallet.MarkSkippedNonce(nonce)

		return nil, nil, client, err
	}

	tx := signed.tx
	receiptChan := make(scenario.ReceiptChan, 1)

	err = s.walletPool.GetTxPool().SendTransaction(ctx, acct.wallet, tx, &spamoor.SendTransactionOptions{
		Client:      client,
		ClientGroup: s.options.ClientGroup,
		Rebroadcast: s.options.Rebroadcast > 0,
		// The transaction reaches a node inside its proof wrapper, on the first
		// submission and on every rebroadcast.
		OnSubmit: func(ctx context.Context, client *spamoor.Client, _ *txtypes.Transaction) error {
			return submitWrapper(ctx, client, signed)
		},
		OnComplete: func(_ *txtypes.Transaction, receipt *txtypes.Receipt, _ error) {
			receiptChan <- receipt
		},
		OnConfirm: func(_ *txtypes.Transaction, receipt *txtypes.Receipt) {
			s.onConfirm(client, acct, op, txIdx, signed, receipt)
		},
		LogFn: spamoor.GetDefaultLogFn(s.logger, op.kind, fmt.Sprintf("%6d", txIdx+1), tx),
	})
	if err != nil {
		acct.wallet.MarkSkippedNonce(nonce)

		return nil, nil, client, err
	}

	return receiptChan, tx, client, nil
}

// onConfirm checks the frame receipt: the account paid, and every frame succeeded.
func (s *Scenario) onConfirm(client *spamoor.Client, acct *account, op *operation, txIdx uint64, signed *signedTx, receipt *txtypes.Receipt) {
	tx := signed.tx
	txFees := utils.GetTransactionFees(tx, receipt)
	logger := s.logger.WithField("rpc", client.GetName())

	extra := receipt.FrameExtra()
	if extra == nil {
		s.missingReceipt.Add(1)
		logger.Debugf(" frame tx %d (%s) confirmed in block #%v without frame receipts. total fee: %v gwei",
			txIdx+1, op.kind, receipt.BlockNumber.String(), txFees.TotalFeeGweiString())

		return
	}

	statuses := make([]uint64, 0, len(extra.Frames))
	for _, frame := range extra.Frames {
		statuses = append(statuses, frame.Status)
	}

	logger.Debugf(" frame tx %d (%s) confirmed in block #%v. account: %v, payer: %v, frames: %v, exec gas: %v, state gas: %v, total fee: %v gwei, sigHash: %v",
		txIdx+1, op.kind, receipt.BlockNumber.String(), acct.address.Hex(), extra.Payer.Hex(), statuses,
		extra.TotalExecutionGas(), extra.TotalStateGas(), txFees.TotalFeeGweiString(), signed.sigHash.Hex())

	if !s.options.VerifyFrames {
		return
	}

	s.framesChecked.Add(1)

	if extra.Payer != acct.address {
		s.framesMismatch.Add(1)
		logger.Warnf("frame receipt mismatch for tx %v: payer %v, expected the account %v", tx.Hash().Hex(), extra.Payer.Hex(), acct.address.Hex())

		return
	}

	if len(extra.Frames) != frameCount {
		s.framesMismatch.Add(1)
		logger.Warnf("frame receipt mismatch for tx %v: %d frame receipts, expected %d", tx.Hash().Hex(), len(extra.Frames), frameCount)

		return
	}

	for i, frame := range extra.Frames {
		if frame.Status != txtypes.FrameStatusSuccess {
			s.framesMismatch.Add(1)
			logger.Warnf("frame receipt mismatch for tx %v: frame %d status %d", tx.Hash().Hex(), i, frame.Status)

			return
		}
	}
}

// etherToWei converts a (fractional) ETH amount to wei.
func etherToWei(eth float64) *big.Int {
	wei, _ := new(big.Float).Mul(big.NewFloat(eth), big.NewFloat(1e18)).Int(nil)

	return wei
}

// clamp bounds v to [low, high].
func clamp(v, low, high uint64) uint64 {
	if v < low {
		return low
	}

	if v > high {
		return high
	}

	return v
}
