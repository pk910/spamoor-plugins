// Package pqforstx is the pq-fors-tx scenario: EIP-8141 frame transactions sent from
// smart accounts that authenticate with the post-quantum FORS+C signature scheme.
//
// Every child wallet owns one ForsFrameAccount. Each transaction of an account is
//
//	frame 0  VERIFY  self_verify: FORS+C signature over the canonical sig hash
//	frame 1  SENDER  rotateOwner(current, next): replace the key that signed with the next
//	frame 2  SENDER  the user operation (ETH transfer or ERC20 transferMint)
//
// with the 2,448-byte witness in signatures[0] (scheme ARBITRARY). The verifier, the ERC20
// token and every account are deployed through spamoor's CREATE2 deployment factory, so
// their addresses are stable across runs and nothing is redeployed.
package pqforstx

import (
	"context"
	"crypto/rand"
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
// the account and transfers to a possibly fresh recipient; under the Amsterdam schedule
// that is ~240k, so the same headroom spamoor's erc20tx scenario uses is reserved.
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

	Envelope         string  `yaml:"envelope"`
	Operation        string  `yaml:"operation"`
	Amount           uint64  `yaml:"amount"`
	RandomAmount     bool    `yaml:"random_amount"`
	RandomTarget     bool    `yaml:"random_target"`
	VerifyGas        uint64  `yaml:"verify_gas"`
	RotateGas        uint64  `yaml:"rotate_gas"`
	RotateStateGas   uint64  `yaml:"rotate_state_gas"`
	OpGas            uint64  `yaml:"op_gas"`
	OpStateGas       uint64  `yaml:"op_state_gas"`
	AccountFund      float64 `yaml:"account_fund"`
	AccountRefill    float64 `yaml:"account_refill"`
	PrepareWorkers   uint64  `yaml:"prepare_workers"`
	VerifyFrames     bool    `yaml:"verify_frames"`
	SkipMempoolCheck bool    `yaml:"skip_mempool_check"`
}

// Scenario is the pq-fors-tx scenario instance.
type Scenario struct {
	options    ScenarioOptions
	logger     *logrus.Entry
	walletPool *spamoor.WalletPool

	extensions txtypes.FrameExtensions
	autoDetect bool

	verifier common.Address
	token    common.Address
	accounts []*account

	accountFundWei   *big.Int
	accountRefillWei *big.Int

	framesChecked  atomic.Uint64
	framesMismatch atomic.Uint64
	missingReceipt atomic.Uint64
}

// ScenarioName is the name the scenario is selected by.
var ScenarioName = "pq-fors-tx"

// ScenarioDefaultOptions are the defaults for flags and YAML.
var ScenarioDefaultOptions = ScenarioOptions{
	Throughput:     10,
	Rebroadcast:    1,
	BaseFee:        20,
	TipFee:         2,
	Envelope:       "auto",
	Operation:      OperationMixed,
	Amount:         20,
	RandomAmount:   true,
	VerifyGas:      90_000,
	RotateGas:      60_000,
	RotateStateGas: 0,
	OpGas:          0,
	AccountFund:    1,
	AccountRefill:  0.2,
	PrepareWorkers: 8,
	VerifyFrames:   true,
}

// ScenarioDescriptor registers the scenario with spamoor.
var ScenarioDescriptor = scenario.Descriptor{
	Name:           ScenarioName,
	Description:    "Send EIP-8141 frame transactions from post-quantum FORS+C smart accounts (ETH and ERC20 transfers with per-transaction key rotation)",
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
	flags.Float64Var(&s.options.BaseFee, "basefee", ScenarioDefaultOptions.BaseFee, "Max fee per gas to use in frame transactions (in gwei)")
	flags.Float64Var(&s.options.TipFee, "tipfee", ScenarioDefaultOptions.TipFee, "Max tip per gas to use in frame transactions (in gwei)")
	flags.StringVar(&s.options.BaseFeeWei, "basefee-wei", ScenarioDefaultOptions.BaseFeeWei, "Max fee per gas in wei (overrides --basefee)")
	flags.StringVar(&s.options.TipFeeWei, "tipfee-wei", ScenarioDefaultOptions.TipFeeWei, "Max tip per gas in wei (overrides --tipfee)")
	flags.StringVar(&s.options.Timeout, "timeout", ScenarioDefaultOptions.Timeout, "Timeout for the scenario (e.g. '1h', '30m')")
	flags.StringVar(&s.options.ClientGroup, "client-group", ScenarioDefaultOptions.ClientGroup, "Client group to use for sending transactions")
	flags.StringVar(&s.options.DeployClientGroup, "deploy-client-group", ScenarioDefaultOptions.DeployClientGroup, "Client group to use for deployments")
	flags.BoolVar(&s.options.LogTxs, "log-txs", ScenarioDefaultOptions.LogTxs, "Log all submitted transactions")

	flags.StringVar(&s.options.Envelope, "envelope", ScenarioDefaultOptions.Envelope,
		"Frame tx envelope: auto (probe the chain), full (every extension), keyed (EIP-8250), base (EIP-8141 only)")
	flags.StringVar(&s.options.Operation, "operation", ScenarioDefaultOptions.Operation,
		"User operation per transaction: eth (value transfer), erc20 (TestToken transferMint) or mixed (alternate)")
	flags.Uint64Var(&s.options.Amount, "amount", ScenarioDefaultOptions.Amount, "Transfer amount per operation (in gwei, also used as token units)")
	flags.BoolVar(&s.options.RandomAmount, "random-amount", ScenarioDefaultOptions.RandomAmount, "Use random amounts up to --amount")
	flags.BoolVar(&s.options.RandomTarget, "random-target", ScenarioDefaultOptions.RandomTarget, "Send to random (non-existent) target addresses")
	flags.Uint64Var(&s.options.VerifyGas, "verify-gas", ScenarioDefaultOptions.VerifyGas, "Execution gas limit of the VERIFY frame (FORS+C verification uses ~43k)")
	flags.Uint64Var(&s.options.RotateGas, "rotate-gas", ScenarioDefaultOptions.RotateGas, "Execution gas limit of the key rotation frame")
	flags.Uint64Var(&s.options.RotateStateGas, "rotate-state-gas", ScenarioDefaultOptions.RotateStateGas, "State gas limit of the key rotation frame (the owner slot is overwritten, so none is needed)")
	flags.Uint64Var(&s.options.OpGas, "op-gas", ScenarioDefaultOptions.OpGas, "Execution gas limit of the user operation frame (0 = derive from the operation: 50k for ETH, 350k for ERC20 transferMint)")
	flags.Uint64Var(&s.options.OpStateGas, "op-state-gas", ScenarioDefaultOptions.OpStateGas, "State gas limit of the user operation frame (0 = derive from the operation)")
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

	extensions, autoDetect, err := parseEnvelope(s.options.Envelope)
	if err != nil {
		return err
	}

	s.extensions = extensions
	s.autoDetect = autoDetect

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
		count := s.options.TotalCount / 10
		if count < 4 {
			count = 4
		} else if count > 200 {
			count = 200
		}

		s.walletPool.SetWalletCount(count)
	default:
		count := s.options.Throughput * 3
		if count < 4 {
			count = 4
		} else if count > 200 {
			count = 200
		}

		s.walletPool.SetWalletCount(count)
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

// Run deploys the infrastructure and the accounts, then sends transactions.
func (s *Scenario) Run(ctx context.Context) error {
	s.logger.Infof("starting scenario: %s", ScenarioName)
	defer s.logger.Infof("scenario %s finished.", ScenarioName)

	if err := s.checkFrameTxSupport(ctx); err != nil {
		return err
	}

	if err := s.deployInfrastructure(ctx); err != nil {
		return err
	}

	if err := s.prepareAccounts(ctx); err != nil {
		return err
	}

	maxPending := s.options.MaxPending
	if maxPending == 0 || maxPending > uint64(len(s.accounts)) {
		// one transaction per account at a time: a key chain is strictly sequential
		maxPending = uint64(len(s.accounts))
	}

	err := scenario.RunTransactionScenario(ctx, scenario.TransactionScenarioOptions{
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

// checkFrameTxSupport waits for the chain to accept frame transactions and settles the
// envelope layout.
func (s *Scenario) checkFrameTxSupport(ctx context.Context) error {
	txpool := s.walletPool.GetTxPool()
	if txpool == nil {
		return nil
	}

	if !txpool.IsAmsterdam() {
		return fmt.Errorf("frame transactions need the Amsterdam (EIP-8037) gas model, but --pre-amsterdam-fee-model is set")
	}

	support, err := txpool.AwaitFrameSupport(ctx, s.logger)
	if err != nil {
		return err
	}

	if !s.autoDetect {
		s.logger.Infof("using pinned frame transaction envelope: %s", s.extensions)

		return nil
	}

	s.extensions = support.Extensions
	s.logger.Infof("detected frame transaction envelope: %s", support.Extensions)

	return nil
}

// deployInfrastructure deploys the FORS+C verifier and the ERC20 token through the CREATE2
// factory from the scenario's deployer wallet. Existing deployments are reused.
func (s *Scenario) deployInfrastructure(ctx context.Context) error {
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

	verifier, err := s.deployContract(ctx, client, deployer, feeCap, tipCap, "ForsVerifier", contract.ForsVerifierInitcode(), "pq-frame-tx/ForsVerifier/v1")
	if err != nil {
		return err
	}

	s.verifier = verifier

	if s.options.Operation != OperationEth {
		token, err := s.deployContract(ctx, client, deployer, feeCap, tipCap, "TestToken", contract.TestTokenInitcode(), "pq-frame-tx/TestToken/v1")
		if err != nil {
			return err
		}

		s.token = token
	}

	return nil
}

func (s *Scenario) deployContract(ctx context.Context, client *spamoor.Client, deployer *spamoor.Wallet, feeCap, tipCap *big.Int, name string, initcode []byte, saltSeed string) (common.Address, error) {
	salt := sha256.Sum256([]byte(saltSeed))

	addr, tx, err := s.walletPool.GetDeploymentFactory().GetContractDeployment(ctx, initcode, salt, client, deployer, feeCap, tipCap, false)
	if err != nil {
		return common.Address{}, fmt.Errorf("prepare %s deployment: %w", name, err)
	}

	if tx == nil {
		s.logger.Infof("using existing %s at %s", name, addr.Hex())

		return addr, nil
	}

	receipt, err := s.walletPool.GetTxPool().SendAndAwaitTransaction(ctx, deployer, tx, &spamoor.SendTransactionOptions{
		Client:      client,
		ClientGroup: s.deployClientGroup(),
		Rebroadcast: true,
	})
	if err != nil {
		return common.Address{}, fmt.Errorf("deploy %s: %w", name, err)
	}

	if receipt == nil || receipt.Status != txtypes.ReceiptStatusSuccessful {
		return common.Address{}, fmt.Errorf("%s deployment reverted", name)
	}

	s.logger.Infof("deployed %s at %s (block #%v)", name, addr.Hex(), receipt.BlockNumber.Uint64())

	return addr, nil
}

// prepareAccounts deploys, funds and syncs one account per child wallet.
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

	s.logger.Infof("%d post-quantum accounts ready (verifier %s)", len(s.accounts), s.verifier.Hex())

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

	// Nothing of this account is in flight here, so the chain is the truth for nonce,
	// balance and, after a failure, the key chain position.
	if err := acct.wallet.UpdateWallet(ctx, client, true); err != nil {
		return nil, nil, client, err
	}

	if acct.needResync {
		if err := acct.syncKeys(ctx, client); err != nil {
			return nil, nil, client, err
		}
	}

	if err := acct.topUp(ctx, s, client, feeCap, tipCap); err != nil {
		return nil, nil, client, err
	}

	op, err := s.buildOperation(txIdx, acct)
	if err != nil {
		return nil, nil, client, err
	}

	nonce := acct.wallet.GetNextNonce()

	frameTx, sigHash, err := s.buildFrameTx(acct, op, nonce, feeCap, tipCap)
	if err != nil {
		acct.wallet.MarkSkippedNonce(nonce)

		return nil, nil, client, err
	}

	if err := s.validate(frameTx); err != nil {
		acct.wallet.MarkSkippedNonce(nonce)

		return nil, nil, client, err
	}

	tx := txtypes.NewTx(frameTx)
	receiptChan := make(scenario.ReceiptChan, 1)

	err = s.walletPool.GetTxPool().SendTransaction(ctx, acct.wallet, tx, &spamoor.SendTransactionOptions{
		Client:      client,
		ClientGroup: s.options.ClientGroup,
		Rebroadcast: s.options.Rebroadcast > 0,
		OnComplete: func(tx *txtypes.Transaction, receipt *txtypes.Receipt, err error) {
			if err != nil || receipt == nil {
				// unknown outcome: re-read the key chain from chain before the next tx
				acct.needResync = true
			} else {
				acct.advance()
			}

			receiptChan <- receipt
		},
		OnConfirm: func(tx *txtypes.Transaction, receipt *txtypes.Receipt) {
			s.onConfirm(client, acct, op, txIdx, sigHash, tx, receipt)
		},
		LogFn: spamoor.GetDefaultLogFn(s.logger, op.kind, fmt.Sprintf("%6d", txIdx+1), tx),
	})
	if err != nil {
		acct.wallet.MarkSkippedNonce(nonce)
		acct.needResync = true

		return nil, nil, client, err
	}

	return receiptChan, tx, client, nil
}

// onConfirm checks the frame receipt: the account paid, and every frame succeeded.
func (s *Scenario) onConfirm(client *spamoor.Client, acct *account, op *operation, txIdx uint64, sigHash common.Hash, tx *txtypes.Transaction, receipt *txtypes.Receipt) {
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
		extra.TotalExecutionGas(), extra.TotalStateGas(), txFees.TotalFeeGweiString(), sigHash.Hex())

	if !s.options.VerifyFrames {
		return
	}

	s.framesChecked.Add(1)

	if extra.Payer != acct.address {
		s.framesMismatch.Add(1)
		logger.Warnf("frame receipt mismatch for tx %v: payer %v, expected the account %v", tx.Hash().Hex(), extra.Payer.Hex(), acct.address.Hex())

		return
	}

	if len(extra.Frames) != 3 {
		s.framesMismatch.Add(1)
		logger.Warnf("frame receipt mismatch for tx %v: %d frame receipts, expected 3", tx.Hash().Hex(), len(extra.Frames))

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

// parseEnvelope maps the --envelope option to a txtypes extension set.
//
// Only extension names that exist in every supported spamoor version are accepted: the
// account nonce is spelled by txtypes according to its own EIP-8250 revision (`[0]`
// before the 2026-10-16 text, `[]` after), and `auto` lets the tx pool pick the revision
// it is configured for.
func parseEnvelope(spec string) (txtypes.FrameExtensions, bool, error) {
	switch spec {
	case "auto", "":
		return 0, true, nil
	case "full":
		return txtypes.FrameExtAll, false, nil
	case "keyed":
		return txtypes.FrameExtKeyedNonces, false, nil
	case "base":
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("unknown envelope %q (want auto, full, keyed or base)", spec)
	}
}
