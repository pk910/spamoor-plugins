# pq-frame-tx

Spamoor plugin that sends [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) frame
transactions from smart accounts authenticated with post-quantum hash-based signatures.

| Scenario | Signature | Verified by | Runs on |
| --- | --- | --- | --- |
| [`pq-fors-tx`](#scenario-pq-fors-tx) | FORS+C, few-time, 2,448 bytes in the transaction | the account's verifier contract | any EIP-8141 chain |
| [`pq-sphincs-tx`](#scenario-pq-sphincs-tx) | SPHINCS-G, many-time, 6,176 bytes beside the transaction | the block's recursive STARK ([EIP-8288](https://eips.ethereum.org/EIPS/eip-8288)) | EIP-8288 chains (daisugi-devnet-0) |

The FORS+C account and verifier come from
[RivaLabs-Core/Post-Quantum-AA-Infra](https://github.com/RivaLabs-Core/Post-Quantum-AA-Infra)
(the NiceTry ephemeral-key wallet design); the frame accounts themselves are the geas
contracts in `contract/`.

## Scenario `pq-fors-tx`

Every child wallet of the scenario owns one `ForsFrameAccount`. Each transaction of an
account has three frames and one ARBITRARY signature entry:

```
frame 0  VERIFY  flags=3  target=account   FORS+C witness in signatures[0] (2,448 bytes)
frame 1  SENDER  flags=0  target=account   rotateOwner(currentKey, nextKey)
frame 2  SENDER  flags=0  target=...       ETH transfer or TestToken.transferMint(to, amount)
```

The VERIFY frame recovers the signer through the Solidity `ForsVerifier`, checks it is the
account's current owner and that frame 1 is exactly the rotation that replaces it, then
`APPROVE`s execution and payment. FORS+C is a few-time scheme, so a key signs once and the
chain moves on: key `i` is `fors.DeriveKey(masterSecret, i)` with
`masterSecret = keccak("pq-fors-tx/master-secret/v1" || ownerPrivateKey)`.

The account keeps exactly two storage slots: the verifier address and one packed word
`(chainIndex << 160) | owner`. A rotation overwrites that word, so it costs no state gas,
and the stored index lets a restarted scenario resume without scanning. Keys that were
rotated out are not remembered; only the signer picks `next`, and a signer deriving keys
by index never names an old one.

### What gets deployed

All through spamoor's CREATE2 deployment factory, so addresses are stable per chain and
nothing is redeployed on a rerun:

| Contract | Deployer | Salt |
| --- | --- | --- |
| `ForsVerifier` (Solidity, stateless) | well-known wallet `deployer` | `sha256("pq-frame-tx/ForsVerifier/v1")` |
| `TestToken` (ERC20 from spamoor's erc20tx) | well-known wallet `deployer` | `sha256("pq-frame-tx/TestToken/v1")` |
| `ForsFrameAccount` per child wallet | the child wallet | `keccak("pq-fors-tx/account/v1" \|\| owner)` |

Each account is then funded by its owner wallet (`--account-fund`, topped up below
`--account-refill`), and the account itself pays for its frame transactions.

### Usage

```bash
spamoor --plugin ./pq-frame-tx pq-fors-tx \
  -h https://rpc-lighthouse-geth-1.srv.bogota-devnet-1.ethpandaops.io \
  -h https://rpc-lighthouse-geth-2.srv.bogota-devnet-1.ethpandaops.io \
  -p <privkey> -t 5 -c 100 --operation mixed --log-txs
```

bogota-devnet-1 runs the EIP-8141 layout with per-gas fee caps, which current spamoor only
builds with its global `--legacy-frame-fees` flag.

Point spamoor at individual nodes rather than a load-balanced endpoint: spamoor tracks
confirmations by loading every block body, and a balancer that mixes in a lagging or
non-validating backend (besu does not validate frame transactions on bogota-devnet-1)
answers "block not found" for recent blocks, which stalls the pool. The node list is at
`https://config.<devnet>.ethpandaops.io/api/v1/nodes/inventory`.

### Options

| Flag | YAML | Default | Description |
| --- | --- | --- | --- |
| `-c, --count` | `total_count` | 0 | Total transactions (0 = unlimited) |
| `-t, --throughput` | `throughput` | 10 | Transactions per slot |
| `--max-pending` | `max_pending` | 0 | Max in flight (capped at the number of accounts) |
| `--max-wallets` | `max_wallets` | 0 | Child wallets = accounts (auto: 3x throughput, 4..200) |
| `--operation` | `operation` | `mixed` | `eth`, `erc20` or `mixed` (alternating) |
| `--amount` | `amount` | 20 | Amount per operation in gwei / token units |
| `--random-amount` | `random_amount` | true | Random amount up to `--amount` |
| `--random-target` | `random_target` | false | Send to fresh random addresses |
| `--envelope` | `envelope` | `auto` | `auto` (probe the chain), `full`, `keyed` (EIP-8250), `base` (EIP-8141 only) |
| `--verify-gas` | `verify_gas` | 90000 | Execution gas of the VERIFY frame (uses ~43k) |
| `--rotate-gas` | `rotate_gas` | 60000 | Execution gas of the rotation frame (uses ~22k) |
| `--rotate-state-gas` | `rotate_state_gas` | 0 | State gas of the rotation frame (the owner slot is overwritten, none needed) |
| `--op-gas` | `op_gas` | 0 | Execution gas of the user operation (0 = derived: 50k ETH transfer, 350k ERC20 transferMint) |
| `--op-state-gas` | `op_state_gas` | 0 | State gas of the user operation (0 = derived: two fresh ERC20 balance slots, or a new account for random ETH targets) |
| `--account-fund` | `account_fund` | 1 | ETH sent to an account that is below the refill threshold |
| `--account-refill` | `account_refill` | 0.2 | ETH threshold for topping up |
| `--prepare-workers` | `prepare_workers` | 8 | Concurrent account deployments at startup |
| `--verify-frames` | `verify_frames` | true | Check receipts: payer is the account, all frames succeeded |
| `--skip-mempool-check` | `skip_mempool_check` | false | Skip the local public-mempool prefix check |
| `--basefee`, `--tipfee`, `--basefee-wei`, `--tipfee-wei`, `--rebroadcast`, `--timeout`, `--client-group`, `--deploy-client-group`, `--log-txs` | | | Standard spamoor options |

### Measured cost (bogota-devnet-1)

| Frame | Execution gas | State gas |
| --- | ---: | ---: |
| VERIFY | 40,657 | 0 |
| rotateOwner | 12,083 | 0 |
| ETH transfer | 3,000 | 0 |

plus the calldata of the ~2.7 KB transaction. (The earlier layout with one `authState`
slot per key cost 22,277 execution gas and 97,920 state gas per rotation.) The validation prefix stays well under the
public mempool's 100k `MAX_VERIFY_GAS`; a SPHINCS-based account (257k+) would not.

## Scenario `pq-sphincs-tx`

Every child wallet of the scenario owns one `SphincsFrameAccount`. Each transaction of an
account has three frames and no signature entry:

```
frame 0  DEP_VERIFY  flags=0  target=-        0x10 || bytes32(0) || PK.seed || PK.root
frame 1  VERIFY      flags=3  target=account  (no data)
frame 2  SENDER      flags=0  target=...      ETH transfer or TestToken.transferMint(to, amount)
```

Frame 0 declares a leanSPHINCS dependency: a signature of the account's key over the
transaction's signature hash, which the zero `data_hash` stands for. The frame executes
nothing. The VERIFY frame only checks that frame 0 declares exactly the key in the
account's storage and `APPROVE`s execution and payment. The signature itself is never on
chain: the block carries one recursive STARK (roughly 250 kB) proving
every dependency of every transaction in it.

The signature travels beside the transaction in a mode-0 mempool wrapper

```
rlp([[raw_tx], 0, [[0x10 || sig_hash || key], [key || signature]]])      6,525 bytes
```

submitted with `eth_sendProofWrapper`; `eth_sendRawTransaction` refuses a transaction that
declares dependencies. The frame, the wrapper and the RPC call are spamoor's own
(`txtypes.DependencyFrame`, `txtypes.ProofWrapper`, `Client.SendProofWrapper`): the scenario
hands the wrapper to the tx pool through the `OnSubmit` callback, so sending, rebroadcast
and confirmation tracking are the pool's usual ones.

SPHINCS-G is stateless and many-time, so there is no key rotation and the account keeps a
single storage slot. The key is `sphincsg.DeriveKey(keccak("pq-sphincs-tx/key-secret/v1" ||
ownerPrivateKey))`.

### What gets deployed

| Contract | Deployer | Salt |
| --- | --- | --- |
| `TestToken` (shared with `pq-fors-tx`) | well-known wallet `deployer` | `sha256("pq-frame-tx/TestToken/v1")` |
| `SphincsFrameAccount` per child wallet | the child wallet | `keccak("pq-sphincs-tx/account/v1" \|\| owner)` |

No verifier contract: the chain verifies the signatures.

### Usage

```bash
spamoor --plugin ./pq-frame-tx pq-sphincs-tx \
  -h https://rpc.daisugi-devnet-0.ethpandaops.io \
  -p <privkey> -t 5 -c 100 --operation mixed --log-txs
```

The per-node endpoints of daisugi-devnet-0 need credentials; with them, prefer individual
nodes over the balanced endpoint, for the reason given under `pq-fors-tx`.

### Options

| Flag | YAML | Default | Description |
| --- | --- | --- | --- |
| `-c, --count` | `total_count` | 0 | Total transactions (0 = unlimited) |
| `-t, --throughput` | `throughput` | 5 | Transactions per slot |
| `--max-pending` | `max_pending` | 0 | Max in flight (capped at the number of accounts) |
| `--max-wallets` | `max_wallets` | 0 | Child wallets = accounts (auto: 3x throughput, 4..200) |
| `--operation` | `operation` | `mixed` | `eth`, `erc20` or `mixed` (alternating) |
| `--amount` | `amount` | 20 | Amount per operation in gwei / token units |
| `--random-amount` | `random_amount` | true | Random amount up to `--amount` |
| `--random-target` | `random_target` | false | Send to fresh random addresses |
| `--verify-gas` | `verify_gas` | 50000 | Execution gas of the VERIFY frame |
| `--op-gas` | `op_gas` | 0 | Execution gas of the user operation (0 = derived: 50k ETH transfer, 350k ERC20 transferMint) |
| `--op-state-gas` | `op_state_gas` | -1 | State gas of the user operation (-1 = derived from the operation and the chain's gas model) |
| `--account-fund` | `account_fund` | 1 | ETH sent to an account that is below the refill threshold |
| `--account-refill` | `account_refill` | 0.2 | ETH threshold for topping up |
| `--prepare-workers` | `prepare_workers` | 8 | Concurrent account deployments at startup |
| `--verify-frames` | `verify_frames` | true | Check receipts: payer is the account, all frames succeeded |
| `--skip-mempool-check` | `skip_mempool_check` | false | Skip the local public-mempool prefix check |
| `--basefee`, `--tipfee`, `--basefee-wei`, `--tipfee-wei`, `--rebroadcast`, `--timeout`, `--client-group`, `--deploy-client-group`, `--log-txs` | | | Standard spamoor options |

### Gas

A dependency costs 3,000 execution gas in its frame plus 30,000 intrinsic gas for its share
of the recursive STARK. Both are part of the `max_fee` budget `txtypes` derives.

### Signing speed

A signature takes roughly 66,000 keccak calls: 16 ms compiled, a little under a second
through spamoor's Yaegi interpreter on one core. Transactions of different accounts are signed concurrently,
so throughput scales with cores and `--max-wallets`.

## Packages

| Path | Content |
| --- | --- |
| `fors/` | Pure-Go FORS+C (n=16, k=26, a=5, keccak256): key derivation, signing, recover. Tested byte-for-byte against the reference Python signer (`fors/testdata`). |
| `sphincsg/` | Pure-Go SPHINCS-G (n=16, h=20, d=5, a=9, k=19, w=16, keccak256): key derivation, signing, verification. Tested against a signature of the reference signer (`sphincsg/testdata`) and accepted by daisugi-devnet-0's wrapper validation. |
| `contract/` | Vendored sources (`ForsVerifier.sol` + `ISignatureVerifier.sol` from Post-Quantum-AA-Infra, `TestToken.sol` from spamoor's erc20tx, the geas accounts), `build.sh` which compiles them with solc 0.8.30 and geas into `bytecode.go`, and calldata/storage helpers. |
| `pqforstx/` | The `pq-fors-tx` scenario. |
| `pqsphincstx/` | The `pq-sphincs-tx` scenario. |

## Caveats

- The keys are derived from spamoor child wallet keys; they are test material for a devnet.
- `pq-fors-tx`: a transaction that is signed but never lands exposes a key without burning it. The
  scenario re-reads the chain position from storage and reuses that key once, which FORS+C
  tolerates with a reduced margin.
- One transaction per account is in flight at a time; throughput scales with
  `--max-wallets`.
- `pq-sphincs-tx` sends one transaction per wrapper. A wrapper may carry up to 16
  signatures, which would save round trips at high throughput.
