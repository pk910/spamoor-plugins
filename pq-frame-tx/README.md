# pq-frame-tx

Spamoor plugin that sends [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) frame
transactions from smart accounts authenticated with a post-quantum hash-based signature
scheme. The accounts and the verifier come from
[RivaLabs-Core/Post-Quantum-AA-Infra](https://github.com/RivaLabs-Core/Post-Quantum-AA-Infra)
(the NiceTry ephemeral-key wallet design); the frame account itself is the geas contract
in `contract/ForsFrameAccount.eas`.

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

## Packages

| Path | Content |
| --- | --- |
| `fors/` | Pure-Go FORS+C (n=16, k=26, a=5, keccak256): key derivation, signing, recover. Tested byte-for-byte against the reference Python signer (`fors/testdata`). |
| `contract/` | Vendored sources (`ForsVerifier.sol` + `ISignatureVerifier.sol` from Post-Quantum-AA-Infra, `TestToken.sol` from spamoor's erc20tx, the geas account), `build.sh` which compiles them with solc 0.8.30 and geas into `bytecode.go`, and calldata/storage helpers. |
| `pqforstx/` | The scenario. |

## Caveats

- The key chain is derived from spamoor child wallet keys; it is test material for a devnet.
- A transaction that is signed but never lands exposes a key without burning it. The
  scenario re-reads the chain position from storage and reuses that key once, which FORS+C
  tolerates with a reduced margin.
- One transaction per account is in flight at a time; throughput scales with
  `--max-wallets`.
