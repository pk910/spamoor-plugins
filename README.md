# spamoor-plugins

Plugins for [spamoor](https://github.com/ethpandaops/spamoor), the Ethereum transaction
spammer. Spamoor loads plugins from Go source at runtime through the Yaegi interpreter, so
nothing here is compiled into a binary; the archives built by `make plugins` contain the
sources plus a `plugin.yaml`.

| Plugin | Scenarios | Purpose |
| --- | --- | --- |
| [`pq-frame-tx`](pq-frame-tx/) | `pq-fors-tx` | EIP-8141 frame transactions from smart accounts authenticated with the post-quantum FORS+C signature scheme |

## Layout

Each top-level directory with a `plugin.go` is one plugin, following spamoor's
[plugin guide](https://github.com/ethpandaops/spamoor/blob/master/docs/plugin-system.md):
`plugin.go` exports `PluginDescriptor`, scenarios live in sub-packages, and imports use the
`github.com/ethpandaops/spamoor/plugins/<plugin>/...` paths that spamoor mounts them under.

The `go.mod` at the root declares that same module path so `go test`, `go vet` and gopls
work natively on the pure-Go parts. Spamoor itself never reads it.

## Build

```bash
make plugins       # dist/<plugin>.tar.gz for every plugin
make validate      # load each plugin through spamoor-utils validate-plugin
make test          # native unit tests (e.g. the FORS+C signer against reference vectors)
```

## Run

```bash
# from a local directory (development)
spamoor --plugin ./pq-frame-tx pq-fors-tx -h <rpc> -p <privkey> -t 5 -c 50

# from an archive
spamoor --plugin ./dist/pq-frame-tx.tar.gz pq-fors-tx -h <rpc> -p <privkey> -t 5

# in the daemon: register dist/<plugin>.tar.gz through the /plugins page or the API
```

Plugins may only import the packages spamoor exposes to the interpreter (its own
`scenario`, `spamoor`, `txbuilder`, `txtypes`, `utils`; go-ethereum `common`, `types`,
`abi`, `bind`, `crypto`, `event`; logrus, pflag, uint256, yaml.v3; and the standard library).
