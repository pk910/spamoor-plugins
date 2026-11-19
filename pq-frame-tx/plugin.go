// Package plugin is the spamoor entry point of the pq-frame-tx plugin: EIP-8141 frame
// transactions authenticated with post-quantum hash-based signatures, verified either by
// the account's own contract (FORS+C) or by the chain's recursive STARK (SPHINCS,
// EIP-8288).
package plugin

import (
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/pqforstx"
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/pqsphincstx"
	"github.com/ethpandaops/spamoor/scenario"
)

// PluginDescriptor defines the plugin metadata and scenarios.
var PluginDescriptor = scenario.PluginDescriptor{
	Name:        "pq-frame-tx",
	Description: "EIP-8141 frame transactions from post-quantum (FORS+C, SPHINCS) smart accounts",
	Categories: []*scenario.Category{
		{
			Name:        "Post-Quantum",
			Description: "Frame transactions authenticated with hash-based post-quantum signatures",
			Descriptors: []*scenario.Descriptor{
				&pqforstx.ScenarioDescriptor,
				&pqsphincstx.ScenarioDescriptor,
			},
		},
	},
}
