package pqforstx

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/contract"
	"github.com/ethpandaops/spamoor/plugins/pq-frame-tx/fors"
)

func ownerWord(index uint64, owner common.Address) common.Hash {
	word := new(uint256.Int).SetUint64(index)
	word.Lsh(word, 160)
	word.Or(word, new(uint256.Int).SetBytes(owner.Bytes()))

	return word.Bytes32()
}

func TestResolveChainPosition(t *testing.T) {
	secret := common.HexToHash("0x1234")

	for _, index := range []uint64{0, 1, 7, 8, 1000, 123456} {
		key := fors.DeriveKey(secret, index)

		got, owner, err := resolveChainPosition(secret, ownerWord(index, key.Address))
		require.NoError(t, err)
		require.Equal(t, index, got)
		require.Equal(t, key.Address, owner)
	}
}

func TestResolveChainPositionRejectsForeignOwner(t *testing.T) {
	secret := common.HexToHash("0x1234")
	other := fors.DeriveKey(common.HexToHash("0x5678"), 3).Address

	_, _, err := resolveChainPosition(secret, ownerWord(3, other))
	require.ErrorContains(t, err, "wrong owner wallet")

	_, _, err = resolveChainPosition(secret, common.Hash{})
	require.ErrorContains(t, err, "not initialised")
}

func TestDecodeOwnerSlotRoundTrip(t *testing.T) {
	owner := common.HexToAddress("0x20678e08e9b74df2070b9257e87d1e9f08f23e47")

	index, got := contract.DecodeOwnerSlot(ownerWord(9, owner))
	require.Equal(t, uint64(9), index)
	require.Equal(t, owner, got)
}
