// Package contract holds the bytecode of the contracts the pq-frame-tx plugin deploys and
// the encoding helpers for talking to the FORS+C frame account.
package contract

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// ForsFrameAccount storage layout (see ForsFrameAccount.eas).
const (
	// SlotVerifier holds the ForsVerifier address.
	SlotVerifier = 0
	// SlotOwner holds (chainIndex << 160) | owner: the current key and how many rotations
	// led to it.
	SlotOwner = 1

	// RotateCalldataLen is selector(4) + current(32) + next(32).
	RotateCalldataLen = 68
)

var (
	// SelectorRotateOwner is rotateOwner(address,address).
	SelectorRotateOwner = crypto.Keccak256([]byte("rotateOwner(address,address)"))[:4]

	// OwnerRotatedTopic is the OwnerRotated(address,address) event signature.
	OwnerRotatedTopic = crypto.Keccak256Hash([]byte("OwnerRotated(address,address)"))
)

// ForsVerifierInitcode returns the creation bytecode of ForsVerifier.
func ForsVerifierInitcode() []byte {
	return common.FromHex(ForsVerifierInitcodeHex)
}

// ForsFrameAccountInitcode returns the creation bytecode of an account bound to
// `verifier` whose first ACTIVE key is `initialOwner`.
func ForsFrameAccountInitcode(verifier, initialOwner common.Address) []byte {
	ctor := common.FromHex(ForsFrameAccountInitcodeHex)

	initcode := make([]byte, 0, len(ctor)+64)
	initcode = append(initcode, ctor...)
	initcode = append(initcode, common.LeftPadBytes(verifier.Bytes(), 32)...)
	initcode = append(initcode, common.LeftPadBytes(initialOwner.Bytes(), 32)...)

	return initcode
}

// OwnerSlot is the storage key of the packed owner word.
func OwnerSlot() common.Hash {
	return common.BigToHash(big.NewInt(SlotOwner))
}

// DecodeOwnerSlot splits the packed owner word into the chain index and the owner.
func DecodeOwnerSlot(word common.Hash) (index uint64, owner common.Address) {
	value := new(uint256.Int).SetBytes(word.Bytes())
	owner = common.BytesToAddress(word[12:])
	index = new(uint256.Int).Rsh(value, 160).Uint64()

	return index, owner
}

// RotateCalldata encodes rotateOwner(current, next).
func RotateCalldata(current, next common.Address) []byte {
	data := make([]byte, 0, RotateCalldataLen)
	data = append(data, SelectorRotateOwner...)
	data = append(data, common.LeftPadBytes(current.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(next.Bytes(), 32)...)

	return data
}

// TestTokenInitcode returns the creation bytecode of the ERC20 test token.
func TestTokenInitcode() []byte {
	return common.FromHex(TestTokenBin)
}

// TestTokenTransferMintCalldata encodes transferMint(to, amount).
func TestTokenTransferMintCalldata(to common.Address, amount *big.Int) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(TestTokenABI))
	if err != nil {
		return nil, err
	}

	return parsed.Pack("transferMint", to, amount)
}
