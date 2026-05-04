package tree

import (
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/tendermint/tendermint/crypto/tmhash"

	"github.com/ethereum/go-ethereum/common"
)

var (
	leafPrefix  = []byte{0}
	innerPrefix = []byte{1}
)

// returns tmhash(<empty>)
func emptyHash() []byte {
	return tmhash.Sum([]byte{})
}

// returns tmhash(0x00 || leaf)
func leafHash(record func(bytes32, []byte, arbutil.PreimageType), leaf []byte) []byte {
	preimage := make([]byte, 0, 1+len(leaf))
	preimage = append(preimage, leafPrefix...)
	preimage = append(preimage, leaf...)
	hash := tmhash.Sum(preimage)

	record(common.BytesToHash(hash), preimage, arbutil.Sha2_256PreimageType)
	return hash
}

// returns tmhash(0x01 || left || right)
func innerHash(record func(bytes32, []byte, arbutil.PreimageType), left []byte, right []byte) []byte {
	preimage := make([]byte, 0, 1+len(left)+len(right))
	preimage = append(preimage, innerPrefix...)
	preimage = append(preimage, left...)
	preimage = append(preimage, right...)
	hash := tmhash.Sum(preimage)

	record(common.BytesToHash(hash), preimage, arbutil.Sha2_256PreimageType)
	return hash
}
