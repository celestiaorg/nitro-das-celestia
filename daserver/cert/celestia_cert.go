package cert

import (
	"encoding/binary"
	"errors"
)

const (
	CustomDAHeaderFlag        byte   = 0x01
	CelestiaMessageHeaderFlag byte   = 0x63
	CelestiaCertVersion       uint16 = 1
	CelestiaDACertV1Len       int    = 92
	SequencerMsgOffset        int    = 40
)

// CelestiaDACertV1 is the Custom DA certificate format for Celestia.
// Binary layout (big endian):
// [0]      header (0x01)
// [1]      providerType (0x63)
// [2..3]   version (uint16)
// [4..11]  blockHeight (uint64)
// [12..19] start (uint64)
// [20..27] sharesLength (uint64)
// [28..59] txCommitment (bytes32)
// [60..91] dataRoot (bytes32)
// No proof bytes are embedded; proofs are supplied at verification time.
type CelestiaDACertV1 struct {
	BlockHeight  uint64
	Start        uint64
	SharesLength uint64
	TxCommitment [32]byte
	DataRoot     [32]byte
}

func NewCelestiaCertificate(blockHeight, start, sharesLength uint64, txCommitment, dataRoot [32]byte) *CelestiaDACertV1 {
	return &CelestiaDACertV1{
		BlockHeight:  blockHeight,
		Start:        start,
		SharesLength: sharesLength,
		TxCommitment: txCommitment,
		DataRoot:     dataRoot,
	}
}

func (c *CelestiaDACertV1) MarshalBinary() ([]byte, error) {
	buf := make([]byte, CelestiaDACertV1Len)
	offset := 0

	buf[offset] = CustomDAHeaderFlag
	offset++
	buf[offset] = CelestiaMessageHeaderFlag
	offset++
	binary.BigEndian.PutUint16(buf[offset:], CelestiaCertVersion)
	offset += 2
	binary.BigEndian.PutUint64(buf[offset:], c.BlockHeight)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], c.Start)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], c.SharesLength)
	offset += 8
	copy(buf[offset:], c.TxCommitment[:])
	offset += 32
	copy(buf[offset:], c.DataRoot[:])

	return buf, nil
}

func (c *CelestiaDACertV1) UnmarshalBinary(data []byte) error {
	if len(data) != CelestiaDACertV1Len {
		return errors.New("certificate has invalid length")
	}
	offset := 0

	if data[offset] != CustomDAHeaderFlag {
		return errors.New("invalid certificate header")
	}
	offset++
	if data[offset] != CelestiaMessageHeaderFlag {
		return errors.New("invalid provider type")
	}
	offset++

	version := binary.BigEndian.Uint16(data[offset:])
	if version != CelestiaCertVersion {
		return errors.New("unsupported certificate version")
	}
	offset += 2

	c.BlockHeight = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	c.Start = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	c.SharesLength = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	copy(c.TxCommitment[:], data[offset:])
	offset += 32
	copy(c.DataRoot[:], data[offset:])

	return nil
}
