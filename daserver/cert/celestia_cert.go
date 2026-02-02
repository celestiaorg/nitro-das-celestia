package cert

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	CustomDAHeaderFlag    byte   = 0x01
	CelestiaProviderTag   byte   = 0x0c
	CelestiaCertVersion   uint16 = 1
	CelestiaDACertV1Len   int    = 92
	SequencerMsgOffset    int    = 40
)

// CelestiaDACertV1 is the Custom DA certificate format for Celestia.
// Binary layout (big endian):
// [0]      header (0x01)
// [1]      providerType (0x0c)
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

func (c *CelestiaDACertV1) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	buf.WriteByte(CustomDAHeaderFlag)
	buf.WriteByte(CelestiaProviderTag)

	if err := binary.Write(buf, binary.BigEndian, CelestiaCertVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, c.BlockHeight); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, c.Start); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, c.SharesLength); err != nil {
		return nil, err
	}
	if _, err := buf.Write(c.TxCommitment[:]); err != nil {
		return nil, err
	}
	if _, err := buf.Write(c.DataRoot[:]); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c *CelestiaDACertV1) UnmarshalBinary(data []byte) error {
	if len(data) != CelestiaDACertV1Len {
		return errors.New("certificate has invalid length")
	}
	if data[0] != CustomDAHeaderFlag {
		return errors.New("invalid certificate header")
	}
	if data[1] != CelestiaProviderTag {
		return errors.New("invalid provider type")
	}

	buf := bytes.NewReader(data[2:])

	var version uint16
	if err := binary.Read(buf, binary.BigEndian, &version); err != nil {
		return err
	}
	if version != CelestiaCertVersion {
		return errors.New("unsupported certificate version")
	}

	if err := binary.Read(buf, binary.BigEndian, &c.BlockHeight); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &c.Start); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &c.SharesLength); err != nil {
		return err
	}
	if _, err := buf.Read(c.TxCommitment[:]); err != nil {
		return err
	}
	if _, err := buf.Read(c.DataRoot[:]); err != nil {
		return err
	}

	return nil
}
