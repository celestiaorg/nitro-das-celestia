package cert

import (
	"encoding/binary"
	"errors"
)

const (
	CustomDAHeaderFlag  byte   = 0x01
	CelestiaProviderTag byte   = 0x0c
	CelestiaCertVersion uint16 = 1
)

// CelestiaDACertV1 is the Custom DA certificate format for Celestia.
// Binary layout (big endian):
// [0]      header (0x01)
// [1]      providerType (0x0c)
// [2..3]   version (uint16)
// [4..35]  dataRoot (bytes32)
// [36..45] namespace (10 bytes)
// [46..53] height (uint64)
// [54..61] shareStart (uint64)
// [62..69] shareLen (uint64)
// [70..101] txCommitment (bytes32)
// No proof bytes are embedded; proofs are supplied at verification time.
type CelestiaDACertV1 struct {
	DataRoot     [32]byte
	Namespace    [10]byte
	Height       uint64
	ShareStart   uint64
	ShareLen     uint64
	TxCommitment [32]byte
}

func Serialize(cert *CelestiaDACertV1) []byte {
	buf := make([]byte, 0, 102)
	buf = append(buf, CustomDAHeaderFlag)
	buf = append(buf, CelestiaProviderTag)

	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, CelestiaCertVersion)
	buf = append(buf, version...)

	buf = append(buf, cert.DataRoot[:]...)
	buf = append(buf, cert.Namespace[:]...)

	field := make([]byte, 8)
	binary.BigEndian.PutUint64(field, cert.Height)
	buf = append(buf, field...)

	field = make([]byte, 8)
	binary.BigEndian.PutUint64(field, cert.ShareStart)
	buf = append(buf, field...)
	binary.BigEndian.PutUint64(field, cert.ShareLen)
	buf = append(buf, field...)

	buf = append(buf, cert.TxCommitment[:]...)

	return buf
}

func Deserialize(data []byte) (*CelestiaDACertV1, error) {
	if len(data) != 102 {
		return nil, errors.New("certificate too short")
	}
	if data[0] != CustomDAHeaderFlag {
		return nil, errors.New("invalid certificate header")
	}
	if data[1] != CelestiaProviderTag {
		return nil, errors.New("invalid provider type")
	}
	version := binary.BigEndian.Uint16(data[2:4])
	if version != CelestiaCertVersion {
		return nil, errors.New("unsupported certificate version")
	}

	cert := &CelestiaDACertV1{}
	copy(cert.DataRoot[:], data[4:36])
	copy(cert.Namespace[:], data[36:46])
	cert.Height = binary.BigEndian.Uint64(data[46:54])
	cert.ShareStart = binary.BigEndian.Uint64(data[54:62])
	cert.ShareLen = binary.BigEndian.Uint64(data[62:70])
	copy(cert.TxCommitment[:], data[70:102])

	return cert, nil
}
