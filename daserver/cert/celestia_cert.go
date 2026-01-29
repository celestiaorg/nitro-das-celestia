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
// [36..67] namespace (bytes32, right padded with zeros)
// [68..75] height (uint64)
// [76..79] shareStart (uint32)
// [80..83] shareLen (uint32)
// [84..115] txCommitment (bytes32)
// [116..119] proofLen (uint32)
// [120..] proof bytes
type CelestiaDACertV1 struct {
	DataRoot     [32]byte
	Namespace    [32]byte
	Height       uint64
	ShareStart   uint32
	ShareLen     uint32
	TxCommitment [32]byte
	Proof        []byte
}

func Serialize(cert *CelestiaDACertV1) []byte {
	proofLen := uint32(len(cert.Proof))
	buf := make([]byte, 0, 120+proofLen)
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

	field4 := make([]byte, 4)
	binary.BigEndian.PutUint32(field4, cert.ShareStart)
	buf = append(buf, field4...)
	binary.BigEndian.PutUint32(field4, cert.ShareLen)
	buf = append(buf, field4...)

	buf = append(buf, cert.TxCommitment[:]...)

	proofLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLenBytes, proofLen)
	buf = append(buf, proofLenBytes...)
	buf = append(buf, cert.Proof...)

	return buf
}

func Deserialize(data []byte) (*CelestiaDACertV1, error) {
	if len(data) < 120 {
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
	copy(cert.Namespace[:], data[36:68])
	cert.Height = binary.BigEndian.Uint64(data[68:76])
	cert.ShareStart = binary.BigEndian.Uint32(data[76:80])
	cert.ShareLen = binary.BigEndian.Uint32(data[80:84])
	copy(cert.TxCommitment[:], data[84:116])
	proofLen := binary.BigEndian.Uint32(data[116:120])

	if int(120+proofLen) != len(data) {
		return nil, errors.New("invalid proof length")
	}
	if proofLen > 0 {
		cert.Proof = make([]byte, proofLen)
		copy(cert.Proof, data[120:])
	}

	return cert, nil
}
