package cert

import (
	"encoding/hex"
	"testing"
)

func TestCelestiaDACertV1_RoundTrip(t *testing.T) {
	original := &CelestiaDACertV1{
		BlockHeight:  12345,
		Start:        100,
		SharesLength: 50,
		TxCommitment: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		DataRoot:     [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != CelestiaDACertV1Len {
		t.Fatalf("expected length %d, got %d", CelestiaDACertV1Len, len(data))
	}

	parsed := &CelestiaDACertV1{}
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if *parsed != *original {
		t.Fatalf("round-trip mismatch:\n  got:  %+v\n  want: %+v", parsed, original)
	}
}

func TestCelestiaDACertV1_GoldenEncoding(t *testing.T) {
	cert := &CelestiaDACertV1{
		BlockHeight:  1,
		Start:        2,
		SharesLength: 3,
		TxCommitment: [32]byte{},
		DataRoot:     [32]byte{},
	}

	data, err := cert.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify header bytes
	if data[0] != CustomDAHeaderFlag {
		t.Errorf("header byte: got 0x%02x, want 0x%02x", data[0], CustomDAHeaderFlag)
	}
	if data[1] != CelestiaMessageHeaderFlag {
		t.Errorf("provider tag: got 0x%02x, want 0x%02x", data[1], CelestiaMessageHeaderFlag)
	}

	// Verify exact encoding for known values
	got := hex.EncodeToString(data)
	// header(01) + provider(63) + version(0001) + height(1) + start(2) + len(3) + commitment + dataroot
	want := "01630001" + "0000000000000001" + "0000000000000002" + "0000000000000003" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	if got != want {
		t.Errorf("encoding mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestCelestiaDACertV1_UnmarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", make([]byte, 91)},
		{"too long", make([]byte, 93)},
		{"wrong header", func() []byte {
			d := make([]byte, 92)
			d[0] = 0xFF
			return d
		}()},
		{"wrong provider", func() []byte {
			d := make([]byte, 92)
			d[0] = CustomDAHeaderFlag
			d[1] = 0xFF
			return d
		}()},
		{"wrong version", func() []byte {
			d := make([]byte, 92)
			d[0] = CustomDAHeaderFlag
			d[1] = CelestiaMessageHeaderFlag
			d[2] = 0xFF // version high byte
			d[3] = 0xFF // version low byte
			return d
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CelestiaDACertV1{}
			if err := c.UnmarshalBinary(tt.data); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
