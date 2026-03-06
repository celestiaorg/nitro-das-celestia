package das

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseNamespaceID_ShortSubID(t *testing.T) {
	ns, err := parseNamespaceID("000008e5f679bf7116cb")
	require.NoError(t, err)
	require.Equal(t, 58, len(ns.String()))
}

func TestParseNamespaceID_FullNamespace(t *testing.T) {
	short := "000008e5f679bf7116cb"
	shortNS, err := parseNamespaceID(short)
	require.NoError(t, err)

	// version(00) + 18 bytes zero padding + 10-byte subID.
	full := "00" + strings.Repeat("00", 18) + short

	ns, err := parseNamespaceID(full)
	require.NoError(t, err)
	require.Equal(t, shortNS.String(), ns.String())
}

func TestParseNamespaceID_InvalidV0Padding(t *testing.T) {
	// Set one non-zero byte inside the expected zero padding range.
	invalid := "00" + strings.Repeat("00", 5) + "01" + strings.Repeat("00", 12) + "000008e5f679bf7116cb"

	_, err := parseNamespaceID(invalid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid v0 namespace")
}
