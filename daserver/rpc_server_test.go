package das

import (
	"context"
	"errors"
	"testing"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/stretchr/testify/require"
)

type rpcFakeCelestiaReader struct{}

func (f *rpcFakeCelestiaReader) Read(context.Context, *cert.CelestiaDACertV1) (*types.ReadResult, error) {
	return nil, errors.New("unused in this test")
}

func (f *rpcFakeCelestiaReader) GetProof(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *rpcFakeCelestiaReader) GenerateReadPreimageProof(context.Context, uint64, *cert.CelestiaDACertV1) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *rpcFakeCelestiaReader) GenerateCertificateValidityProof(context.Context, *cert.CelestiaDACertV1) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func newInProcDAProviderClient(t *testing.T) *rpc.Client {
	t.Helper()

	server := rpc.NewServer()
	err := server.RegisterName("daprovider", &DaClientServer{
		reader: types.NewReaderForCelestia(&rpcFakeCelestiaReader{}),
	})
	require.NoError(t, err)

	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	return client
}

func makeRPCMalformedSequencerMessage(t *testing.T, mutate func([]byte) []byte) []byte {
	t.Helper()

	var txCommitment [32]byte
	var dataRoot [32]byte
	txCommitment[0] = 0xAA
	dataRoot[0] = 0xBB
	certificate := cert.NewCelestiaCertificate(123, 10, 100, txCommitment, dataRoot)
	certBytes, err := certificate.MarshalBinary()
	require.NoError(t, err)
	sequencerMsg := make([]byte, cert.SequencerMsgOffset+len(certBytes))
	copy(sequencerMsg[cert.SequencerMsgOffset:], certBytes)
	return mutate(sequencerMsg)
}

func TestDAProviderRPC_MalformedCertificateReturnsCertificateValidationError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		sequencerMsg []byte
		wantContains string
	}{
		{
			name:         "sequencer_message_too_short",
			sequencerMsg: []byte{0x01, 0x02},
			wantContains: "certificate validation failed",
		},
		{
			name: "invalid_certificate_header",
			sequencerMsg: makeRPCMalformedSequencerMessage(t, func(msg []byte) []byte {
				mutated := append([]byte(nil), msg...)
				mutated[cert.SequencerMsgOffset] = 0x00
				return mutated
			}),
			wantContains: "certificate validation failed: invalid certificate header",
		},
		{
			name: "invalid_provider_type",
			sequencerMsg: makeRPCMalformedSequencerMessage(t, func(msg []byte) []byte {
				mutated := append([]byte(nil), msg...)
				mutated[cert.SequencerMsgOffset+1] = 0x00
				return mutated
			}),
			wantContains: "certificate validation failed: invalid provider type",
		},
		{
			name: "unsupported_certificate_version",
			sequencerMsg: makeRPCMalformedSequencerMessage(t, func(msg []byte) []byte {
				mutated := append([]byte(nil), msg...)
				mutated[cert.SequencerMsgOffset+2] = 0x00
				mutated[cert.SequencerMsgOffset+3] = 0x02
				return mutated
			}),
			wantContains: "certificate validation failed: unsupported certificate version",
		},
	}

	client := newInProcDAProviderClient(t)

	for _, tc := range cases {
		tc := tc

		t.Run("recover_payload_"+tc.name, func(t *testing.T) {
			var result daprovider.PayloadResult
			err := client.Call(&result, "daprovider_recoverPayload", hexutil.Uint64(1), common.Hash{}, hexutil.Bytes(tc.sequencerMsg))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantContains)
		})

		t.Run("collect_preimages_"+tc.name, func(t *testing.T) {
			var result daprovider.PreimagesResult
			err := client.Call(&result, "daprovider_collectPreimages", hexutil.Uint64(1), common.Hash{}, hexutil.Bytes(tc.sequencerMsg))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantContains)
		})

		t.Run("recover_payload_and_preimages_"+tc.name, func(t *testing.T) {
			var result daprovider.PayloadAndPreimagesResult
			err := client.Call(&result, "daprovider_recoverPayloadAndPreimages", hexutil.Uint64(1), common.Hash{}, hexutil.Bytes(tc.sequencerMsg))
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantContains)
		})
	}
}
