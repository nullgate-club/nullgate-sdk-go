package nullgate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestTransportCauseUsesTypesNotMessages(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "cancelled"},
		{&net.DNSError{Err: "private-host", Name: "private-host"}, "dns"},
		{syscall.ECONNREFUSED, "connection"},
		{errors.New("timeout DNS TLS proxy password=private"), "unknown"},
		{nil, "invalid_response"},
	} {
		cause := transportCause(test.err)
		if cause.Kind != test.want || cause.Type != "" || cause.Code != "" {
			t.Fatalf("unexpected cause: %#v", cause)
		}
	}
}

func TestMalformedMetadataDoesNotBecomeTransportAttribution(t *testing.T) {
	for _, raw := range []string{
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe"}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":null,"retryable":null}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"cause":{"kind":"invented"}}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"cause":{"kind":"unknown","type":"https://secret@proxy"}}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"command_id":0}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"command_id":-1}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"command_id":1.5}`,
		`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"command_id":true}`,
	} {
		if parseErrorInfo(json.RawMessage(raw)) != nil {
			t.Fatal("accepted malformed metadata")
		}
	}
}

func TestMetadataRetainsPositiveCommandID(t *testing.T) {
	info := parseErrorInfo(json.RawMessage(`{"code":"CLIENT_TRANSPORT_ERROR","origin":"client","message":"safe","retryable":null,"command_id":2}`))
	if info == nil || info.CommandID == nil || *info.CommandID != 2 {
		t.Fatal("lost positive command ID")
	}
}
