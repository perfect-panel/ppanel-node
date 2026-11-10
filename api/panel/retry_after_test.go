package panel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/conf"
)

func TestRetryAfterSecondsAndDate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cause := errors.New("panel busy")
	for _, test := range []struct {
		header string
		want   time.Duration
	}{
		{"60", time.Minute}, {" 30 ", 30 * time.Second},
		{now.Add(time.Minute).Format(http.TimeFormat), time.Minute},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"", 0}, {"0", 0}, {"-1", 0}, {"invalid", 0}, {"9999999999", 24 * time.Hour},
	} {
		t.Run(test.header, func(t *testing.T) {
			err := withRetryAfter(cause, test.header, now)
			if !errors.Is(err, cause) {
				t.Fatal("lost underlying panel error")
			}
			var hint interface{ RetryAfter() time.Duration }
			var got time.Duration
			if errors.As(err, &hint) {
				got = hint.RetryAfter()
			}
			if got != test.want {
				t.Fatalf("hint = %s, want %s", got, test.want)
			}
		})
	}
}

type admissionTransport func(*http.Request) (*http.Response, error)

func (f admissionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDeviceRequestBoundsDeadlineAndRetainsOverloadHint(t *testing.T) {
	for _, binary := range []bool{false, true} {
		client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: "http://localhost", NodeType: "vless", UseProtobuf: binary})
		if err != nil {
			t.Fatal(err)
		}
		client.Client.SetTransport(admissionTransport(func(req *http.Request) (*http.Response, error) {
			deadline, ok := req.Context().Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
				t.Error("claim did not bound its deadline")
			}
			// Even a proxy-generated non-Protobuf error must retain Retry-After.
			return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": {"60"}}, Body: io.NopCloser(strings.NewReader("unavailable")), Request: req}, nil
		}))
		allowed, _, err := client.ClaimDevice(context.Background(), 21, "127.0.0.1")
		var hint interface{ RetryAfter() time.Duration }
		if allowed || !errors.As(err, &hint) || hint.RetryAfter() != time.Minute {
			t.Fatalf("overload decision: %v %v", allowed, err)
		}
	}
}
