package rawi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New("rh_test")
	if err != nil {
		t.Fatal(err)
	}
	client.base = server.URL
	return client
}

func TestStopWaitsForHypervisor(t *testing.T) {
	var reads atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rh_test" {
			t.Error("missing provider authorization")
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /servers/server-1/power":
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != `{"action":"stop"}` {
				t.Error("incorrect stop payload")
			}
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"action":"stop","queued":true}`)
		case "GET /servers/server-1/status":
			if reads.Add(1) == 1 {
				io.WriteString(w, `{"status":{"power":"running"}}`)
			} else {
				io.WriteString(w, `{"status":{"power":"stopped"}}`)
			}
		default:
			http.NotFound(w, r)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.RequestStop(ctx, "server-1"); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 0 {
		t.Fatal("stop submission unexpectedly queried status")
	}
	if err := client.WaitStopped(ctx, "server-1", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 2 {
		t.Fatal("did not wait for confirmed power-off")
	}
}

func TestUnconfirmedPowerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"conflict", 409, "rh_test"},
		{"redirect", 307, ""},
		{"missing power", 200, `{"status":{"lifecycle":"active"}}`},
		{"malformed", 200, `{"status":`},
		{"oversize", 200, strings.Repeat(" ", 33*1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/should-not-follow")
				if r.URL.Path == "/should-not-follow" {
					t.Error("followed redirect")
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.WaitStopped(ctx, "server-1", time.Millisecond); err == nil || strings.Contains(err.Error(), "rh_test") {
				t.Fatalf("expected a sanitized error, got %v", err)
			}
		})
	}
}

func TestUnknownPowerWaitsUntilDeadline(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"status":{"power":"unknown"}}`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := client.WaitStopped(ctx, "server-1", time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline", err)
	}
	if _, err := client.Power(context.Background(), "../other"); err == nil {
		t.Fatal("invalid server ID accepted")
	}
}
