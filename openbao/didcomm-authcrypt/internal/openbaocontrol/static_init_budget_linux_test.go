//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type staticInitRoundTripper func(*http.Request) (*http.Response, error)

func (transport staticInitRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

// The real Unix response exceeds both ordinary production limits. The control
// case reproduces the old header timeout; the dedicated client must receive the
// same valid response within its operation context. No real OpenBao is started.
func TestStaticInitializationResponseBudgetIsSeparateFromControlRequests(t *testing.T) {
	assertStaticInitializationResponseBudget(t, staticInitUnixClients)
}

// This uses real HTTP transports and their timers over net.Pipe. It can run
// without OS socket permission and does not qualify Unix peer/socket custody.
func TestStaticInitializationInMemoryResponseBudgetIsSeparateFromControlRequests(t *testing.T) {
	assertStaticInitializationResponseBudget(t, staticInitMemoryClients)
}

func assertStaticInitializationResponseBudget(t *testing.T, server staticInitTestServer) {
	t.Helper()
	for _, dedicated := range []bool{false, true} {
		name := "ordinary-control-client"
		if dedicated {
			name = "initialization-client"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			paths, client, initializationClient, requests, initialized := staticInitFixtureWithServer(t, "", func(request *http.Request) {
				timer := time.NewTimer(16 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-request.Context().Done():
				}
			}, server)
			controlTransport := client.Transport.(*http.Transport)
			initializationTransport := initializationClient.Transport.(*http.Transport)
			if client.Timeout != 15*time.Second || controlTransport.ResponseHeaderTimeout != 10*time.Second ||
				initializationClient.Timeout != 0 || initializationTransport.ResponseHeaderTimeout != 0 ||
				controlTransport == initializationTransport {
				t.Fatal("initialization budget changed the ordinary client or shared its transport")
			}
			postClient := client
			if dedicated {
				postClient = initializationClient
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			receipt, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, postClient)
			if initialized.Load() != 1 {
				t.Fatal("delayed response caused a missing or repeated initialization POST")
			}
			result := filepath.Join(paths.output, "static-init-result.json")
			if dedicated {
				if err != nil || !receipt.UnsealedReady || receipt.InitializationReplayed || receipt.InstallationReady {
					t.Fatal("valid delayed initialization response was not accepted within its operation context")
				}
				if _, err := os.Stat(result); err != nil {
					t.Fatal("successful delayed initialization did not publish its scoped result")
				}
			} else {
				if err == nil || StaticInitFailureClass(err) != string(staticInitRequestRefused) || ctx.Err() != nil {
					t.Fatal("ordinary header timeout did not refuse before the operation deadline")
				}
				if _, err := os.Stat(result); !os.IsNotExist(err) {
					t.Fatal("timed-out ordinary request published a result")
				}
			}
			before := requests.Load()
			if _, err := initializeStaticAt(context.Background(), testInstallation, testAttempt, paths, currentOwner(), client, initializationClient); err == nil || requests.Load() != before {
				t.Fatal("delayed initialization outcome was adopted or replayed")
			}
		})
	}
}

func TestStaticInitializationInMemoryCancellationRetainsIntentAndRefusesReplay(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name, want := "canceled", staticInitRequestCanceled
		if deadline {
			name, want = "parent-deadline", staticInitRequestDeadline
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			paths, client, initializationClient, requests, initialized := staticInitFixtureWithServer(t, "", func(request *http.Request) {
				close(started)
				<-request.Context().Done()
			}, staticInitMemoryClients)
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, initializationClient)
				done <- err
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("initialization did not reach its single POST: %v", StaticInitFailureClass(err))
			case <-time.After(5 * time.Second):
				t.Fatal("initialization POST did not start")
			}
			pending := filepath.Join(paths.output, "static-init-pending.json")
			before, err := os.ReadFile(pending)
			if err != nil || !bytes.Contains(before, []byte(testAttempt)) {
				t.Fatal("initialization started without its retained attempt")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, errStaticInit) || StaticInitFailureClass(err) != string(want) {
					t.Fatal("cancellation did not report its fixed uncertain-outcome classification")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("initialization ignored its caller cancellation or shorter deadline")
			}
			after, err := os.ReadFile(pending)
			if err != nil || !bytes.Equal(before, after) || initialized.Load() != 1 {
				t.Fatal("cancellation changed the pending intent or repeated initialization")
			}
			if _, err := os.Stat(filepath.Join(paths.output, "static-init-result.json")); !os.IsNotExist(err) {
				t.Fatal("canceled initialization published a result")
			}
			for _, name := range []string{"static-init-material.json", "root.token", "recovery.key", initialAuthorityName} {
				if _, err := os.Stat(filepath.Join(paths.state, name)); !os.IsNotExist(err) {
					t.Fatal("canceled response invented private initialization outputs")
				}
			}
			count := requests.Load()
			if _, err := initializeStaticAt(context.Background(), testInstallation, testAttempt, paths, currentOwner(), client, initializationClient); err == nil || requests.Load() != count {
				t.Fatal("canceled initialization reached the API again")
			}
		})
	}
}

func TestStaticInitializationInMemoryAlwaysBoundsTheRequestContext(t *testing.T) {
	for _, budget := range []time.Duration{0, 240 * time.Second, 5 * time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			paths, client, initializationClient, _, _ := staticInitFixtureWithServer(t, "", nil, staticInitMemoryClients)
			ctx := context.Background()
			if budget > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, budget)
				defer cancel()
			}
			var observed time.Time
			transport := initializationClient.Transport
			initializer := *initializationClient
			initializer.Transport = staticInitRoundTripper(func(request *http.Request) (*http.Response, error) {
				var bounded bool
				observed, bounded = request.Context().Deadline()
				if !bounded || request.Method != http.MethodPost || request.URL.Path != "/v1/sys/init" {
					t.Error("dedicated client received an unbounded or unrelated request")
				}
				return transport.RoundTrip(request)
			})
			before := time.Now()
			if _, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, &initializer); err != nil {
				t.Fatal("bounded initialization fixture failed")
			}
			after := time.Now()
			if budget == 5*time.Second {
				parent, _ := ctx.Deadline()
				if !observed.Equal(parent) {
					t.Fatal("initialization extended its shorter parent deadline")
				}
			} else if observed.Before(before.Add(120*time.Second)) || observed.After(after.Add(120*time.Second)) {
				t.Fatal("unbounded or long parent did not receive the fixed120-second cap")
			}
		})
	}
}

func TestStaticInitializationFailureClassesNeverExposeUnderlyingErrors(t *testing.T) {
	for _, class := range []staticInitRequestFailure{staticInitRequestDeadline, staticInitRequestCanceled, staticInitRequestRefused, staticInitMaterialRefused} {
		err := fmt.Errorf("private fixture text must not escape: %w", class)
		if StaticInitFailureClass(err) != string(class) || class.Error() != errStaticInit.Error() {
			t.Fatal("fixed initialization classification changed or exposed an underlying error")
		}
	}
	for _, err := range []error{nil, errStaticInit, errors.New("private fixture token"), staticInitRequestFailure("private fixture token")} {
		if StaticInitFailureClass(err) != "" {
			t.Fatal("unknown initialization error became public diagnostic text")
		}
	}
}

type staticInitMemoryListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func (listener *staticInitMemoryListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *staticInitMemoryListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

type staticInitMemoryAddress struct{}

func (staticInitMemoryAddress) Network() string { return "in-memory" }
func (staticInitMemoryAddress) String() string  { return "static-init-fixture" }
func (listener *staticInitMemoryListener) Addr() net.Addr {
	return staticInitMemoryAddress{}
}

func staticInitMemoryClients(t *testing.T, handler http.Handler) (*http.Client, *http.Client) {
	t.Helper()
	listener := &staticInitMemoryListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1,
		MaxResponseHeaderBytes: 16 * 1024, ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "openbao-local.invalid:80" {
				return nil, errControl
			}
			client, peer := net.Pipe()
			select {
			case listener.connections <- peer:
				return client, nil
			case <-ctx.Done():
				client.Close()
				peer.Close()
				return nil, ctx.Err()
			case <-listener.closed:
				client.Close()
				peer.Close()
				return nil, net.ErrClosed
			}
		},
	}
	client := &http.Client{
		Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(func() { closeClient(client) })
	initializationClient, err := cloneStaticInitClient(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeClient(initializationClient) })
	return client, initializationClient
}
