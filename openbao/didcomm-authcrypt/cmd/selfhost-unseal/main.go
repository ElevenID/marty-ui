// selfhost-unseal restores access to an initialized Raft-backed OpenBao node.
// It never reads the initial root token or puts the unseal key in process arguments.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/openbaocontrol"
)

type sealStatus struct {
	Initialized *bool `json:"initialized"`
	Sealed      *bool `json:"sealed"`
}

var errStatusUnavailable = errors.New("OpenBao status is unavailable")

func main() {
	checkListener := flag.Bool("check-listener", false, "observe local listener availability without changing seal state")
	checkUnsealed := flag.Bool("check-unsealed", false, "observe initialized and unsealed readiness without changing seal state")
	flag.Parse()
	if flag.NArg() != 0 || (*checkListener && *checkUnsealed) {
		fatal(errors.New("invalid OpenBao health check mode"))
	}
	addr := valueOrDefault("BAO_ADDR", "https://openbao:8200")
	caFile := valueOrDefault("BAO_CACERT", "/bao/data/tls/ca.crt")
	keyFile := valueOrDefault("BAO_UNSEAL_KEY_FILE", "/bao/data/unseal.key")
	client, endpoint, err := configuredClient(os.Getenv("MARTY_OPENBAO_LOCAL_CONTROL"), addr, caFile, keyFile)
	if err != nil {
		fatal(err)
	}
	if *checkListener || *checkUnsealed {
		observation, err := check(context.Background(), client, endpoint, *checkUnsealed)
		if err == nil || observation.ListenerAvailable {
			if json.NewEncoder(os.Stdout).Encode(observation) != nil {
				fatal(errors.New("OpenBao health output failed"))
			}
		}
		if err != nil {
			fatal(err)
		}
		return
	}
	for {
		if err := reconcile(context.Background(), client, endpoint, keyFile); err != nil {
			fatal(err)
		}
		time.Sleep(5 * time.Second)
	}
}

// The installer opts into one fixed local endpoint. Missing/unsafe sockets and
// conflicting network/path settings fail closed; they never trigger fallback.
// Existing non-installer callers retain their verified HTTPS configuration.
func configuredClient(local, addr, caFile, keyFile string) (*http.Client, string, error) {
	if local == "" {
		return secureClient(addr, caFile)
	}
	if local != "1" || addr != "https://openbao:8200" || caFile != "/bao/data/tls/ca.crt" || keyFile != "/bao/data/unseal.key" {
		return nil, "", errors.New("OpenBao local control configuration refused")
	}
	client, err := openbaocontrol.NewClient()
	if err != nil {
		return nil, "", err
	}
	return client, openbaocontrol.Endpoint, nil
}

type healthObservation struct {
	Schema            string `json:"schema"`
	ListenerAvailable bool   `json:"listener_available"`
	Initialized       bool   `json:"initialized"`
	Sealed            bool   `json:"sealed"`
	UnsealedReady     bool   `json:"unsealed_ready"`
	InstallationReady bool   `json:"installation_ready"`
}

func check(ctx context.Context, client *http.Client, endpoint string, requireUnsealed bool) (healthObservation, error) {
	observation := healthObservation{Schema: "elevenid.openbao-local-health/v1"}
	status, err := requestStatus(ctx, client, endpoint)
	if err != nil {
		return observation, err
	}
	observation.ListenerAvailable = true
	observation.Initialized = *status.Initialized
	observation.Sealed = *status.Sealed
	observation.UnsealedReady = *status.Initialized && !*status.Sealed
	if requireUnsealed && !observation.UnsealedReady {
		return observation, errors.New("OpenBao is not initialized and unsealed")
	}
	return observation, nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "OpenBao unseal failed:", err)
	os.Exit(1)
}

func secureClient(addr, caFile string) (*http.Client, string, error) {
	parsed, err := url.Parse(addr)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", errors.New("OpenBao address must be an HTTPS origin")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, "", errors.New("OpenBao CA is unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, "", errors.New("OpenBao CA is invalid")
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, strings.TrimRight(addr, "/"), nil
}

func requestStatus(ctx context.Context, client *http.Client, endpoint string) (sealStatus, error) {
	var status sealStatus
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/seal-status", nil)
	if err != nil {
		return status, err
	}
	response, err := client.Do(request)
	if err != nil {
		return status, errStatusUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return status, errors.New("OpenBao status returned an unexpected response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return status, errors.New("OpenBao status exceeds bounds")
	}
	if err := json.Unmarshal(body, &status); err != nil ||
		status.Initialized == nil || status.Sealed == nil {
		return status, errors.New("OpenBao status is invalid")
	}
	return status, nil
}

func readUnsealKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return nil, errors.New("OpenBao unseal key file is missing or invalid")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("OpenBao unseal key file is unreadable")
	}
	key = bytes.TrimSpace(key)
	if len(key) == 0 || bytes.ContainsAny(key, "\r\n\x00") {
		return nil, errors.New("OpenBao unseal key is invalid")
	}
	return key, nil
}

func reconcile(ctx context.Context, client *http.Client, endpoint, keyFile string) error {
	status, err := requestStatus(ctx, client, endpoint)
	if err != nil {
		if errors.Is(err, errStatusUnavailable) {
			// The OpenBao container may still be starting or restarting.
			return nil
		}
		return err
	}
	if !*status.Initialized {
		if _, err := os.Lstat(keyFile); err == nil {
			return errors.New("uninitialized OpenBao has existing unseal material")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot inspect OpenBao unseal material")
		}
		return nil // The explicit bootstrap service owns first initialization.
	}
	if !*status.Sealed {
		return nil
	}
	key, err := readUnsealKey(keyFile)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Key string `json:"key"`
	}{Key: string(key)})
	if err != nil {
		return errors.New("cannot encode OpenBao unseal request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/sys/unseal", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("OpenBao unseal request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("OpenBao rejected the unseal request")
	}
	var result sealStatus
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&result); err != nil ||
		result.Sealed == nil || *result.Sealed {
		return errors.New("OpenBao remained sealed after unseal")
	}
	return nil
}
