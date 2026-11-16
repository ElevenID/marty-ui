//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

var errStaticInit = errors.New("fresh OpenBao static-seal initialization refused; retain the pending setup and private outputs")

const staticInitTimeout = 120 * time.Second

type staticInitRequestFailure string

const (
	staticInitRequestDeadline staticInitRequestFailure = "initialization_request_context_deadline"
	staticInitRequestCanceled staticInitRequestFailure = "initialization_request_context_canceled"
	staticInitRequestRefused  staticInitRequestFailure = "initialization_request_or_response_refused"
	staticInitMaterialRefused staticInitRequestFailure = "initialization_response_material_refused"
)

func (failure staticInitRequestFailure) Error() string { return errStaticInit.Error() }
func (failure staticInitRequestFailure) Unwrap() error { return errStaticInit }

// StaticInitFailureClass exposes only fixed local classifications. It never
// returns an underlying transport error, response body, token, or private path.
// Every failed initialization request still has an uncertain server outcome.
func StaticInitFailureClass(err error) string {
	var failure staticInitRequestFailure
	if errors.As(err, &failure) {
		switch failure {
		case staticInitRequestDeadline, staticInitRequestCanceled, staticInitRequestRefused, staticInitMaterialRefused:
			return string(failure)
		}
	}
	return ""
}

// The one fresh sys/init POST can spend the remaining initialization context
// receiving its response. Other control requests retain their short timeouts.
// A new client owns its transport; no shared client or transport is modified.
func newStaticInitClientAt(path string, expected owner) (*http.Client, error) {
	client, err := newClientAt(path, expected)
	if err != nil {
		return nil, err
	}
	defer closeClient(client)
	return cloneStaticInitClient(client)
}

func cloneStaticInitClient(client *http.Client) (*http.Client, error) {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errStaticInit
	}
	initializationTransport := transport.Clone()
	initializationTransport.ResponseHeaderTimeout = 0
	initializationClient := *client
	initializationClient.Transport = initializationTransport
	initializationClient.Timeout = 0
	return &initializationClient, nil
}

type staticInitPaths struct {
	state, output string
	root          owner
}

// StaticInitReceipt is public evidence from one fresh initialization. The static
// seal key is never mounted in this job, read by it, or included in evidence.
type StaticInitReceipt struct {
	Schema                 string `json:"schema"`
	InstallationID         string `json:"installation_id"`
	AttemptID              string `json:"attempt_id"`
	ClusterID              string `json:"cluster_id"`
	SealType               string `json:"seal_type"`
	Initialized            bool   `json:"initialized"`
	UnsealedReady          bool   `json:"unsealed_ready"`
	RecoveryKeyWritten     bool   `json:"recovery_key_written"`
	RootTokenWritten       bool   `json:"root_token_written"`
	RootRetired            bool   `json:"root_retired"`
	InitializationReplayed bool   `json:"initialization_replayed"`
	InstallationReady      bool   `json:"installation_ready"`
}

type staticInitIntent struct {
	Schema            string `json:"schema"`
	InstallationID    string `json:"installation_id"`
	AttemptID         string `json:"attempt_id"`
	SealType          string `json:"seal_type"`
	RecoveryShares    int    `json:"recovery_shares"`
	RecoveryThreshold int    `json:"recovery_threshold"`
}

type staticInitMaterial struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	AttemptID      string `json:"attempt_id"`
	RecoveryKey    string `json:"recovery_key"`
	RootToken      string `json:"root_token"`
}

// InitializeStatic has no seal-key, URL, output-path, migration, or unseal
// option. The host's exclusive fresh setup job and durable intent own this
// call. An existing or uncertain initialization can never be adopted/replayed.
func InitializeStatic(ctx context.Context, installationID, attemptID string) (StaticInitReceipt, error) {
	if os.Geteuid() != 0 || !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return StaticInitReceipt{}, errStaticInit
	}
	expected, err := imageOwner()
	if err != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	client, err := NewClient()
	if err != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	defer closeClient(client)
	initializationClient, err := newStaticInitClientAt(SocketPath, expected)
	if err != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	defer closeClient(initializationClient)
	return initializeStaticAt(ctx, installationID, attemptID, staticInitPaths{
		state: "/bao/data", output: "/bao/static-init", root: owner{0, 0},
	}, expected, client, initializationClient)
}

// Root-owned private initialization outputs live inside the image-owned state
// directory. No ownership repair occurs; every output is created exclusively.
func writeRootExclusive(directory *os.File, name string, data []byte, root owner, mode uint32) (retainedFile, error) {
	if len(data) == 0 || len(data) > 16384 || (mode != 0400 && mode != 0600) || strings.ContainsAny(name, "/\\") || name == "" || name == "." || name == ".." {
		return retainedFile{}, errFiles
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return retainedFile{}, errFiles
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var created syscall.Stat_t
	if syscall.Fstat(fd, &created) != nil || created.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		created.Uid != root.uid || created.Gid != root.gid || created.Mode&07777 != mode || created.Nlink != 1 ||
		directory.Sync() != nil {
		return retainedFile{}, errFiles
	}
	if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil || directory.Sync() != nil {
		return retainedFile{}, errFiles
	}
	retained, err := readFile(directory, name, root, []uint32{mode}, 16384, false)
	if err != nil || !sameInode(created, retained.stat) || !bytes.Equal(data, retained.bytes) {
		return retainedFile{}, errFiles
	}
	return retained, nil
}

func initializeStaticAt(ctx context.Context, installationID, attemptID string, paths staticInitPaths, expected owner, client, initializationClient *http.Client) (StaticInitReceipt, error) {
	// Bound the entire initialization even for an unbounded caller. A shorter
	// parent deadline or cancellation remains authoritative; the POST never
	// starts a new budget after the fresh-state checks and durable intent.
	ctx, cancel := context.WithTimeout(ctx, staticInitTimeout)
	defer cancel()
	var receipt StaticInitReceipt
	if !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return receipt, errStaticInit
	}
	state, err := openDirectory(paths.state, expected, 0700)
	if err != nil {
		return receipt, errStaticInit
	}
	defer state.Close()
	output, err := openDirectory(paths.output, paths.root, 0700)
	if err != nil {
		return receipt, errStaticInit
	}
	defer output.Close()
	var stateStat, outputStat syscall.Stat_t
	if syscall.Fstat(int(state.Fd()), &stateStat) != nil || syscall.Fstat(int(output.Fd()), &outputStat) != nil ||
		stateStat.Dev == outputStat.Dev && stateStat.Ino == outputStat.Ino || emptyDirectory(output) != nil {
		return receipt, errStaticInit
	}
	for _, directory := range []*os.File{state, output} {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Flags&1 != 0 {
			return receipt, errStaticInit
		}
	}
	for _, name := range []string{"selfhost-init.json", "root.token", "unseal.key", "recovery.key", "static-init-material.json", initialAuthorityName} {
		if _, exists, err := objectStat(state, name); err != nil || exists {
			return receipt, errStaticInit
		}
	}
	status, err := staticStatus(ctx, client, false)
	if err != nil || status.Initialized || !status.Sealed {
		return receipt, errStaticInit
	}
	intent, err := json.Marshal(staticInitIntent{
		Schema: "elevenid.openbao-static-init-intent/v1", InstallationID: installationID,
		AttemptID: attemptID, SealType: "static", RecoveryShares: 1, RecoveryThreshold: 1,
	})
	if err != nil || boundDirectory(state, paths.state, expected) != nil || boundDirectory(output, paths.output, paths.root) != nil {
		return receipt, errStaticInit
	}
	pending, err := writeRootExclusive(output, "static-init-pending.json", intent, paths.root, 0600)
	if err != nil {
		return receipt, errStaticInit
	}
	var initialized struct {
		UnsealKeys    []string `json:"keys"`
		UnsealKeysB64 []string `json:"keys_base64"`
		RecoveryKeys  []string `json:"recovery_keys"`
		RecoveryB64   []string `json:"recovery_keys_base64"`
		RootToken     string   `json:"root_token"`
	}
	// Auto seals reject Shamir secret_shares/secret_threshold. Recovery shares
	// authorize administrative recovery; they cannot replace the static key.
	if err := apiRequest(ctx, initializationClient, http.MethodPost, "sys/init", "", map[string]int{
		"recovery_shares": 1, "recovery_threshold": 1,
	}, &initialized); err != nil {
		switch ctx.Err() {
		case context.DeadlineExceeded:
			return receipt, staticInitRequestDeadline
		case context.Canceled:
			return receipt, staticInitRequestCanceled
		default:
			return receipt, staticInitRequestRefused
		}
	}
	if len(initialized.UnsealKeys) != 0 || len(initialized.UnsealKeysB64) != 0 ||
		len(initialized.RecoveryKeys) != 1 || len(initialized.RecoveryB64) != 1 ||
		len(initialized.RootToken) < 20 || len(initialized.RootToken) > 4096 ||
		strings.IndexFunc(initialized.RootToken, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return receipt, staticInitMaterialRefused
	}
	recovery, err := base64.StdEncoding.DecodeString(initialized.RecoveryB64[0])
	hexRecovery, hexErr := hex.DecodeString(initialized.RecoveryKeys[0])
	if err != nil || hexErr != nil || len(recovery) < 32 || len(recovery) > 64 ||
		base64.StdEncoding.EncodeToString(recovery) != initialized.RecoveryB64[0] || !bytes.Equal(recovery, hexRecovery) {
		return receipt, staticInitMaterialRefused
	}
	material, err := json.Marshal(staticInitMaterial{
		Schema: "elevenid.openbao-static-init-private/v1", InstallationID: installationID,
		AttemptID: attemptID, RecoveryKey: initialized.RecoveryB64[0], RootToken: initialized.RootToken,
	})
	if err != nil || boundDirectory(state, paths.state, expected) != nil || boundDirectory(output, paths.output, paths.root) != nil ||
		unchangedFile(output, "static-init-pending.json", pending, paths.root, []uint32{0600}, 16384, false) != nil {
		return receipt, errStaticInit
	}
	materialFile, err := writeRootExclusive(state, "static-init-material.json", material, paths.root, 0400)
	if err != nil {
		return receipt, errStaticInit
	}
	recoveryFile, err := writeRootExclusive(state, "recovery.key", []byte(initialized.RecoveryB64[0]), paths.root, 0400)
	if err != nil {
		return receipt, errStaticInit
	}
	rootFile, err := writeRootExclusive(state, "root.token", []byte(initialized.RootToken), paths.root, 0400)
	if err != nil {
		return receipt, errStaticInit
	}
	// Initialization may return before Raft finishes becoming usable. Observe
	// readiness only: this loop never submits recovery shares to sys/unseal.
	for {
		status, err = staticStatus(ctx, client, true)
		if err == nil {
			break
		}
		if ctx.Err() != nil || status.ListenerAvailable && (status.SealType != "static" || !status.RecoverySeal) {
			return receipt, errStaticInit
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return receipt, errStaticInit
		case <-timer.C:
		}
	}
	if boundDirectory(state, paths.state, expected) != nil || boundDirectory(output, paths.output, paths.root) != nil ||
		unchangedFile(output, "static-init-pending.json", pending, paths.root, []uint32{0600}, 16384, false) != nil ||
		unchangedFile(state, "static-init-material.json", materialFile, paths.root, []uint32{0400}, 16384, false) != nil ||
		unchangedFile(state, "recovery.key", recoveryFile, paths.root, []uint32{0400}, 16384, false) != nil ||
		unchangedFile(state, "root.token", rootFile, paths.root, []uint32{0400}, 16384, false) != nil {
		return receipt, errStaticInit
	}
	receipt = StaticInitReceipt{
		Schema: "elevenid.openbao-static-init-result/v1", InstallationID: installationID,
		AttemptID: attemptID, ClusterID: status.ClusterID, SealType: "static", Initialized: true,
		UnsealedReady: true, RecoveryKeyWritten: true, RootTokenWritten: true,
		RootRetired: false, InitializationReplayed: false, InstallationReady: false,
	}
	// Bind the exact initial root/recovery files privately before any public
	// completion. Later retirement can prove original authority without sending
	// secret digests or token accessors to the host.
	authorityFile, err := writeInitialAuthority(state, paths.root, installationID, attemptID, status.ClusterID, rootFile, recoveryFile)
	if err != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	if _, err := writeRootExclusive(output, "static-init-result.json", public, paths.root, 0600); err != nil ||
		unchangedFile(state, initialAuthorityName, authorityFile, paths.root, []uint32{0400}, 8192, false) != nil ||
		unchangedFile(state, "static-init-material.json", materialFile, paths.root, []uint32{0400}, 16384, false) != nil ||
		syscall.Unlinkat(int(state.Fd()), "static-init-material.json") != nil || state.Sync() != nil {
		return StaticInitReceipt{}, errStaticInit
	}
	return receipt, nil
}
