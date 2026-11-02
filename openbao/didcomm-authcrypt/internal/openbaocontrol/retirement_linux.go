//go:build linux

package openbaocontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
)

const (
	retirementLockName    = ".root-retirement.lock"
	retirementJournalName = ".root-retirement-transaction.json"
)

var errRetirement = errors.New("initial OpenBao root retirement incomplete; preserve the exact pending attempt and original authority")

// RootRetirementReceipt contains public facts only. Private initial-authority
// digests and accessors are deliberately absent. Host eligibility is a separate
// immutable intent covering app validation and independent retained identities.
type RootRetirementReceipt struct {
	Schema                    string `json:"schema"`
	InstallationID            string `json:"installation_id"`
	AttemptID                 string `json:"attempt_id"`
	IntentSHA256              string `json:"intent_sha256"`
	ClusterID                 string `json:"cluster_id"`
	RootRejectionObserved     bool   `json:"root_rejection_observed"`
	RootTokenRemoved          bool   `json:"root_token_removed"`
	RecoveryKeyPreserved      bool   `json:"recovery_key_preserved"`
	OriginalAuthorityVerified bool   `json:"original_authority_verified"`
	AuthorityRecordPreserved  bool   `json:"authority_record_preserved"`
	InitializationReplayed    bool   `json:"initialization_replayed"`
	InstallationReady         bool   `json:"installation_ready"`
}
type rootRetirementPaths struct {
	state, identity  string
	root             owner
	readOnlyIdentity bool
	checkpoint       func(string) error
}
type retirementJournal struct {
	Schema                  string `json:"schema"`
	InstallationID          string `json:"installation_id"`
	AttemptID               string `json:"attempt_id"`
	IntentSHA256            string `json:"intent_sha256"`
	ClusterID               string `json:"cluster_id"`
	InitializationAttemptID string `json:"initialization_attempt_id"`
	AuthoritySHA256         string `json:"authority_sha256"`
	Phase                   string `json:"phase"`
}

func (journal retirementJournal) receipt() RootRetirementReceipt {
	return RootRetirementReceipt{Schema: "elevenid.openbao-initial-root-retirement-result/v1", InstallationID: journal.InstallationID, AttemptID: journal.AttemptID,
		IntentSHA256: journal.IntentSHA256, ClusterID: journal.ClusterID, RootRejectionObserved: true, RootTokenRemoved: true, RecoveryKeyPreserved: true,
		OriginalAuthorityVerified: true, AuthorityRecordPreserved: true, InitializationReplayed: false, InstallationReady: false}
}

func RetireInitialRoot(ctx context.Context, installation, attempt, intentSHA string) (RootRetirementReceipt, error) {
	if os.Geteuid() != 0 || !uuidPattern.MatchString(installation) || !uuidPattern.MatchString(attempt) || !exactHash(intentSHA) {
		return RootRetirementReceipt{}, errRetirement
	}
	expected, err := imageOwner()
	if err != nil {
		return RootRetirementReceipt{}, errRetirement
	}
	client, err := NewClient()
	if err != nil {
		return RootRetirementReceipt{}, errRetirement
	}
	defer closeClient(client)
	return retireInitialRootAt(ctx, installation, attempt, intentSHA, rootRetirementPaths{state: "/bao/data", identity: identityDirectory, root: owner{0, 0}, readOnlyIdentity: true}, expected, client)
}

func initialRootRejected(ctx context.Context, client *http.Client, token string) (bool, error) {
	if len(token) < 20 || len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return false, errRetirement
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return false, errRetirement
	}
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		return false, errRetirement
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(data) > 16384 {
		return false, errRetirement
	}
	if response.StatusCode == http.StatusForbidden {
		return true, nil
	}
	if response.StatusCode != http.StatusOK {
		return false, errRetirement
	}
	var lookup struct {
		Data struct {
			ID       string   `json:"id"`
			Policies []string `json:"policies"`
			Path     string   `json:"path"`
			Type     string   `json:"type"`
			Orphan   *bool    `json:"orphan"`
		} `json:"data"`
	}
	if decodeJSON(data, &lookup, false) != nil || lookup.Data.ID != token || len(lookup.Data.Policies) != 1 || lookup.Data.Policies[0] != "root" || lookup.Data.Path != "auth/token/root" || lookup.Data.Type != "service" || lookup.Data.Orphan == nil || !*lookup.Data.Orphan {
		return false, errRetirement
	}
	return false, nil
}

func retireInitialRootAt(ctx context.Context, installation, attempt, intentSHA string, paths rootRetirementPaths, expected owner, client *http.Client) (RootRetirementReceipt, error) {
	var result RootRetirementReceipt
	if !uuidPattern.MatchString(installation) || !uuidPattern.MatchString(attempt) || !exactHash(intentSHA) {
		return result, errRetirement
	}
	state, err := openDirectory(paths.state, expected, 0700)
	if err != nil {
		return result, errRetirement
	}
	defer state.Close()
	lock, err := acquireNamedControlLock(state, paths.root, retirementLockName)
	if err != nil {
		return result, errRetirement
	}
	defer lock.Close()
	authority, authorityFile, err := readInitialAuthority(state, paths.root, installation)
	if err != nil {
		return result, errRetirement
	}
	identityDir, err := openDirectory(paths.identity, paths.root, 0700)
	if err != nil {
		return result, errRetirement
	}
	defer identityDir.Close()
	identityFile, err := readFile(identityDir, "recovery.json", paths.root, []uint32{0400, 0600}, 8192, paths.readOnlyIdentity)
	if err != nil {
		return result, errRetirement
	}
	identity, err := parseIdentity(identityFile.bytes, installation)
	if err != nil || identity.ClusterID != authority.ClusterID {
		return result, errRetirement
	}
	pending, enrollment, err := requireEnrollment(identityDir, paths.root, paths.readOnlyIdentity, identity)
	if err != nil {
		return result, errRetirement
	}
	recovery, err := readFile(state, "recovery.key", paths.root, []uint32{0400}, 4096, false)
	if err != nil || bindAuthorityFile(recovery) != authority.Recovery {
		return result, errRetirement
	}
	guard := func() error {
		if boundDirectory(state, paths.state, expected) != nil || boundDirectory(identityDir, paths.identity, paths.root) != nil || requireNamedControlLock(state, lock, paths.root, retirementLockName) != nil ||
			unchangedFile(state, initialAuthorityName, authorityFile, paths.root, []uint32{0400}, 8192, false) != nil || unchangedFile(state, "recovery.key", recovery, paths.root, []uint32{0400}, 4096, false) != nil ||
			unchangedFile(identityDir, "recovery.json", identityFile, paths.root, []uint32{0400, 0600}, 8192, paths.readOnlyIdentity) != nil ||
			unchangedFile(identityDir, "enrollment-pending.json", pending, paths.root, []uint32{0600}, 8192, paths.readOnlyIdentity) != nil ||
			unchangedFile(identityDir, "enrollment-result.json", enrollment, paths.root, []uint32{0600}, 16384, paths.readOnlyIdentity) != nil {
			return errRetirement
		}
		for _, name := range []string{"selfhost-init.json", "static-init-material.json", "unseal.key"} {
			if _, exists, err := objectStat(state, name); err != nil || exists {
				return errRetirement
			}
		}
		return nil
	}
	if guard() != nil {
		return result, errRetirement
	}
	journalFile, err := optionalPublic(state, retirementJournalName, paths.root)
	if err != nil {
		return result, errRetirement
	}
	journal := retirementJournal{Schema: "elevenid.openbao-root-retirement-private/v1", InstallationID: installation, AttemptID: attempt, IntentSHA256: intentSHA,
		ClusterID: authority.ClusterID, InitializationAttemptID: authority.AttemptID, AuthoritySHA256: fingerprint(authorityFile.bytes), Phase: "prepared"}
	if journalFile != nil {
		var saved retirementJournal
		var fields map[string]json.RawMessage
		if decodeJSON(journalFile.bytes, &saved, true) != nil || json.Unmarshal(journalFile.bytes, &fields) != nil || len(fields) != 8 ||
			(saved.Phase != "prepared" && saved.Phase != "revocation_observed" && saved.Phase != "completed") {
			return result, errRetirement
		}
		journal.Phase = saved.Phase
		if saved != journal {
			return result, errRetirement
		}
	}
	privatePaths := recoveryPaths{tls: paths.state, root: paths.root, checkpoint: paths.checkpoint}
	save := func(phase string) error {
		journal.Phase = phase
		data, err := json.Marshal(journal)
		if err != nil || guard() != nil {
			return errRetirement
		}
		file, err := atomicPublic(state, privatePaths, expected, retirementJournalName, journalFile, data, "retirement-"+phase)
		if err != nil {
			return errRetirement
		}
		journalFile = &file
		return nil
	}
	rootStat, rootPresent, err := objectStat(state, "root.token")
	if err != nil {
		return result, errRetirement
	}
	var rootFile retainedFile
	if rootPresent {
		rootFile, err = readFile(state, "root.token", paths.root, []uint32{0400}, 4096, false)
		if err != nil || !sameFile(rootStat, rootFile.stat) || bindAuthorityFile(rootFile) != authority.Root {
			return result, errRetirement
		}
	} else if journalFile == nil || journal.Phase == "prepared" {
		return result, errRetirement
	}
	if journal.Phase == "completed" {
		if rootPresent || guard() != nil || unchangedFile(state, retirementJournalName, *journalFile, paths.root, []uint32{0600}, recoveryJournalMax, false) != nil {
			return result, errRetirement
		}
		return journal.receipt(), nil
	}
	if journalFile == nil {
		if save("prepared") != nil {
			return result, errRetirement
		}
	}
	unchangedJournal := func() error {
		return unchangedFile(state, retirementJournalName, *journalFile, paths.root, []uint32{0600}, recoveryJournalMax, false)
	}
	ready := func() error {
		status, err := staticStatus(ctx, client, true)
		if err != nil || status.ClusterID != authority.ClusterID {
			return errRetirement
		}
		return nil
	}
	if journal.Phase == "prepared" {
		if !rootPresent || guard() != nil || unchangedJournal() != nil || ready() != nil {
			return result, errRetirement
		}
		rejected, err := initialRootRejected(ctx, client, string(rootFile.bytes))
		if err != nil {
			return result, errRetirement
		}
		if !rejected {
			if unchangedFile(state, "root.token", rootFile, paths.root, []uint32{0400}, 4096, false) != nil || guard() != nil || unchangedJournal() != nil {
				return result, errRetirement
			}
			// The response may be lost after the revoke succeeds. Do not turn
			// that ordinary uncertainty into a new attempt or assume success.
			_ = apiRequest(ctx, client, http.MethodPost, "auth/token/revoke-self", string(rootFile.bytes), nil, nil)
			if checkpoint(privatePaths, "retirement-revoke-requested") != nil {
				return result, errRetirement
			}
			rejected, err = initialRootRejected(ctx, client, string(rootFile.bytes))
			if err != nil || !rejected {
				return result, errRetirement
			}
		}
		if ready() != nil || guard() != nil || unchangedJournal() != nil || unchangedFile(state, "root.token", rootFile, paths.root, []uint32{0400}, 4096, false) != nil || save("revocation_observed") != nil {
			return result, errRetirement
		}
	}
	if journal.Phase != "revocation_observed" || guard() != nil || unchangedJournal() != nil || ready() != nil {
		return result, errRetirement
	}
	if rootPresent {
		if unchangedFile(state, "root.token", rootFile, paths.root, []uint32{0400}, 4096, false) != nil || syscall.Unlinkat(int(state.Fd()), "root.token") != nil || state.Sync() != nil {
			return result, errRetirement
		}
		if checkpoint(privatePaths, "retirement-root-unlinked") != nil {
			return result, errRetirement
		}
	}
	if _, exists, err := objectStat(state, "root.token"); err != nil || exists || guard() != nil || unchangedJournal() != nil || save("completed") != nil {
		return result, errRetirement
	}
	if _, exists, err := objectStat(state, "root.token"); err != nil || exists || guard() != nil || unchangedJournal() != nil {
		return result, errRetirement
	}
	return journal.receipt(), nil
}
