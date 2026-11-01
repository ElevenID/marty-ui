//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInspectionIsReadOnlyAndContainsOnlyPublicIdentity(t *testing.T) {
	fixture := newRecoveryFixture(t, "")
	before, _ := os.ReadDir(fixture.paths.tls)
	observation, err := inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now)
	if err != nil || !observation.NodeKeyMatches || !observation.RenewalIssuerUsable || observation.Transaction != nil || observation.CompletedReceipt != nil {
		t.Fatal("initial inspection failed", err)
	}
	after, _ := os.ReadDir(fixture.paths.tls)
	if len(before) != len(after) || fixture.requests.Load() != 0 {
		t.Fatal("inspection created state or called an API")
	}
	data, _ := json.Marshal(observation)
	for _, private := range []string{"PRIVATE KEY", testRole, testSecret, testToken} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("inspection emitted private material")
		}
	}
	if observation.CertificateSHA256 == "" || observation.CASHA256 != fixture.identity.CASHA256 || observation.SPKISHA256 != fixture.identity.SPKISHA256 {
		t.Fatal("inspection lost enrolled identities")
	}
	expires, _ := time.Parse(time.RFC3339, observation.NotAfter)
	if !expires.Before(fixture.now) {
		t.Fatal("inspection did not observe the expired network leaf")
	}
	// A read-only diagnosis remains possible after authority expiry, but never
	// represents that expired CA as usable for renewal.
	observation, err = inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.ca.NotAfter.Add(time.Second))
	if err != nil || observation.RenewalIssuerUsable {
		t.Fatal("expired authority diagnostic was lost or misrepresented", err)
	}
}

func TestInspectionBindsPendingAndCompletedRecovery(t *testing.T) {
	fixture := newRecoveryFixture(t, "")
	interruptRecovery(t, fixture, "candidate-durable")
	requests := fixture.requests.Load()
	observation, err := inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now)
	if err != nil || observation.Transaction == nil || observation.Transaction.Phase != "candidate" || observation.Transaction.AttemptID != testAttempt || observation.CompletedReceipt != nil || !exactHash(observation.TransactionSHA256) {
		t.Fatal("candidate inspection incomplete", err)
	}
	receipt, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	observation, err = inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now)
	if err != nil || observation.Transaction.Phase != "published" || observation.CompletedReceipt == nil || *observation.CompletedReceipt != receipt || !exactHash(observation.CompletedReceiptSHA256) || fixture.requests.Load() != requests {
		t.Fatal("completed inspection lost receipt or made API requests", err)
	}
	file, _ := os.ReadFile(filepath.Join(fixture.paths.tls, completedName(testAttempt)))
	if fingerprint(file) != observation.CompletedReceiptSHA256 {
		t.Fatal("completed receipt digest was not over retained bytes")
	}
}

func TestInspectionRefusesLiveWriterAndChangedCustody(t *testing.T) {
	for _, changed := range []string{"live-writer", "identity", "ca", "server", "lock-created", "journal-created"} {
		t.Run(changed, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			if changed == "live-writer" {
				directory, err := openDirectory(fixture.paths.tls, currentOwner(), 0700)
				if err != nil {
					t.Fatal(err)
				}
				defer directory.Close()
				lock, err := acquireRecoveryLock(directory, currentOwner())
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			} else {
				fixture.paths.checkpoint = func(point string) error {
					if point != "inspection-observed" {
						return nil
					}
					switch changed {
					case "identity", "ca", "server":
						path := filepath.Join(fixture.paths.tls, "server.pem")
						if changed == "identity" {
							path = filepath.Join(fixture.paths.identity, "recovery.json")
						}
						if changed == "ca" {
							path = filepath.Join(fixture.paths.tls, "ca.crt")
						}
						data, _ := os.ReadFile(path)
						if os.Remove(path) != nil || os.WriteFile(path, data, 0600) != nil {
							t.Fatal("cannot replace inspected fixture")
						}
					case "lock-created":
						if os.WriteFile(filepath.Join(fixture.paths.tls, recoveryLockName), nil, 0600) != nil {
							t.Fatal("cannot create fixture lock")
						}
					case "journal-created":
						if syscall.Mkfifo(filepath.Join(fixture.paths.tls, recoveryJournalName), 0600) != nil {
							t.Fatal("cannot create fixture journal")
						}
					}
					return nil
				}
			}
			if _, err := inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now); err == nil || fixture.requests.Load() != 0 {
				t.Fatal("inspection accepted changed custody or reached API")
			}
		})
	}
}
