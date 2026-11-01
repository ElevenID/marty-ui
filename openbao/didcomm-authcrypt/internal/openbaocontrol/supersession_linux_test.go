//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const replacementAttempt = "77777777-7777-4777-8777-777777777777"

func expireRecoveryCandidate(t *testing.T, fixture *recoveryFixture) {
	t.Helper()
	fixture.now = fixture.issued.NotAfter.Add(time.Second)
	fixture.issued = testCertificate(t, testLeaf(fixture.now, 7, fixture.now.Add(30*24*time.Hour)), fixture.ca, &fixture.key.PublicKey, fixture.caKey)
}

func TestExpiredCandidateSupersessionResumesEveryDurableBoundary(t *testing.T) {
	for _, initial := range []string{"candidate-durable", "stage-durable", "certificate-published"} {
		for _, point := range []string{"supersession-staged", "supersession-durable", "issuing-staged", "issuing-durable", "candidate-durable"} {
			t.Run(initial+"/"+point, func(t *testing.T) {
				fixture := newRecoveryFixture(t, "")
				interruptRecovery(t, fixture, initial)
				expired := fixture.issued
				if initial == "certificate-published" {
					fixture.old, _ = os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
				}
				expireRecoveryCandidate(t, fixture)
				reached := false
				fixture.paths.checkpoint = func(observed string) error {
					if observed == point {
						reached = true
						return errRecovery
					}
					return nil
				}
				if _, err := recoverAt(context.Background(), testInstallation, replacementAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || !reached {
					t.Fatalf("did not interrupt replacement at %s", point)
				}
				fixture.paths.checkpoint = nil
				observed, err := inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now)
				if err != nil {
					t.Fatal("interrupted replacement was not inspectable", err)
				}
				if point == "supersession-durable" || point == "issuing-staged" {
					if observed.PendingSupersession == nil || observed.PendingSupersession.ReplacementAttemptID != replacementAttempt {
						t.Fatal("missing outgoing durable supersession")
					}
				}
				result, err := recoverAt(context.Background(), testInstallation, replacementAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
				if err != nil || fixture.signed.Load() != 2 {
					t.Fatal("replacement did not resume with exactly one new local issuance", err)
				}
				assertPublishedRecovery(t, fixture, result)
				observed, err = inspectTLSAt(testInstallation, fixture.paths, currentOwner(), fixture.now)
				if err != nil || observed.Supersession == nil || observed.Transaction.SupersedesAttemptID != testAttempt ||
					observed.Supersession.PreviousTransaction.CertificateSHA256 != fingerprint(expired.Raw) || observed.PendingSupersession != nil {
					t.Fatal("replacement lost its durable prior-candidate link", err)
				}
				data, err := os.ReadFile(filepath.Join(fixture.paths.tls, supersededName(testAttempt)))
				if err != nil || bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte(testSecret)) {
					t.Fatal("supersession leaked private material")
				}
				requests := fixture.requests.Load()
				current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
				if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != requests {
					t.Fatal("superseded attempt reused")
				}
				after, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
				if !bytes.Equal(current, after) {
					t.Fatal("historical attempt replaced current leaf")
				}
				if _, err := os.Lstat(filepath.Join(fixture.paths.tls, ".recovery-"+testAttempt+".pem")); !os.IsNotExist(err) {
					t.Fatal("supersession retained an old private stage")
				}
			})
		}
	}
}

func TestSupersessionRefusesChangedLinkAndUnrelatedStage(t *testing.T) {
	for _, failure := range []string{"replacement", "journal-hash", "previous", "recorded-before-expiry", "unknown", "stage"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			interruptRecovery(t, fixture, "stage-durable")
			expireRecoveryCandidate(t, fixture)
			fixture.paths.checkpoint = func(point string) error {
				if point == "supersession-durable" {
					return errRecovery
				}
				return nil
			}
			_, _ = recoverAt(context.Background(), testInstallation, replacementAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			fixture.paths.checkpoint = nil
			path := filepath.Join(fixture.paths.tls, supersededName(testAttempt))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if json.Unmarshal(data, &record) != nil {
				t.Fatal("invalid fixture record")
			}
			switch failure {
			case "replacement":
				record["replacement_attempt_id"] = testRole
			case "journal-hash":
				record["previous_journal_sha256"] = fixture.identity.CASHA256
			case "previous":
				record["previous_transaction"].(map[string]any)["attempt_id"] = testRole
			case "recorded-before-expiry":
				record["recorded_at"] = fixture.now.Add(-time.Hour).Format(time.RFC3339)
			case "unknown":
				record["unknown"] = true
			case "stage":
				if os.WriteFile(filepath.Join(fixture.paths.tls, ".recovery-"+testAttempt+".pem"), []byte("unrelated private stage"), 0600) != nil {
					t.Fatal("cannot replace stage fixture")
				}
			}
			data, _ = json.Marshal(record)
			if os.WriteFile(path, data, 0600) != nil {
				t.Fatal("cannot change supersession fixture")
			}
			requests := fixture.requests.Load()
			if _, err := recoverAt(context.Background(), testInstallation, replacementAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != requests {
				t.Fatal("changed supersession reached local signing")
			}
			current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
			if !bytes.Equal(current, fixture.old) {
				t.Fatal("changed supersession altered active certificate")
			}
		})
	}
}
