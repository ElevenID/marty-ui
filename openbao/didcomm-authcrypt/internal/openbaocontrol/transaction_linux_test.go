//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func interruptRecovery(t *testing.T, fixture *recoveryFixture, point string) {
	t.Helper()
	reached := false
	fixture.paths.checkpoint = func(observed string) error {
		if observed == point {
			reached = true
			return errRecovery
		}
		return nil
	}
	if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || !reached {
		t.Fatalf("did not interrupt recovery at %s", point)
	}
	fixture.paths.checkpoint = nil
}

func assertPublishedRecovery(t *testing.T, fixture *recoveryFixture, receipt RecoveryReceipt) {
	t.Helper()
	current, err := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := pem.Decode(current)
	_, originalKey := pem.Decode(fixture.old)
	if certificate == nil || fingerprint(certificate.Bytes) != receipt.CertificateSHA256 || !bytes.Equal(key, originalKey) {
		t.Fatal("resumed publication changed the candidate or retained key")
	}
	data, err := os.ReadFile(filepath.Join(fixture.paths.tls, completedName(receipt.AttemptID)))
	if err != nil || requireCompleted(retainedFile{bytes: data}, receipt) != nil {
		t.Fatal("completed receipt was not durably retained")
	}
	for _, name := range []string{recoveryJournalName, completedName(receipt.AttemptID)} {
		public, err := os.ReadFile(filepath.Join(fixture.paths.tls, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"PRIVATE KEY", testRole, testSecret, testToken} {
			if bytes.Contains(public, []byte(private)) {
				t.Fatal("private material appeared in public recovery state")
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(fixture.paths.tls, ".recovery-"+receipt.AttemptID+".pem")); !os.IsNotExist(err) {
		t.Fatal("successful recovery left a private stage")
	}
}

func TestRecoveryResumesEveryPublicationBoundary(t *testing.T) {
	for _, point := range []string{
		"issuing-staged", "issuing-durable", "signing-response", "candidate-staged", "candidate-durable",
		"stage-durable", "certificate-published", "published-staged", "published-durable", "result-staged", "result-durable",
	} {
		t.Run(point, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			interruptRecovery(t, fixture, point)
			requests := fixture.requests.Load()
			receipt, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			expectedSigns := int32(1)
			if point == "signing-response" || point == "candidate-staged" {
				expectedSigns = 2
			}
			if fixture.signed.Load() != expectedSigns {
				t.Fatal("resumption issued an unexpected additional certificate")
			}
			if point != "issuing-staged" && point != "issuing-durable" && point != "signing-response" && point != "candidate-staged" && fixture.requests.Load() != requests {
				t.Fatal("durable candidate resumption contacted the control API")
			}
			assertPublishedRecovery(t, fixture, receipt)
			requests = fixture.requests.Load()
			before, _ := os.Stat(filepath.Join(fixture.paths.tls, "server.pem"))
			repeated, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			after, _ := os.Stat(filepath.Join(fixture.paths.tls, "server.pem"))
			if err != nil || repeated != receipt || fixture.requests.Load() != requests || !os.SameFile(before, after) {
				t.Fatal("completed same-attempt retry changed the receipt, certificate, or control state")
			}
		})
	}
}

func TestRecoveryFinishesOnlySameCandidatePartialStage(t *testing.T) {
	for _, prefix := range []string{"empty", "public-prefix", "private-prefix", "unrelated"} {
		t.Run(prefix, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			interruptRecovery(t, fixture, "candidate-durable")
			_, key := pem.Decode(fixture.old)
			certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.issued.Raw})
			combined := append(certificate, key...)
			var stage []byte
			switch prefix {
			case "public-prefix":
				stage = combined[:100]
			case "private-prefix":
				stage = combined[:len(certificate)+40]
			case "unrelated":
				stage = []byte("unrelated file must not be overwritten")
			}
			if err := os.WriteFile(filepath.Join(fixture.paths.tls, ".recovery-"+testAttempt+".pem"), stage, 0600); err != nil {
				t.Fatal(err)
			}
			requests := fixture.requests.Load()
			receipt, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			if prefix == "unrelated" {
				if err == nil {
					t.Fatal("unrelated private stage was adopted")
				}
				current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
				if !bytes.Equal(current, fixture.old) {
					t.Fatal("stage refusal changed the active certificate")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertPublishedRecovery(t, fixture, receipt)
			}
			if fixture.requests.Load() != requests {
				t.Fatal("partial-stage resumption issued another certificate")
			}
		})
	}
}

func TestRecoveryLostLocalSigningOrRetirementResponseRemainsResumable(t *testing.T) {
	for _, fault := range []string{"sign-response-lost-once", "revoke-uncertain-once"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newRecoveryFixture(t, fault)
			if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil {
				t.Fatal("uncertain API response was reported as a published result")
			}
			current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
			if !bytes.Equal(current, fixture.old) {
				t.Fatal("an uncertain response published a certificate")
			}
			receipt, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			if err != nil || fixture.signed.Load() != 2 || fixture.revoked.Load() != 2 {
				t.Fatal("same-attempt bounded local issuance did not resume")
			}
			assertPublishedRecovery(t, fixture, receipt)
		})
	}
}

func TestRecoveryRefusesAnotherAttemptUntilPublicationAndRetainsHistory(t *testing.T) {
	const nextAttempt = "77777777-7777-4777-8777-777777777777"
	fixture := newRecoveryFixture(t, "")
	interruptRecovery(t, fixture, "candidate-durable")
	requests := fixture.requests.Load()
	if _, err := recoverAt(context.Background(), testInstallation, nextAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != requests {
		t.Fatal("a different attempt bypassed unfinished publication")
	}
	first, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.old, _ = os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
	fixture.issued = testCertificate(t, testLeaf(fixture.now, 4, fixture.now.Add(30*24*time.Hour)), fixture.ca, &fixture.key.PublicKey, fixture.caKey)
	second, err := recoverAt(context.Background(), testInstallation, nextAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
	if err != nil || second.PreviousSHA256 != first.CertificateSHA256 || fixture.signed.Load() != 2 {
		t.Fatal("a completed recovery did not allow the next owned renewal")
	}
	// Historical receipts remain compact public evidence after the journal
	// advances. Reusing an old attempt can never roll back or issue again.
	data, err := os.ReadFile(filepath.Join(fixture.paths.tls, completedName(testAttempt)))
	if err != nil || requireCompleted(retainedFile{bytes: data}, first) != nil {
		t.Fatal("advancing the journal lost the prior public receipt")
	}
	requests = fixture.requests.Load()
	if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != requests {
		t.Fatal("a historical attempt was reused")
	}
	assertPublishedRecovery(t, fixture, second)
}

func TestRecoveryLocalLockSerializesHelpersSurvivingCallerDisconnect(t *testing.T) {
	fixture := newRecoveryFixture(t, "")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseFirst := func() { once.Do(func() { close(release) }) }
	defer releaseFirst()
	fixture.paths.checkpoint = func(point string) error {
		if point == "signing-response" {
			close(entered)
			<-release
		}
		return nil
	}
	finished := make(chan error, 1)
	go func() {
		_, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first helper did not reach its controlled interruption")
	}
	requests := fixture.requests.Load()
	for _, attempt := range []string{testAttempt, testRole} {
		second := make(chan error, 1)
		go func() {
			_, err := recoverAt(context.Background(), testInstallation, attempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
			second <- err
		}()
		select {
		case err := <-second:
			if err == nil || fixture.requests.Load() != requests {
				t.Fatal("overlapping helper reached the control API")
			}
		case <-time.After(time.Second):
			t.Fatal("local recovery lock blocked instead of refusing promptly")
		}
	}
	releaseFirst()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	fixture.paths.checkpoint = nil
	requests = fixture.requests.Load()
	if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err != nil || fixture.requests.Load() != requests {
		t.Fatal("same-attempt retry failed after the original helper finished")
	}
}

func TestRecoveryRejectsUnsafeLockBeforeControlRequests(t *testing.T) {
	for _, failure := range []string{"symlink", "hardlink", "fifo", "mode", "nonempty"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			path := filepath.Join(fixture.paths.tls, recoveryLockName)
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "symlink":
				_ = os.Rename(path, path+".other")
				_ = os.Symlink(path+".other", path)
			case "hardlink":
				_ = os.Link(path, path+".other")
			case "fifo":
				_ = os.Remove(path)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				_ = os.Chmod(path, 0644)
			case "nonempty":
				_ = os.WriteFile(path, []byte("not a lock"), 0600)
			}
			if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != 0 {
				t.Fatal("unsafe lock was adopted or reached the control API")
			}
		})
	}
}

func TestRecoveryRejectsChangedDurableCandidateWithoutReissuing(t *testing.T) {
	for _, failure := range []string{
		"unknown", "duplicate", "missing", "installation", "cluster", "issuer", "ca", "spki", "previous", "certificate", "not-after", "phase",
		"private-material", "symlink", "hardlink", "mode", "oversized",
	} {
		t.Run(failure, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			interruptRecovery(t, fixture, "candidate-durable")
			path := filepath.Join(fixture.paths.tls, recoveryJournalName)
			data, _ := os.ReadFile(path)
			var value map[string]any
			if json.Unmarshal(data, &value) != nil {
				t.Fatal("invalid journal fixture")
			}
			switch failure {
			case "unknown":
				value["secret_id"] = "not-permitted"
			case "duplicate":
				data = []byte(strings.Replace(string(data), "{", "{\"phase\":\"candidate\",", 1))
			case "missing":
				delete(value, "previous_certificate_sha256")
			case "installation", "cluster", "issuer":
				value[failure+"_id"] = testRole
			case "ca", "spki":
				value[failure+"_sha256"] = strings.Repeat("f", 64)
			case "previous", "certificate":
				field := "certificate_sha256"
				if failure == "previous" {
					field = "previous_certificate_sha256"
				}
				value[field] = strings.Repeat("f", 64)
			case "not-after":
				value["not_after"] = fixture.now.Format(time.RFC3339)
			case "phase":
				value["phase"] = "published"
			case "private-material":
				value["certificate_pem"] = value["certificate_pem"].(string) + "-----BEGIN PRIVATE KEY-----"
			case "symlink":
				_ = os.Rename(path, path+".other")
				_ = os.Symlink(path+".other", path)
			case "hardlink":
				_ = os.Link(path, path+".other")
			case "mode":
				_ = os.Chmod(path, 0644)
			case "oversized":
				data = make([]byte, recoveryJournalMax+1)
			}
			if failure != "symlink" && failure != "hardlink" && failure != "mode" {
				if failure != "duplicate" && failure != "oversized" {
					data, _ = json.Marshal(value)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			requests := fixture.requests.Load()
			if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil || fixture.requests.Load() != requests {
				t.Fatal("changed durable candidate was admitted or reissued")
			}
			current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
			if !bytes.Equal(current, fixture.old) {
				t.Fatal("candidate refusal changed the active certificate")
			}
		})
	}
}
