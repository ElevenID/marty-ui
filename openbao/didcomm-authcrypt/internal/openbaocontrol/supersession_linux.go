//go:build linux

package openbaocontrol

import (
	"bytes"
	"encoding/json"
	"os"
	"syscall"
	"time"
)

// Expiry cannot grant a new trust anchor or node key. It can retire only one
// saved, still-unfinished local candidate, with a durable link to the host's
// next attempt before any new issuance. This has no public ACME semantics.
type recoverySupersession struct {
	Schema                       string              `json:"schema"`
	PreviousTransaction          recoveryTransaction `json:"previous_transaction"`
	PreviousJournalSHA256        string              `json:"previous_journal_sha256"`
	ReplacementAttemptID         string              `json:"replacement_attempt_id"`
	ObservedActiveSHA256         string              `json:"observed_active_certificate_sha256"`
	RecordedAt                   string              `json:"recorded_at"`
	Reason                       string              `json:"reason"`
	PreviousCertificatePublished bool                `json:"previous_certificate_published"`
}

func supersededName(attempt string) string { return ".recovery-superseded-" + attempt + ".json" }

func loadSupersession(directory *os.File, root owner, identity recoveryIdentity, retained retainedTLS, previousAttempt, replacementAttempt, activeSHA string, now time.Time) (recoverySupersession, retainedFile, error) {
	var record recoverySupersession
	file, err := optionalPublic(directory, supersededName(previousAttempt), root)
	if err != nil || file == nil || decodeJSON(file.bytes, &record, true) != nil {
		return record, retainedFile{}, errRecovery
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(file.bytes, &fields) != nil || len(fields) != 8 ||
		record.Schema != "elevenid.openbao-tcp-recovery-supersession/v1" || record.Reason != "candidate_expired" ||
		record.PreviousTransaction.AttemptID != previousAttempt || record.ReplacementAttemptID != replacementAttempt ||
		previousAttempt == replacementAttempt || !uuidPattern.MatchString(previousAttempt) || !uuidPattern.MatchString(replacementAttempt) ||
		!exactHash(record.PreviousJournalSHA256) || record.ObservedActiveSHA256 != activeSHA {
		return record, retainedFile{}, errRecovery
	}
	previousJSON, err := json.Marshal(record.PreviousTransaction)
	previous, parseErr := parseTransaction(previousJSON, identity, retained, now)
	if err != nil || parseErr != nil || fingerprint(previousJSON) != record.PreviousJournalSHA256 || previous.Phase != "candidate" ||
		(activeSHA != previous.PreviousSHA256 && activeSHA != previous.CertificateSHA256) ||
		record.PreviousCertificatePublished != (activeSHA == previous.CertificateSHA256) ||
		(!record.PreviousCertificatePublished && !requiredFalse(file.bytes, "previous_certificate_published")) {
		return record, retainedFile{}, errRecovery
	}
	recordedAt, err := time.Parse(time.RFC3339, record.RecordedAt)
	expires, expiresErr := time.Parse(time.RFC3339, previous.NotAfter)
	if err != nil || expiresErr != nil || recordedAt.UTC().Format(time.RFC3339) != record.RecordedAt ||
		recordedAt.Before(expires) || recordedAt.After(now) || expires.After(now) {
		return record, retainedFile{}, errRecovery
	}
	return record, *file, nil
}

func recordExpiredSupersession(directory *os.File, paths recoveryPaths, expected owner, identity recoveryIdentity, retained retainedTLS, previous recoveryTransaction, journal retainedFile, replacementAttempt string, now time.Time) error {
	expires, err := time.Parse(time.RFC3339, previous.NotAfter)
	activeSHA := fingerprint(retained.leaf.Raw)
	if err != nil || previous.Phase != "candidate" || expires.After(now) ||
		(activeSHA != previous.PreviousSHA256 && activeSHA != previous.CertificateSHA256) ||
		!uuidPattern.MatchString(replacementAttempt) || previous.AttemptID == replacementAttempt {
		return errRecovery
	}
	existing, err := optionalPublic(directory, supersededName(previous.AttemptID), paths.root)
	if err != nil {
		return errRecovery
	}
	if existing == nil {
		record := recoverySupersession{
			Schema: "elevenid.openbao-tcp-recovery-supersession/v1", PreviousTransaction: previous,
			PreviousJournalSHA256: fingerprint(journal.bytes), ReplacementAttemptID: replacementAttempt,
			ObservedActiveSHA256: activeSHA, RecordedAt: now.UTC().Format(time.RFC3339), Reason: "candidate_expired",
			PreviousCertificatePublished: activeSHA == previous.CertificateSHA256,
		}
		data, err := json.Marshal(record)
		if err != nil {
			return errRecovery
		}
		if _, err := atomicPublic(directory, paths, expected, supersededName(previous.AttemptID), nil, data, "supersession"); err != nil {
			return err
		}
	}
	record, _, err := loadSupersession(directory, paths.root, identity, retained, previous.AttemptID, replacementAttempt, activeSHA, now)
	if err != nil || record.PreviousTransaction != previous || record.PreviousJournalSHA256 != fingerprint(journal.bytes) {
		return errRecovery
	}
	if record.PreviousCertificatePublished {
		current, err := readFile(directory, "server.pem", expected, []uint32{0600}, 128*1024, false)
		combined := append([]byte(previous.CertificatePEM), retained.keyPEM...)
		if err != nil || !bytes.Equal(current.bytes, combined) || saveCompleted(directory, paths, expected, previous.receipt()) != nil {
			return errRecovery
		}
	}
	if retireCandidateStage(directory, paths, expected, previous, retained) != nil {
		return errRecovery
	}
	return nil
}

// A superseded candidate can leave its interrupted private publication stage.
// Remove only that attempt's exact candidate/key prefix, after the public
// supersession is durable. Unrelated bytes, links or ownership fail closed.
func retireCandidateStage(directory *os.File, paths recoveryPaths, expected owner, previous recoveryTransaction, retained retainedTLS) error {
	name := ".recovery-" + previous.AttemptID + ".pem"
	before, exists, err := objectStat(directory, name)
	if err != nil || !exists {
		return err
	}
	combined := append([]byte(previous.CertificatePEM), retained.keyPEM...)
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errFiles
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || !sameFile(before, stat) || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size < 0 || stat.Size > int64(len(combined)) ||
		!((stat.Uid == expected.uid && stat.Gid == expected.gid) || (stat.Uid == paths.root.uid && stat.Gid == paths.root.gid)) {
		return errFiles
	}
	prefix := make([]byte, stat.Size)
	if len(prefix) != 0 {
		if n, err := file.ReadAt(prefix, 0); err != nil || n != len(prefix) {
			return errFiles
		}
	}
	current, exists, err := objectStat(directory, name)
	if err != nil || !exists || !sameFile(stat, current) || !bytes.HasPrefix(combined, prefix) ||
		boundDirectory(directory, paths.tls, expected) != nil || syscall.Unlinkat(int(directory.Fd()), name) != nil || directory.Sync() != nil {
		return errFiles
	}
	return checkpoint(paths, "supersession-stage-retired")
}
