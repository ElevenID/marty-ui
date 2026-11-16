//go:build linux

package openbaocontrol

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"syscall"
	"time"
)

const (
	recoveryLockName    = ".recovery.lock"
	recoveryJournalName = ".recovery-transaction.json"
	recoveryJournalMax  = 16384
	recoveryJournalV1   = "elevenid.openbao-tcp-recovery-transaction/v1"
)

// The journal contains public data only. A durable candidate is the boundary
// after which this attempt never signs again: it can only finish publication
// of that exact certificate, or reobserve the already published certificate.
type recoveryTransaction struct {
	Schema              string `json:"schema"`
	InstallationID      string `json:"installation_id"`
	AttemptID           string `json:"attempt_id"`
	ClusterID           string `json:"cluster_id"`
	IssuerID            string `json:"issuer_id"`
	PreviousSHA256      string `json:"previous_certificate_sha256"`
	CASHA256            string `json:"ca_sha256"`
	SPKISHA256          string `json:"spki_sha256"`
	Phase               string `json:"phase"`
	CertificatePEM      string `json:"certificate_pem"`
	CertificateSHA256   string `json:"certificate_sha256"`
	NotAfter            string `json:"not_after"`
	SupersedesAttemptID string `json:"supersedes_attempt_id,omitempty"`
}

func (transaction recoveryTransaction) receipt() RecoveryReceipt {
	return RecoveryReceipt{
		Schema: "elevenid.openbao-tcp-recovery-result/v1", InstallationID: transaction.InstallationID,
		AttemptID: transaction.AttemptID, ClusterID: transaction.ClusterID, IssuerID: transaction.IssuerID,
		PreviousSHA256: transaction.PreviousSHA256, CertificateSHA256: transaction.CertificateSHA256,
		CASHA256: transaction.CASHA256, SPKISHA256: transaction.SPKISHA256, NotAfter: transaction.NotAfter,
		NodeKeyPreserved: true, CertificatePublished: true, ReloadPerformed: false, NetworkTLSVerified: false,
	}
}

func parseTransaction(data []byte, identity recoveryIdentity, retained retainedTLS, now time.Time) (recoveryTransaction, error) {
	var transaction recoveryTransaction
	var fields map[string]json.RawMessage
	if len(data) > recoveryJournalMax || decodeJSON(data, &transaction, true) != nil ||
		json.Unmarshal(data, &fields) != nil || (len(fields) != 12 && len(fields) != 13) ||
		transaction.Schema != recoveryJournalV1 || transaction.InstallationID != identity.InstallationID ||
		!uuidPattern.MatchString(transaction.AttemptID) || transaction.ClusterID != identity.ClusterID ||
		transaction.IssuerID != identity.IssuerID || transaction.CASHA256 != identity.CASHA256 ||
		transaction.SPKISHA256 != identity.SPKISHA256 || !exactHash(transaction.PreviousSHA256) {
		return recoveryTransaction{}, errRecovery
	}
	if len(fields) == 13 && (!uuidPattern.MatchString(transaction.SupersedesAttemptID) || transaction.SupersedesAttemptID == transaction.AttemptID) {
		return recoveryTransaction{}, errRecovery
	}
	if transaction.Phase == "issuing" {
		if transaction.CertificatePEM != "" || transaction.CertificateSHA256 != "" || transaction.NotAfter != "" {
			return recoveryTransaction{}, errRecovery
		}
		for _, name := range []string{"certificate_pem", "certificate_sha256", "not_after"} {
			if !bytes.Equal(bytes.TrimSpace(fields[name]), []byte(`""`)) {
				return recoveryTransaction{}, errRecovery
			}
		}
		return transaction, nil
	}
	if transaction.Phase != "candidate" && transaction.Phase != "published" {
		return recoveryTransaction{}, errRecovery
	}
	certificate, err := oneCertificate([]byte(transaction.CertificatePEM))
	if err != nil {
		return recoveryTransaction{}, errRecovery
	}
	// Published leaves may have expired before the next renewal. Their former
	// validity is sufficient to bind history; publication separately requires a
	// currently valid candidate, and never silently substitutes another leaf.
	checkAt := now
	if !certificate.NotAfter.After(now) {
		checkAt = certificate.NotAfter.Add(-time.Second)
	}
	if verifyNode(certificate, retained.ca, retained.leaf.RawSubjectPublicKeyInfo, checkAt) != nil ||
		fingerprint(certificate.Raw) != transaction.CertificateSHA256 ||
		transaction.CertificateSHA256 == transaction.PreviousSHA256 ||
		certificate.NotAfter.Sub(certificate.NotBefore) > 31*24*time.Hour ||
		certificate.NotAfter.UTC().Format(time.RFC3339) != transaction.NotAfter {
		return recoveryTransaction{}, errRecovery
	}
	return transaction, nil
}

func checkpoint(paths recoveryPaths, point string) error {
	if paths.checkpoint != nil {
		return paths.checkpoint(point)
	}
	return nil
}

func objectStat(directory *os.File, name string) (syscall.Stat_t, bool, error) {
	const oPath = 0x200000
	var stat syscall.Stat_t
	fd, err := syscall.Openat(int(directory.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return stat, false, nil
	}
	if err != nil {
		return stat, false, errFiles
	}
	defer syscall.Close(fd)
	if syscall.Fstat(fd, &stat) != nil {
		return stat, false, errFiles
	}
	return stat, true, nil
}

func optionalPublic(directory *os.File, name string, expected owner) (*retainedFile, error) {
	before, exists, err := objectStat(directory, name)
	if err != nil || !exists {
		return nil, err
	}
	file, err := readFile(directory, name, expected, []uint32{0600}, recoveryJournalMax, false)
	if err != nil || !sameFile(before, file.stat) {
		return nil, errFiles
	}
	return &file, nil
}

// A Docker client disconnect does not establish that its exec process exited.
// Keep a separate, nonblocking kernel lock for the entire in-container attempt.
// The lock has no contents and stays root-owned; it is never unlinked/replaced.
func acquireRecoveryLock(directory *os.File, root owner) (*os.File, error) {
	return acquireNamedControlLock(directory, root, recoveryLockName)
}

func acquireNamedControlLock(directory *os.File, root owner, name string) (*os.File, error) {
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	fd, err := syscall.Openat(int(directory.Fd()), name, flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
	created := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Openat(int(directory.Fd()), name, flags, 0)
	}
	if err != nil {
		return nil, errFiles
	}
	file := os.NewFile(uintptr(fd), name)
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Mode&07777 != 0600 || stat.Uid != root.uid || stat.Gid != root.gid || stat.Nlink != 1 || stat.Size != 0 ||
		syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, errFiles
	}
	current, exists, err := objectStat(directory, name)
	if err != nil || !exists || !sameFile(stat, current) || (created && (file.Sync() != nil || directory.Sync() != nil)) {
		file.Close()
		return nil, errFiles
	}
	return file, nil
}

func requireRecoveryLock(directory, held *os.File, root owner) error {
	return requireNamedControlLock(directory, held, root, recoveryLockName)
}

func requireNamedControlLock(directory, held *os.File, root owner, name string) error {
	var stat syscall.Stat_t
	current, exists, err := objectStat(directory, name)
	if err != nil || !exists || syscall.Fstat(int(held.Fd()), &stat) != nil || !sameFile(stat, current) ||
		stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size != 0 ||
		stat.Uid != root.uid || stat.Gid != root.gid {
		return errFiles
	}
	return nil
}

// Only a fixed, root-owned transaction temporary may be rewritten after an
// interrupted write. The durable target is compared before atomic replacement.
func atomicPublic(directory *os.File, paths recoveryPaths, expected owner, name string, previous *retainedFile, data []byte, point string) (retainedFile, error) {
	if len(data) == 0 || len(data) > recoveryJournalMax || boundDirectory(directory, paths.tls, expected) != nil {
		return retainedFile{}, errFiles
	}
	temporary := name + ".tmp"
	fd, err := syscall.Openat(int(directory.Fd()), temporary, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return retainedFile{}, errFiles
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Mode&07777 != 0600 || stat.Uid != paths.root.uid || stat.Gid != paths.root.gid || stat.Nlink != 1 ||
		stat.Size < 0 || stat.Size > recoveryJournalMax {
		return retainedFile{}, errFiles
	}
	current, exists, err := objectStat(directory, temporary)
	if err != nil || !exists || !sameFile(stat, current) || file.Truncate(0) != nil {
		return retainedFile{}, errFiles
	}
	if written, err := file.Write(data); err != nil || written != len(data) || file.Sync() != nil ||
		checkpoint(paths, point+"-staged") != nil {
		return retainedFile{}, errFiles
	}
	staged, err := readFile(directory, temporary, paths.root, []uint32{0600}, recoveryJournalMax, false)
	if err != nil || syscall.Fstat(fd, &stat) != nil || !sameFile(stat, staged.stat) || !bytes.Equal(staged.bytes, data) {
		return retainedFile{}, errFiles
	}
	if previous == nil {
		_, exists, err := objectStat(directory, name)
		if err != nil || exists {
			return retainedFile{}, errFiles
		}
	} else if unchangedFile(directory, name, *previous, paths.root, []uint32{0600}, recoveryJournalMax, false) != nil {
		return retainedFile{}, errFiles
	}
	if boundDirectory(directory, paths.tls, expected) != nil ||
		syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name) != nil || directory.Sync() != nil {
		return retainedFile{}, errFiles
	}
	published, err := readFile(directory, name, paths.root, []uint32{0600}, recoveryJournalMax, false)
	if err != nil || !sameInode(stat, published.stat) || !bytes.Equal(published.bytes, data) || checkpoint(paths, point+"-durable") != nil {
		return retainedFile{}, errFiles
	}
	return published, nil
}

func saveTransaction(directory *os.File, paths recoveryPaths, expected owner, previous *retainedFile, transaction recoveryTransaction) (retainedFile, error) {
	data, err := json.Marshal(transaction)
	if err != nil {
		return retainedFile{}, errFiles
	}
	return atomicPublic(directory, paths, expected, recoveryJournalName, previous, data, transaction.Phase)
}

func completedName(attempt string) string { return ".recovery-result-" + attempt + ".json" }

func requireCompleted(file retainedFile, expected RecoveryReceipt) error {
	var actual RecoveryReceipt
	if decodeJSON(file.bytes, &actual, true) != nil || actual != expected ||
		!requiredFalse(file.bytes, "reload_performed") || !requiredFalse(file.bytes, "network_tls_verified") {
		return errRecovery
	}
	return nil
}

func saveCompleted(directory *os.File, paths recoveryPaths, expected owner, receipt RecoveryReceipt) error {
	name := completedName(receipt.AttemptID)
	previous, err := optionalPublic(directory, name, paths.root)
	if err != nil {
		return err
	}
	if previous != nil {
		return requireCompleted(*previous, receipt)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return errFiles
	}
	_, err = atomicPublic(directory, paths, expected, name, nil, data, "result")
	return err
}

func candidateFor(transaction recoveryTransaction, certificate *x509.Certificate) recoveryTransaction {
	transaction.Phase = "candidate"
	transaction.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	transaction.CertificateSHA256 = fingerprint(certificate.Raw)
	transaction.NotAfter = certificate.NotAfter.UTC().Format(time.RFC3339)
	return transaction
}

func beginTransaction(directory *os.File, paths recoveryPaths, expected owner, identity recoveryIdentity, retained retainedTLS, attempt string, now time.Time) (recoveryTransaction, retainedFile, error) {
	var transaction recoveryTransaction
	previous, err := optionalPublic(directory, recoveryJournalName, paths.root)
	if err != nil {
		return transaction, retainedFile{}, err
	}
	completed, err := optionalPublic(directory, completedName(attempt), paths.root)
	if err != nil {
		return transaction, retainedFile{}, err
	}
	if _, retired, err := objectStat(directory, supersededName(attempt)); err != nil || retired {
		return transaction, retainedFile{}, errRecovery
	}
	currentSHA := fingerprint(retained.leaf.Raw)
	supersedes := ""
	if previous != nil {
		transaction, err = parseTransaction(previous.bytes, identity, retained, now)
		if err != nil {
			return transaction, retainedFile{}, err
		}
		if transaction.SupersedesAttemptID != "" {
			if _, _, err := loadSupersession(directory, paths.root, identity, retained, transaction.SupersedesAttemptID, transaction.AttemptID, transaction.PreviousSHA256, now); err != nil {
				return transaction, retainedFile{}, err
			}
		}
		if transaction.AttemptID == attempt {
			if transaction.Phase == "issuing" && currentSHA != transaction.PreviousSHA256 ||
				transaction.Phase == "candidate" && currentSHA != transaction.PreviousSHA256 && currentSHA != transaction.CertificateSHA256 ||
				transaction.Phase == "published" && currentSHA != transaction.CertificateSHA256 ||
				completed != nil && (transaction.Phase != "published" || requireCompleted(*completed, transaction.receipt()) != nil) {
				return transaction, retainedFile{}, errRecovery
			}
			if transaction.Phase != "candidate" {
				if _, exists, err := objectStat(directory, ".recovery-"+attempt+".pem"); err != nil || exists {
					return transaction, retainedFile{}, errRecovery
				}
			}
			return transaction, *previous, nil
		}
		// A new attempt may follow only a fully published, durably recorded
		// operation whose leaf is still active. Historical attempt IDs can never
		// be reused to issue again or overwrite a newer certificate.
		if completed != nil {
			return transaction, retainedFile{}, errRecovery
		}
		if transaction.Phase == "candidate" {
			// A long outage may outlive a durable candidate. The host records
			// a linked replacement attempt; the local helper durably retires
			// the expired candidate before any new same-key signing operation.
			if recordExpiredSupersession(directory, paths, expected, identity, retained, transaction, *previous, attempt, now) != nil {
				return transaction, retainedFile{}, errRecovery
			}
			supersedes = transaction.AttemptID
		} else if transaction.Phase == "published" && currentSHA == transaction.CertificateSHA256 {
			priorResult, err := optionalPublic(directory, completedName(transaction.AttemptID), paths.root)
			if err != nil || priorResult == nil || requireCompleted(*priorResult, transaction.receipt()) != nil {
				return transaction, retainedFile{}, errRecovery
			}
		} else {
			return transaction, retainedFile{}, errRecovery
		}
	} else if completed != nil {
		return transaction, retainedFile{}, errRecovery
	}
	if _, exists, err := objectStat(directory, ".recovery-"+attempt+".pem"); err != nil || exists {
		return transaction, retainedFile{}, errRecovery
	}
	transaction = recoveryTransaction{
		Schema: recoveryJournalV1, InstallationID: identity.InstallationID, AttemptID: attempt,
		ClusterID: identity.ClusterID, IssuerID: identity.IssuerID, PreviousSHA256: currentSHA,
		CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256, Phase: "issuing",
		SupersedesAttemptID: supersedes,
	}
	journal, err := saveTransaction(directory, paths, expected, previous, transaction)
	return transaction, journal, err
}

// A stage may be empty or contain a prefix after a short write or crash. Only
// the same attempt's durable candidate can authorize finishing it. A root-owned
// stage is the known interval before the final OpenBao ownership handoff.
func publishCandidate(directory *os.File, paths recoveryPaths, expected owner, attempt string, previous retainedFile, combined []byte) error {
	if boundDirectory(directory, paths.tls, expected) != nil ||
		unchangedFile(directory, "server.pem", previous, expected, []uint32{0600}, 128*1024, false) != nil {
		return errFiles
	}
	stage := ".recovery-" + attempt + ".pem"
	fd, err := syscall.Openat(int(directory.Fd()), stage, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errFiles
	}
	file := os.NewFile(uintptr(fd), stage)
	defer file.Close()
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&07777 != 0600 ||
		stat.Nlink != 1 || stat.Size < 0 || stat.Size > int64(len(combined)) ||
		!((stat.Uid == expected.uid && stat.Gid == expected.gid) || (stat.Uid == paths.root.uid && stat.Gid == paths.root.gid)) {
		return errFiles
	}
	prefix := make([]byte, stat.Size)
	if len(prefix) != 0 {
		if n, err := file.ReadAt(prefix, 0); err != nil || n != len(prefix) {
			return errFiles
		}
	}
	current, exists, err := objectStat(directory, stage)
	if err != nil || !exists || !sameFile(stat, current) || !bytes.HasPrefix(combined, prefix) {
		return errFiles
	}
	if n, err := file.WriteAt(combined, 0); err != nil || n != len(combined) ||
		syscall.Fchown(fd, int(expected.uid), int(expected.gid)) != nil || file.Sync() != nil || directory.Sync() != nil ||
		checkpoint(paths, "stage-durable") != nil {
		return errFiles
	}
	staged, err := readFile(directory, stage, expected, []uint32{0600}, 128*1024, false)
	if err != nil || syscall.Fstat(fd, &stat) != nil || !sameFile(stat, staged.stat) || !bytes.Equal(staged.bytes, combined) ||
		unchangedFile(directory, "server.pem", previous, expected, []uint32{0600}, 128*1024, false) != nil ||
		boundDirectory(directory, paths.tls, expected) != nil {
		return errFiles
	}
	if syscall.Renameat(int(directory.Fd()), stage, int(directory.Fd()), "server.pem") != nil || directory.Sync() != nil ||
		checkpoint(paths, "certificate-published") != nil {
		return errFiles
	}
	published, err := readFile(directory, "server.pem", expected, []uint32{0600}, 128*1024, false)
	if err != nil || !sameInode(stat, published.stat) || !bytes.Equal(published.bytes, combined) {
		return errFiles
	}
	return nil
}
