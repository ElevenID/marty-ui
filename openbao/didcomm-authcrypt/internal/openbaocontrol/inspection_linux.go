//go:build linux

package openbaocontrol

import (
	"os"
	"syscall"
	"time"
)

// TLSInspection contains public certificates and binding evidence only. It
// reads the retained node key solely to check its match, never calls an API,
// and does not create a lock, journal, candidate or receipt. It cannot establish
// network readiness: a file may differ from the certificate still in memory.
type TLSInspection struct {
	Schema                    string                `json:"schema"`
	InstallationID            string                `json:"installation_id"`
	ClusterID                 string                `json:"cluster_id"`
	IssuerID                  string                `json:"issuer_id"`
	CASHA256                  string                `json:"ca_sha256"`
	SPKISHA256                string                `json:"spki_sha256"`
	CertificatePEM            string                `json:"certificate_pem"`
	CertificateSHA256         string                `json:"certificate_sha256"`
	NotBefore                 string                `json:"not_before"`
	NotAfter                  string                `json:"not_after"`
	CANotAfter                string                `json:"ca_not_after"`
	NodeKeyMatches            bool                  `json:"node_key_matches"`
	RenewalIssuerUsable       bool                  `json:"renewal_issuer_usable"`
	Transaction               *recoveryTransaction  `json:"transaction,omitempty"`
	TransactionSHA256         string                `json:"transaction_sha256,omitempty"`
	CompletedReceipt          *RecoveryReceipt      `json:"completed_receipt,omitempty"`
	CompletedReceiptSHA256    string                `json:"completed_receipt_sha256,omitempty"`
	Supersession              *recoverySupersession `json:"supersession,omitempty"`
	SupersessionSHA256        string                `json:"supersession_sha256,omitempty"`
	PendingSupersession       *recoverySupersession `json:"pending_supersession,omitempty"`
	PendingSupersessionSHA256 string                `json:"pending_supersession_sha256,omitempty"`
}

func InspectTLS(installationID string) (TLSInspection, error) {
	if os.Geteuid() != 0 || !uuidPattern.MatchString(installationID) {
		return TLSInspection{}, errRecovery
	}
	expected, err := imageOwner()
	if err != nil {
		return TLSInspection{}, errRecovery
	}
	return inspectTLSAt(installationID, recoveryPaths{
		identity: identityDirectory, tls: tlsDirectory, root: owner{0, 0}, readOnly: true,
	}, expected, time.Now())
}

// Shared nonblocking locking refuses a surviving writer. The very first
// inspection may observe an absent lock, but must recheck that absence before
// returning. It never silently creates local recovery state during a check.
func inspectRecoveryLock(directory *os.File, root owner) (*os.File, error) {
	before, exists, err := objectStat(directory, recoveryLockName)
	if err != nil || !exists {
		return nil, err
	}
	fd, err := syscall.Openat(int(directory.Fd()), recoveryLockName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errFiles
	}
	file := os.NewFile(uintptr(fd), recoveryLockName)
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || !sameFile(before, stat) ||
		stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size != 0 ||
		stat.Uid != root.uid || stat.Gid != root.gid || syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB) != nil ||
		requireRecoveryLock(directory, file, root) != nil {
		file.Close()
		return nil, errFiles
	}
	return file, nil
}

func inspectTLSAt(installationID string, paths recoveryPaths, expected owner, now time.Time) (TLSInspection, error) {
	var result TLSInspection
	identityDir, err := openDirectory(paths.identity, paths.root, 0700)
	if err != nil {
		return result, errRecovery
	}
	defer identityDir.Close()
	identityFile, err := readFile(identityDir, "recovery.json", paths.root, []uint32{0400, 0600}, 8192, paths.readOnly)
	if err != nil {
		return result, errRecovery
	}
	identity, err := parseIdentity(identityFile.bytes, installationID)
	if err != nil {
		return result, errRecovery
	}
	pending, enrollment, err := requireEnrollment(identityDir, paths.root, paths.readOnly, identity)
	if err != nil {
		return result, errRecovery
	}
	directory, err := openDirectory(paths.tls, expected, 0700)
	if err != nil {
		return result, errRecovery
	}
	defer directory.Close()
	lock, err := inspectRecoveryLock(directory, paths.root)
	if err != nil {
		return result, errRecovery
	}
	if lock != nil {
		defer lock.Close()
	}
	caFile, err := readFile(directory, "ca.crt", expected, []uint32{0644}, 64*1024, false)
	if err != nil {
		return result, errRecovery
	}
	serverFile, err := readFile(directory, "server.pem", expected, []uint32{0600}, 128*1024, false)
	if err != nil {
		return result, errRecovery
	}
	retained, err := parseTLSAt(caFile.bytes, serverFile.bytes, identity, now, false)
	if err != nil {
		return result, errRecovery
	}
	publicCertificate := len(serverFile.bytes) - len(retained.keyPEM)
	result = TLSInspection{
		Schema: "elevenid.openbao-tcp-inspection/v1", InstallationID: installationID,
		ClusterID: identity.ClusterID, IssuerID: identity.IssuerID, CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256,
		CertificatePEM: string(serverFile.bytes[:publicCertificate]), CertificateSHA256: fingerprint(retained.leaf.Raw),
		NotBefore: retained.leaf.NotBefore.UTC().Format(time.RFC3339), NotAfter: retained.leaf.NotAfter.UTC().Format(time.RFC3339),
		CANotAfter: retained.ca.NotAfter.UTC().Format(time.RFC3339), NodeKeyMatches: true,
		RenewalIssuerUsable: retained.ca.NotAfter.After(now.Add(31 * 24 * time.Hour)),
	}
	retainedPublic := map[string]retainedFile{}
	absent := []string{}
	journal, err := optionalPublic(directory, recoveryJournalName, paths.root)
	if err != nil || (lock == nil && journal != nil) {
		return TLSInspection{}, errRecovery
	}
	if journal == nil {
		absent = append(absent, recoveryJournalName)
	} else {
		retainedPublic[recoveryJournalName] = *journal
		transaction, err := parseTransaction(journal.bytes, identity, retained, now)
		if err != nil ||
			transaction.Phase == "issuing" && transaction.PreviousSHA256 != result.CertificateSHA256 ||
			transaction.Phase == "candidate" && transaction.PreviousSHA256 != result.CertificateSHA256 && transaction.CertificateSHA256 != result.CertificateSHA256 ||
			transaction.Phase == "published" && transaction.CertificateSHA256 != result.CertificateSHA256 {
			return TLSInspection{}, errRecovery
		}
		result.Transaction = &transaction
		result.TransactionSHA256 = fingerprint(journal.bytes)
		completed, err := optionalPublic(directory, completedName(transaction.AttemptID), paths.root)
		if err != nil {
			return TLSInspection{}, errRecovery
		}
		if completed == nil {
			absent = append(absent, completedName(transaction.AttemptID))
		} else {
			if transaction.Phase == "issuing" || transaction.CertificateSHA256 != result.CertificateSHA256 || requireCompleted(*completed, transaction.receipt()) != nil {
				return TLSInspection{}, errRecovery
			}
			retainedPublic[completedName(transaction.AttemptID)] = *completed
			receipt := transaction.receipt()
			result.CompletedReceipt = &receipt
			result.CompletedReceiptSHA256 = fingerprint(completed.bytes)
		}
		if transaction.SupersedesAttemptID != "" {
			supersession, file, err := loadSupersession(directory, paths.root, identity, retained, transaction.SupersedesAttemptID, transaction.AttemptID, transaction.PreviousSHA256, now)
			if err != nil {
				return TLSInspection{}, errRecovery
			}
			retainedPublic[supersededName(transaction.SupersedesAttemptID)] = file
			result.Supersession, result.SupersessionSHA256 = &supersession, fingerprint(file.bytes)
		}
		outgoing, err := optionalPublic(directory, supersededName(transaction.AttemptID), paths.root)
		if err != nil {
			return TLSInspection{}, errRecovery
		}
		if outgoing == nil {
			absent = append(absent, supersededName(transaction.AttemptID))
		} else {
			var candidate recoverySupersession
			if decodeJSON(outgoing.bytes, &candidate, true) != nil {
				return TLSInspection{}, errRecovery
			}
			supersession, file, err := loadSupersession(directory, paths.root, identity, retained, transaction.AttemptID, candidate.ReplacementAttemptID, result.CertificateSHA256, now)
			if err != nil || transaction != supersession.PreviousTransaction || fingerprint(journal.bytes) != supersession.PreviousJournalSHA256 {
				return TLSInspection{}, errRecovery
			}
			retainedPublic[supersededName(transaction.AttemptID)] = file
			result.PendingSupersession, result.PendingSupersessionSHA256 = &supersession, fingerprint(file.bytes)
		}
	}
	if checkpoint(paths, "inspection-observed") != nil ||
		boundDirectory(identityDir, paths.identity, paths.root) != nil || boundDirectory(directory, paths.tls, expected) != nil ||
		unchangedFile(identityDir, "recovery.json", identityFile, paths.root, []uint32{0400, 0600}, 8192, paths.readOnly) != nil ||
		unchangedFile(identityDir, "enrollment-pending.json", pending, paths.root, []uint32{0600}, 8192, paths.readOnly) != nil ||
		unchangedFile(identityDir, "enrollment-result.json", enrollment, paths.root, []uint32{0600}, 16384, paths.readOnly) != nil ||
		unchangedFile(directory, "ca.crt", caFile, expected, []uint32{0644}, 64*1024, false) != nil ||
		unchangedFile(directory, "server.pem", serverFile, expected, []uint32{0600}, 128*1024, false) != nil {
		return TLSInspection{}, errRecovery
	}
	if lock == nil {
		if _, exists, err := objectStat(directory, recoveryLockName); err != nil || exists {
			return TLSInspection{}, errRecovery
		}
	} else if requireRecoveryLock(directory, lock, paths.root) != nil {
		return TLSInspection{}, errRecovery
	}
	for name, file := range retainedPublic {
		if unchangedFile(directory, name, file, paths.root, []uint32{0600}, recoveryJournalMax, false) != nil {
			return TLSInspection{}, errRecovery
		}
	}
	for _, name := range absent {
		if _, exists, err := objectStat(directory, name); err != nil || exists {
			return TLSInspection{}, errRecovery
		}
	}
	return result, nil
}
