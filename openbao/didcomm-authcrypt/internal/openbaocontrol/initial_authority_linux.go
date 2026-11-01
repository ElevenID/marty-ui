//go:build linux

package openbaocontrol

import (
	"encoding/json"
	"os"
)

const initialAuthorityName = "static-init-authority.json"

// This record is private, root0400 inside mapped OpenBao state. Its digests,
// file bindings and bytes must never enter host receipts, stdout or support
// exports. It proves the exact original initialization authority, rather than
// adopting whichever root-policy token happens to occupy root.token later.
type authorityFileBinding struct {
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	UID             uint32 `json:"uid"`
	GID             uint32 `json:"gid"`
	Mode            uint32 `json:"mode"`
	Links           uint64 `json:"links"`
	Size            int64  `json:"size"`
	ModifiedSeconds int64  `json:"modified_seconds"`
	ModifiedNanos   int64  `json:"modified_nanos"`
	ChangedSeconds  int64  `json:"changed_seconds"`
	ChangedNanos    int64  `json:"changed_nanos"`
	SHA256          string `json:"sha256"`
}

func bindAuthorityFile(file retainedFile) authorityFileBinding {
	stat := file.stat
	return authorityFileBinding{Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 07777, Links: uint64(stat.Nlink), Size: stat.Size,
		ModifiedSeconds: stat.Mtim.Sec, ModifiedNanos: stat.Mtim.Nsec, ChangedSeconds: stat.Ctim.Sec, ChangedNanos: stat.Ctim.Nsec, SHA256: fingerprint(file.bytes)}
}

type initialAuthority struct {
	Schema         string               `json:"schema"`
	InstallationID string               `json:"installation_id"`
	AttemptID      string               `json:"attempt_id"`
	ClusterID      string               `json:"cluster_id"`
	Root           authorityFileBinding `json:"root"`
	Recovery       authorityFileBinding `json:"recovery"`
}

func writeInitialAuthority(directory *os.File, root owner, installation, attempt, cluster string, rootFile, recoveryFile retainedFile) (retainedFile, error) {
	record := initialAuthority{Schema: "elevenid.openbao-static-initial-authority-private/v1", InstallationID: installation, AttemptID: attempt, ClusterID: cluster, Root: bindAuthorityFile(rootFile), Recovery: bindAuthorityFile(recoveryFile)}
	data, err := json.Marshal(record)
	if err != nil {
		return retainedFile{}, errStaticInit
	}
	return writeRootExclusive(directory, initialAuthorityName, data, root, 0400)
}
func readInitialAuthority(directory *os.File, root owner, installation string) (initialAuthority, retainedFile, error) {
	var record initialAuthority
	file, err := readFile(directory, initialAuthorityName, root, []uint32{0400}, 8192, false)
	if err != nil || decodeJSON(file.bytes, &record, true) != nil {
		return record, retainedFile{}, errFiles
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(file.bytes, &fields) != nil || len(fields) != 6 || record.Schema != "elevenid.openbao-static-initial-authority-private/v1" || record.InstallationID != installation ||
		!uuidPattern.MatchString(installation) || !uuidPattern.MatchString(record.AttemptID) || !uuidPattern.MatchString(record.ClusterID) {
		return record, retainedFile{}, errFiles
	}
	for name, binding := range map[string]authorityFileBinding{"root": record.Root, "recovery": record.Recovery} {
		var nested map[string]json.RawMessage
		if json.Unmarshal(fields[name], &nested) != nil || len(nested) != 12 || binding.Mode != 0400 || binding.Links != 1 || binding.Size < 1 || binding.Size > 4096 ||
			binding.UID != root.uid || binding.GID != root.gid || !exactHash(binding.SHA256) || binding.Inode == 0 || binding.ModifiedNanos < 0 || binding.ModifiedNanos >= 1e9 || binding.ChangedNanos < 0 || binding.ChangedNanos >= 1e9 {
			return record, retainedFile{}, errFiles
		}
	}
	return record, file, nil
}
