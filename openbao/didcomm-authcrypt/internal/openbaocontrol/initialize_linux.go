//go:build linux

package openbaocontrol

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// InitializeDirectories is the fresh TLS setup job's optional local-control
// handoff. It can only transition the exact pre-created empty socket bind from
// container root to OpenBao. It does not create/adopt paths or repair ownership.
func InitializeDirectories() error {
	if os.Geteuid() != 0 {
		return errFiles
	}
	expected, err := imageOwner()
	if err != nil {
		return err
	}
	return initializeDirectoriesAt("/bao/data", filepath.Dir(SocketPath), identityDirectory, expected, owner{0, 0})
}

func emptyDirectory(directory *os.File) error {
	fd, err := syscall.Openat(int(directory.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errFiles
	}
	file := os.NewFile(uintptr(fd), directory.Name())
	defer file.Close()
	entries, err := file.Readdirnames(1)
	if len(entries) != 0 || !errors.Is(err, io.EOF) {
		return errFiles
	}
	return nil
}

func initializeDirectoriesAt(statePath, socketPath, identityPath string, expected, root owner) error {
	if expected == root {
		return errFiles
	}
	state, err := openDirectory(statePath, root, 0700)
	if err != nil {
		return errFiles
	}
	defer state.Close()
	socket, err := openDirectory(socketPath, root, 0700)
	if err != nil {
		return errFiles
	}
	defer socket.Close()
	identity, err := openDirectory(identityPath, root, 0700)
	if err != nil {
		return errFiles
	}
	defer identity.Close()
	var stateInfo, socketInfo, identityInfo syscall.Stat_t
	if syscall.Fstat(int(state.Fd()), &stateInfo) != nil || syscall.Fstat(int(socket.Fd()), &socketInfo) != nil ||
		syscall.Fstat(int(identity.Fd()), &identityInfo) != nil ||
		(stateInfo.Dev == socketInfo.Dev && stateInfo.Ino == socketInfo.Ino) ||
		(stateInfo.Dev == identityInfo.Dev && stateInfo.Ino == identityInfo.Ino) ||
		(socketInfo.Dev == identityInfo.Dev && socketInfo.Ino == identityInfo.Ino) ||
		emptyDirectory(state) != nil || emptyDirectory(socket) != nil || emptyDirectory(identity) != nil {
		return errFiles
	}
	// This opt-in is fresh installation only, even though the legacy TLS
	// initializer separately supports explicit rotation for other consumers.
	const oPath = 0x200000
	fd, err := syscall.Openat(int(state.Fd()), "tls", oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		syscall.Close(fd)
		return errFiles
	}
	if !errors.Is(err, syscall.ENOENT) {
		return errFiles
	}
	for _, directory := range []*os.File{state, socket, identity} {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Flags&1 != 0 {
			return errFiles
		}
	}
	if boundDirectory(state, statePath, root) != nil || boundDirectory(socket, socketPath, root) != nil ||
		boundDirectory(identity, identityPath, root) != nil || emptyDirectory(socket) != nil || emptyDirectory(identity) != nil {
		return errFiles
	}
	// The host's pending setup receipt must already be durable. A failure after
	// this transition is uncertain setup, not permission to call this again.
	if syscall.Fchown(int(socket.Fd()), int(expected.uid), int(expected.gid)) != nil || socket.Sync() != nil ||
		boundDirectory(socket, socketPath, expected) != nil || boundDirectory(identity, identityPath, root) != nil {
		return errFiles
	}
	return nil
}
