//go:build linux

package openbaocontrol

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errFiles = errors.New("OpenBao control file custody refused")

// openDirectory rejects links in every component, holds the final inode, and
// refuses ancestors writable by unrelated identities. A root-owned sticky
// temporary parent is useful for focused tests; production paths use /bao.
func openDirectory(path string, expected owner, mode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errFiles
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errFiles
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, errFiles
		}
		fd = next
		var stat syscall.Stat_t
		if syscall.Fstat(fd, &stat) != nil || (stat.Uid != 0 && stat.Uid != expected.uid) ||
			(stat.Mode&0022 != 0 && !(stat.Uid == 0 && stat.Mode&syscall.S_ISVTX != 0)) {
			syscall.Close(fd)
			return nil, errFiles
		}
	}
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Uid != expected.uid || stat.Gid != expected.gid || stat.Mode&07777 != mode {
		syscall.Close(fd)
		return nil, errFiles
	}
	return os.NewFile(uintptr(fd), path), nil
}

type retainedFile struct {
	bytes []byte
	stat  syscall.Stat_t
}

func readFile(directory *os.File, name string, expected owner, modes []uint32, maximum int64, readOnly bool) (retainedFile, error) {
	var result retainedFile
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return result, errFiles
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return result, errFiles
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if syscall.Fstat(fd, &result.stat) != nil || result.stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		result.stat.Uid != expected.uid || result.stat.Gid != expected.gid || result.stat.Nlink != 1 ||
		result.stat.Size <= 0 || result.stat.Size > maximum {
		return retainedFile{}, errFiles
	}
	allowedMode := false
	for _, mode := range modes {
		allowedMode = allowedMode || result.stat.Mode&07777 == mode
	}
	if !allowedMode {
		return retainedFile{}, errFiles
	}
	if readOnly {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(fd, &fs) != nil || fs.Flags&1 == 0 { // Linux ST_RDONLY.
			return retainedFile{}, errFiles
		}
	}
	result.bytes, err = io.ReadAll(io.LimitReader(file, maximum+1))
	var after syscall.Stat_t
	if err != nil || int64(len(result.bytes)) != result.stat.Size || syscall.Fstat(fd, &after) != nil ||
		!sameFile(result.stat, after) {
		return retainedFile{}, errFiles
	}
	return result, nil
}

func sameFile(a, b syscall.Stat_t) bool {
	return sameInode(a, b) && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func unchangedFile(directory *os.File, name string, previous retainedFile, expected owner, modes []uint32, maximum int64, readOnly bool) error {
	current, err := readFile(directory, name, expected, modes, maximum, readOnly)
	if err != nil || !sameFile(previous.stat, current.stat) || !bytes.Equal(previous.bytes, current.bytes) {
		return errFiles
	}
	return nil
}

func boundDirectory(directory *os.File, path string, expected owner) error {
	current, err := openDirectory(path, expected, 0700)
	if err != nil {
		return errFiles
	}
	defer current.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(int(directory.Fd()), &before) != nil || syscall.Fstat(int(current.Fd()), &after) != nil || !sameObject(before, after) {
		return errFiles
	}
	return nil
}

func writeExclusive(directory *os.File, name string, value []byte, mode uint32) error {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." || len(value) == 0 || len(value) > 16384 ||
		(mode != 0400 && mode != 0600) {
		return errFiles
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return errFiles
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var parent, created syscall.Stat_t
	if syscall.Fstat(int(directory.Fd()), &parent) != nil || syscall.Fstat(fd, &created) != nil ||
		created.Uid != parent.Uid || created.Gid != parent.Gid || created.Mode&07777 != mode || created.Nlink != 1 || directory.Sync() != nil {
		return errFiles
	}
	if _, err := file.Write(value); err != nil || file.Sync() != nil || directory.Sync() != nil {
		return errFiles
	}
	written, err := readFile(directory, name, owner{parent.Uid, parent.Gid}, []uint32{mode}, 16384, false)
	if err != nil || !sameInode(created, written.stat) || !bytes.Equal(written.bytes, value) {
		return errFiles
	}
	return nil
}
