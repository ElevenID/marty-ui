//go:build linux

package openbaocontrol

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func initializationFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	paths := []string{filepath.Join(root, "state"), filepath.Join(root, "socket"), filepath.Join(root, "identity")}
	for _, path := range paths {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1], paths[2]
}

func TestFreshControlMountOwnershipTransitionCannotReplay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("image owner transition needs root")
	}
	state, socket, identity := initializationFixture(t)
	if err := initializeDirectoriesAt(state, socket, identity, owner{65534, 65534}, currentOwner()); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		path     string
		expected owner
	}{
		{state, currentOwner()}, {identity, currentOwner()}, {socket, owner{65534, 65534}},
	} {
		info, err := os.Stat(value.path)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != value.expected.uid || stat.Gid != value.expected.gid || info.Mode().Perm() != 0700 {
			t.Fatal("control handoff changed the wrong owner or permissions")
		}
	}
	if err := initializeDirectoriesAt(state, socket, identity, owner{65534, 65534}, currentOwner()); err == nil {
		t.Fatal("an ownership transition was adopted or replayed")
	}
}

func TestControlHandoffRejectsNonfreshInputsBeforeChangingOwnership(t *testing.T) {
	for _, fault := range []string{"identity-content", "socket-content", "existing-state", "existing-tls", "symlink-tls", "mode", "aliased-directories", "symlink-directory"} {
		t.Run(fault, func(t *testing.T) {
			state, socket, identity := initializationFixture(t)
			switch fault {
			case "identity-content":
				_ = os.WriteFile(filepath.Join(identity, "pending"), []byte("uncertain"), 0600)
			case "socket-content":
				_ = os.WriteFile(filepath.Join(socket, "api.sock"), []byte("existing"), 0600)
			case "existing-state":
				_ = os.WriteFile(filepath.Join(state, "root.token"), []byte("preexisting"), 0400)
			case "existing-tls":
				_ = os.Mkdir(filepath.Join(state, "tls"), 0700)
			case "symlink-tls":
				_ = os.Symlink("/missing", filepath.Join(state, "tls"))
			case "mode":
				_ = os.Chmod(identity, 0755)
			case "aliased-directories":
				identity = socket
			case "symlink-directory":
				_ = os.Remove(identity)
				_ = os.Symlink(socket, identity)
			}
			if err := initializeDirectoriesAt(state, socket, identity, owner{65534, 65534}, currentOwner()); err == nil {
				t.Fatal("nonfresh handoff was accepted")
			}
			info, err := os.Stat(socket)
			if err != nil || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				t.Fatal("refusal still changed socket ownership")
			}
		})
	}
}
