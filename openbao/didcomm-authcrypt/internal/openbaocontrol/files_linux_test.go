//go:build linux

package openbaocontrol

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateIdentityFilesRejectsLinksSpecialFilesAndWritableMounts(t *testing.T) {
	for _, failure := range []string{"hardlink", "symlink", "fifo", "mode", "oversized", "writable-mount"} {
		t.Run(failure, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(path, "recovery.json")
			if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "hardlink":
				if err := os.Link(target, filepath.Join(path, "other")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				_ = os.Rename(target, filepath.Join(path, "other"))
				_ = os.Symlink("other", target)
			case "fifo":
				_ = os.Remove(target)
				if err := syscall.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				_ = os.Chmod(target, 0640)
			case "oversized":
				_ = os.WriteFile(target, make([]byte, 8193), 0600)
			}
			directory, err := openDirectory(path, currentOwner(), 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if _, err := readFile(directory, "recovery.json", currentOwner(), []uint32{0600}, 8192, failure == "writable-mount"); err == nil {
				t.Fatal("unsafe private input was accepted")
			}
		})
	}
}
