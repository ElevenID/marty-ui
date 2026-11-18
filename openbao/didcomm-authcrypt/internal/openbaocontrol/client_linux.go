//go:build linux

// Package openbaocontrol provides the installer's fixed local OpenBao control
// channel. It is separate from every application's verified HTTPS transport.
package openbaocontrol

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	SocketPath = "/bao/control/api.sock"
	// Endpoint is only an HTTP routing authority. The transport below cannot
	// resolve or connect to it over a network, and cannot use environment proxies.
	Endpoint = "http://openbao-local.invalid"
)

var errControl = errors.New("OpenBao local control channel refused")

type owner struct{ uid, gid uint32 }

func imageOwner() (owner, error) {
	u, err := user.Lookup("openbao")
	if err != nil {
		return owner{}, errControl
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil || uid == 0 || gid == 0 {
		return owner{}, errControl
	}
	return owner{uint32(uid), uint32(gid)}, nil
}

// NewClient permits only the fixed, private socket owned by the image's
// OpenBao user. A missing or unsafe socket is an error, never a TCP fallback.
func NewClient() (*http.Client, error) {
	expected, err := imageOwner()
	if err != nil {
		return nil, err
	}
	return newClientAt(SocketPath, expected)
}

func socketIdentity(path string, expected owner) (syscall.Stat_t, error) {
	var result syscall.Stat_t
	directory, err := openDirectory(filepath.Dir(path), expected, 0700)
	if err != nil {
		return result, errControl
	}
	defer directory.Close()
	// O_PATH inspects the inode without opening a FIFO, device or socket as a
	// regular file. O_NOFOLLOW keeps a symlink's own type visible for rejection.
	const oPath = 0x200000
	fd, err := syscall.Openat(int(directory.Fd()), filepath.Base(path), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return result, errControl
	}
	defer syscall.Close(fd)
	if syscall.Fstat(fd, &result) != nil || result.Mode&syscall.S_IFMT != syscall.S_IFSOCK ||
		result.Mode&07777 != 0600 || result.Uid != expected.uid || result.Gid != expected.gid || result.Nlink != 1 {
		return syscall.Stat_t{}, errControl
	}
	return result, nil
}

func newClientAt(path string, expected owner) (*http.Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "api.sock" {
		return nil, errControl
	}
	if _, err := socketIdentity(path, expected); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1,
		MaxResponseHeaderBytes: 16 * 1024, ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "openbao-local.invalid:80" {
				return nil, errControl
			}
			before, err := socketIdentity(path, expected)
			if err != nil {
				return nil, err
			}
			connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
			if err != nil {
				return nil, errControl
			}
			good := false
			defer func() {
				if !good {
					connection.Close()
				}
			}()
			unix, ok := connection.(*net.UnixConn)
			if !ok {
				return nil, errControl
			}
			raw, err := unix.SyscallConn()
			if err != nil {
				return nil, errControl
			}
			var peer *syscall.Ucred
			var peerErr error
			// A sibling container's PID need not be visible in this PID
			// namespace. Its mapped UID/GID are the local authentication
			// boundary; this transport never turns peer PIDs into signals.
			if err := raw.Control(func(fd uintptr) {
				peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			}); err != nil || peerErr != nil || peer == nil || peer.Uid != expected.uid || peer.Gid != expected.gid {
				return nil, errControl
			}
			after, err := socketIdentity(path, expected)
			if err != nil || !sameInode(before, after) {
				return nil, errControl
			}
			good = true
			return connection, nil
		},
	}
	return &http.Client{
		Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// closeClient avoids keeping file descriptors beyond one maintenance operation.
func closeClient(client *http.Client) {
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func sameInode(a, b syscall.Stat_t) bool {
	return sameObject(a, b) && a.Nlink == b.Nlink
}

func sameObject(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}
