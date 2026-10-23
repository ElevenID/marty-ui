// selfhost-tls-init creates the OpenBao node's own TLS identity inside its
// durable KMS state volume. It never writes private material to an app mount.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var names = []string{"ca.crt", "ca.key", "server.pem"}

func main() {
	dir := flag.String("dir", "/bao/data/tls", "KMS-owned TLS directory")
	rotate := flag.Bool("rotate", false, "renew the listener certificate under the existing KMS-owned CA")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(errors.New("unexpected arguments"))
	}
	if err := ensure(*dir, *rotate); err != nil {
		fail(err)
	}
	fmt.Println("OpenBao TLS identity is ready inside the KMS state volume")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "OpenBao TLS bootstrap failed:", err)
	os.Exit(1)
}

func ensure(dir string, forceRotate bool) error {
	if filepath.Clean(dir) != "/bao/data/tls" {
		return errors.New("TLS identity must stay in /bao/data/tls")
	}
	owner, err := user.Lookup("openbao")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(owner.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(filepath.Dir(dir), uid, gid); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("TLS identity path is not a directory")
		}
		server, err := readServerCertificate(dir)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		validationTime := now
		if !server.NotAfter.After(now) {
			validationTime = server.NotAfter.Add(-time.Second)
		}
		if err := verify(dir, validationTime, uid, gid); err != nil {
			return err
		}
		if forceRotate || !server.NotAfter.After(now.Add(30*24*time.Hour)) {
			if err := rotateServer(dir, uid, gid, now); err != nil {
				return err
			}
			return verify(dir, now, uid, gid)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dir), ".tls-init-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0700); err != nil {
		return err
	}
	if err := generate(staging); err != nil {
		return err
	}
	for _, name := range append([]string{""}, names...) {
		if err := os.Chown(filepath.Join(staging, name), uid, gid); err != nil {
			return err
		}
	}
	if err := verify(staging, time.Now().UTC(), uid, gid); err != nil {
		return err
	}
	if err := os.Rename(staging, dir); err != nil {
		return fmt.Errorf("TLS directory already exists or cannot be installed: %w", err)
	}
	return nil
}

func generate(dir string) error {
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: caSerial,
		Subject:      pkix.Name{CommonName: "Marty self-host OpenBao TLS CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(dir, "ca.crt", "CERTIFICATE", caDER, 0644); err != nil {
		return err
	}
	if err := writeKey(dir, "ca.key", caKey); err != nil {
		return err
	}
	serverPEM, err := createServerPEM(caCert, caKey, now)
	if err != nil {
		return err
	}
	return writeBytes(dir, "server.pem", serverPEM, 0600)
}

func createServerPEM(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time) ([]byte, error) {
	if !ca.NotAfter.After(now.Add(31 * 24 * time.Hour)) {
		return nil, errors.New("OpenBao TLS CA is too close to expiry; rotate the CA and public trust anchor")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	notAfter := now.AddDate(1, 0, 0)
	if limit := ca.NotAfter.Add(-24 * time.Hour); limit.Before(notAfter) {
		notAfter = limit
	}
	server := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "openbao"},
		NotBefore:    now.Add(-time.Hour), NotAfter: notAfter,
		DNSNames:    []string{"openbao", "host.docker.internal", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})...)
	return combined, nil
}

func writeKey(dir, name string, key *ecdsa.PrivateKey) error {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(dir, name, "PRIVATE KEY", encoded, 0600)
}

func writePEM(dir, name, kind string, data []byte, mode os.FileMode) error {
	return writeBytes(dir, name, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), mode)
}

func writeBytes(dir, name string, data []byte, mode os.FileMode) error {
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func readServerCertificate(dir string) (*x509.Certificate, error) {
	serverBytes, err := os.ReadFile(filepath.Join(dir, "server.pem"))
	if err != nil {
		return nil, err
	}
	serverBlock, _ := pem.Decode(serverBytes)
	if serverBlock == nil || serverBlock.Type != "CERTIFICATE" {
		return nil, errors.New("TLS server certificate is invalid")
	}
	return x509.ParseCertificate(serverBlock.Bytes)
}

func rotateServer(dir string, uid, gid int, now time.Time) error {
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode(caBytes)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return errors.New("TLS CA certificate is invalid")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	caKeyBytes, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return err
	}
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil || caKeyBlock.Type != "PRIVATE KEY" {
		return errors.New("TLS CA private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return err
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !caKey.PublicKey.Equal(ca.PublicKey) || ca.CheckSignatureFrom(ca) != nil {
		return errors.New("TLS CA certificate and key differ")
	}
	serverPEM, err := createServerPEM(ca, caKey, now)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".server-renew-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(serverPEM); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(dir, "server.pem")); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func verify(dir string, when time.Time, uid, gid int) error {
	directory, err := os.Lstat(dir)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 ||
		directory.Mode().Perm()&0077 != 0 {
		return errors.New("TLS identity directory is missing or accessible outside OpenBao")
	}
	owner, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != uid || int(owner.Gid) != gid {
		return errors.New("TLS identity directory is outside OpenBao ownership")
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("TLS identity file %s is missing or unsafe", name)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
			return fmt.Errorf("TLS identity file %s is outside OpenBao ownership", name)
		}
		if name != "ca.crt" && info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("TLS private file %s is accessible outside its owner", name)
		}
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode(caBytes)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return errors.New("TLS CA certificate is invalid")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return errors.New("TLS CA certificate is invalid")
	}
	caKeyBytes, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return err
	}
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil || caKeyBlock.Type != "PRIVATE KEY" {
		return errors.New("TLS CA private key is invalid")
	}
	parsedCA, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return err
	}
	caPrivate, ok := parsedCA.(*ecdsa.PrivateKey)
	if !ok || !caPrivate.PublicKey.Equal(ca.PublicKey) {
		return errors.New("TLS CA certificate and key differ")
	}
	serverBytes, err := os.ReadFile(filepath.Join(dir, "server.pem"))
	if err != nil {
		return err
	}
	server, err := readServerCertificate(dir)
	if err != nil {
		return err
	}
	if _, err := server.Verify(x509.VerifyOptions{
		Roots: pool(ca), DNSName: "openbao", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: when,
	}); err != nil {
		return fmt.Errorf("TLS server certificate is untrusted: %w", err)
	}
	for _, host := range []string{"host.docker.internal", "localhost", "127.0.0.1"} {
		if err := server.VerifyHostname(host); err != nil {
			return err
		}
	}
	pair, err := tls.X509KeyPair(serverBytes, serverBytes)
	if err != nil {
		return err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(server.PublicKey) {
		return errors.New("TLS server certificate and key differ")
	}
	return nil
}

func pool(ca *x509.Certificate) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots
}
