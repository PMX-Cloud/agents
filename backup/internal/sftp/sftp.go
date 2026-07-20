// Package sftp implements SFTP backup push/pull primitives.
package sftp

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	gosftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type PushParams struct {
	LocalPath             string `json:"local_path"`
	RemotePath            string `json:"remote_path"`
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PrivateKeyPEM         string `json:"private_key_pem"`
	PrivateKeyPassphase   string `json:"private_key_passphrase"`
	KnownHostPublicKey    string `json:"known_host_public_key"`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_host_key"`
	Resume                bool   `json:"resume"`
}

type PullParams struct {
	LocalPath             string `json:"local_path"`
	RemotePath            string `json:"remote_path"`
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PrivateKeyPEM         string `json:"private_key_pem"`
	PrivateKeyPassphase   string `json:"private_key_passphrase"`
	KnownHostPublicKey    string `json:"known_host_public_key"`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_host_key"`
	Resume                bool   `json:"resume"`
}

type Result struct {
	BytesTransferred int64 `json:"bytes_transferred"`
	Offset           int64 `json:"offset"`
}

func Push(ctx context.Context, p PushParams, stepFn func(string)) (*Result, error) {
	if strings.TrimSpace(p.LocalPath) == "" || strings.TrimSpace(p.RemotePath) == "" {
		return nil, fmt.Errorf("sftp push: local_path and remote_path are required")
	}

	client, err := connect(ctx, connParams{
		host:                p.Host,
		port:                p.Port,
		username:            p.Username,
		password:            p.Password,
		privateKeyPEM:       p.PrivateKeyPEM,
		privateKeyPassphase: p.PrivateKeyPassphase,
		knownHostPublicKey:  p.KnownHostPublicKey,
		insecureHostKey:     p.InsecureIgnoreHostKey,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	local, err := os.Open(p.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("sftp push: open local %q: %w", p.LocalPath, err)
	}
	defer local.Close()
	localStat, err := local.Stat()
	if err != nil {
		return nil, fmt.Errorf("sftp push: stat local %q: %w", p.LocalPath, err)
	}

	if err := client.MkdirAll(filepath.Dir(p.RemotePath)); err != nil {
		return nil, fmt.Errorf("sftp push: create remote dir: %w", err)
	}

	var offset int64
	if p.Resume {
		if st, err := client.Stat(p.RemotePath); err == nil {
			offset, err = resumeOffset(localStat.Size(), st.Size())
			if err != nil {
				return nil, fmt.Errorf("sftp push: %w", err)
			}
		}
	}
	if offset > 0 {
		if _, err := local.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("sftp push: seek local: %w", err)
		}
	}

	flags := os.O_CREATE | os.O_WRONLY
	if !p.Resume {
		flags |= os.O_TRUNC
	}
	remote, err := client.OpenFile(p.RemotePath, flags)
	if err != nil {
		return nil, fmt.Errorf("sftp push: open remote %q: %w", p.RemotePath, err)
	}
	defer remote.Close()

	if offset > 0 {
		if _, err := remote.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("sftp push: seek remote: %w", err)
		}
	}
	if stepFn != nil {
		stepFn(fmt.Sprintf("sftp-upload: starting offset=%d", offset))
	}
	written, err := io.Copy(remote, local)
	if err != nil {
		return nil, fmt.Errorf("sftp push: copy: %w", err)
	}
	if stepFn != nil {
		stepFn(fmt.Sprintf("sftp-upload: completed bytes=%d", written))
	}
	return &Result{BytesTransferred: written, Offset: offset}, nil
}

func Pull(ctx context.Context, p PullParams, stepFn func(string)) (*Result, error) {
	if strings.TrimSpace(p.LocalPath) == "" || strings.TrimSpace(p.RemotePath) == "" {
		return nil, fmt.Errorf("sftp pull: local_path and remote_path are required")
	}

	client, err := connect(ctx, connParams{
		host:                p.Host,
		port:                p.Port,
		username:            p.Username,
		password:            p.Password,
		privateKeyPEM:       p.PrivateKeyPEM,
		privateKeyPassphase: p.PrivateKeyPassphase,
		knownHostPublicKey:  p.KnownHostPublicKey,
		insecureHostKey:     p.InsecureIgnoreHostKey,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := os.MkdirAll(filepath.Dir(p.LocalPath), 0o755); err != nil {
		return nil, fmt.Errorf("sftp pull: create local dir: %w", err)
	}

	remoteStat, err := client.Stat(p.RemotePath)
	if err != nil {
		return nil, fmt.Errorf("sftp pull: stat remote %q: %w", p.RemotePath, err)
	}

	var offset int64
	if p.Resume {
		if st, err := os.Stat(p.LocalPath); err == nil {
			offset, err = resumeOffset(remoteStat.Size(), st.Size())
			if err != nil {
				return nil, fmt.Errorf("sftp pull: %w", err)
			}
		}
	}

	var local *os.File
	if offset > 0 {
		local, err = os.OpenFile(p.LocalPath, os.O_WRONLY, 0o644)
	} else {
		local, err = os.Create(p.LocalPath)
	}
	if err != nil {
		return nil, fmt.Errorf("sftp pull: open local %q: %w", p.LocalPath, err)
	}
	defer local.Close()

	if offset > 0 {
		if _, err := local.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("sftp pull: seek local: %w", err)
		}
	}

	remote, err := client.Open(p.RemotePath)
	if err != nil {
		return nil, fmt.Errorf("sftp pull: open remote %q: %w", p.RemotePath, err)
	}
	defer remote.Close()

	if offset > 0 {
		if _, err := remote.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("sftp pull: seek remote: %w", err)
		}
	}

	if stepFn != nil {
		stepFn(fmt.Sprintf("sftp-download: starting offset=%d", offset))
	}
	written, err := io.Copy(local, remote)
	if err != nil {
		return nil, fmt.Errorf("sftp pull: copy: %w", err)
	}
	if stepFn != nil {
		stepFn(fmt.Sprintf("sftp-download: completed bytes=%d", written))
	}
	return &Result{BytesTransferred: written, Offset: offset}, nil
}

type connParams struct {
	host                string
	port                int
	username            string
	password            string
	privateKeyPEM       string
	privateKeyPassphase string
	knownHostPublicKey  string
	insecureHostKey     bool
}

func connect(ctx context.Context, p connParams) (*gosftp.Client, error) {
	if strings.TrimSpace(p.host) == "" || strings.TrimSpace(p.username) == "" {
		return nil, fmt.Errorf("sftp: host and username are required")
	}
	if p.port == 0 {
		p.port = 22
	}
	authMethods := make([]ssh.AuthMethod, 0, 2)
	if strings.TrimSpace(p.password) != "" {
		authMethods = append(authMethods, ssh.Password(p.password))
	}
	if strings.TrimSpace(p.privateKeyPEM) != "" {
		signer, err := parseSigner(p.privateKeyPEM, p.privateKeyPassphase)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("sftp: one auth method is required (password or private key)")
	}

	cb, err := hostKeyCallback(p.knownHostPublicKey, p.insecureHostKey)
	if err != nil {
		return nil, err
	}
	sshConfig := &ssh.ClientConfig{
		User:            p.username,
		Auth:            authMethods,
		HostKeyCallback: cb,
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port))
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sftp: dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sftp: ssh handshake: %w", err)
	}
	client, err := gosftp.NewClient(ssh.NewClient(sshConn, chans, reqs))
	if err != nil {
		return nil, fmt.Errorf("sftp: client init: %w", err)
	}
	return client, nil
}

func parseSigner(privateKeyPEM, passphrase string) (ssh.Signer, error) {
	if strings.TrimSpace(passphrase) == "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("sftp: parse private key: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(privateKeyPEM), []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("sftp: parse encrypted private key: %w", err)
	}
	return signer, nil
}

func hostKeyCallback(knownHostPublicKey string, insecure bool) (ssh.HostKeyCallback, error) {
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	trimmed := strings.TrimSpace(knownHostPublicKey)
	if trimmed == "" {
		return nil, fmt.Errorf("sftp: known_host_public_key is required unless insecure_ignore_host_key=true")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("sftp: parse known_host_public_key: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if string(parsed.Marshal()) == string(key.Marshal()) {
			return nil
		}
		return fmt.Errorf("sftp: host key mismatch for %s", hostname)
	}, nil
}

func resumeOffset(sourceSize, partialSize int64) (int64, error) {
	if partialSize < 0 {
		return 0, fmt.Errorf("partial size must be >= 0")
	}
	if partialSize > sourceSize {
		return 0, fmt.Errorf("partial file is larger than source (%d > %d)", partialSize, sourceSize)
	}
	return partialSize, nil
}
