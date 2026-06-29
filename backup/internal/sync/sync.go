// Package sync coordinates off-host backup sync operations (S3/SFTP/PBS).
package sync

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	stdsync "sync"
	"time"

	"github.com/pmx-cloud/agents/backup/internal/pbs"
	"github.com/pmx-cloud/agents/backup/internal/s3"
	"github.com/pmx-cloud/agents/backup/internal/sftp"
	"golang.org/x/crypto/chacha20poly1305"
)

type PushParams struct {
	JobID         string          `json:"job_id"`
	Provider      string          `json:"provider"`
	LocalPath     string          `json:"local_path"`
	EncryptionKey string          `json:"encryption_key"`
	S3            s3.PushParams   `json:"s3"`
	SFTP          sftp.PushParams `json:"sftp"`
	PBS           pbs.PushParams  `json:"pbs"`
}

type PullParams struct {
	JobID         string          `json:"job_id"`
	Provider      string          `json:"provider"`
	LocalPath     string          `json:"local_path"`
	EncryptionKey string          `json:"encryption_key"`
	S3            s3.PullParams   `json:"s3"`
	SFTP          sftp.PullParams `json:"sftp"`
	PBS           pbs.PullParams  `json:"pbs"`
}

type Result struct {
	Provider         string `json:"provider"`
	BytesTransferred int64  `json:"bytes_transferred"`
	Encrypted        bool   `json:"encrypted"`
}

type Runner struct {
	mu   stdsync.Mutex
	jobs map[string]jobState
}

type jobState struct {
	Provider string
	Action   string
	Updated  time.Time
}

func NewRunner() *Runner {
	return &Runner{jobs: map[string]jobState{}}
}

func (r *Runner) Push(ctx context.Context, p PushParams, stepFn func(string)) (*Result, error) {
	provider := strings.ToLower(strings.TrimSpace(p.Provider))
	if provider == "" {
		return nil, fmt.Errorf("sync push: provider is required")
	}
	if p.JobID != "" {
		r.record(p.JobID, provider, "push")
	}

	localPath := strings.TrimSpace(p.LocalPath)
	if localPath == "" {
		localPath = strings.TrimSpace(p.S3.LocalPath)
		if localPath == "" {
			localPath = strings.TrimSpace(p.SFTP.LocalPath)
			if localPath == "" {
				localPath = strings.TrimSpace(p.PBS.LocalPath)
			}
		}
	}
	if localPath == "" {
		return nil, fmt.Errorf("sync push: local_path is required")
	}

	key, err := parseEncryptionKey(p.EncryptionKey)
	if err != nil {
		return nil, err
	}
	encrypted := len(key) > 0
	uploadPath := localPath
	cleanup := func() {}
	if encrypted {
		tmp, err := encryptToTemp(localPath, key, stepFn)
		if err != nil {
			return nil, err
		}
		uploadPath = tmp
		cleanup = func() {
			_ = os.Remove(tmp)
		}
	}
	defer cleanup()

	switch provider {
	case "s3":
		input := p.S3
		input.LocalPath = uploadPath
		input.JobID = p.JobID
		res, err := s3.Push(ctx, input, stepFn)
		if err != nil {
			return nil, err
		}
		return &Result{Provider: provider, BytesTransferred: res.BytesTransferred, Encrypted: encrypted}, nil
	case "sftp":
		input := p.SFTP
		input.LocalPath = uploadPath
		res, err := sftp.Push(ctx, input, stepFn)
		if err != nil {
			return nil, err
		}
		return &Result{Provider: provider, BytesTransferred: res.BytesTransferred, Encrypted: encrypted}, nil
	case "pbs":
		input := p.PBS
		input.LocalPath = uploadPath
		if err := pbs.Push(ctx, input, stepFn); err != nil {
			return nil, err
		}
		st, _ := os.Stat(uploadPath)
		var size int64
		if st != nil {
			size = st.Size()
		}
		return &Result{Provider: provider, BytesTransferred: size, Encrypted: encrypted}, nil
	default:
		return nil, fmt.Errorf("sync push: unsupported provider %q", provider)
	}
}

func (r *Runner) Pull(ctx context.Context, p PullParams, stepFn func(string)) (*Result, error) {
	provider := strings.ToLower(strings.TrimSpace(p.Provider))
	if provider == "" {
		return nil, fmt.Errorf("sync pull: provider is required")
	}
	if p.JobID != "" {
		r.record(p.JobID, provider, "pull")
	}

	destination := strings.TrimSpace(p.LocalPath)
	if destination == "" {
		destination = strings.TrimSpace(p.S3.LocalPath)
		if destination == "" {
			destination = strings.TrimSpace(p.SFTP.LocalPath)
			if destination == "" {
				destination = strings.TrimSpace(p.PBS.LocalPath)
			}
		}
	}
	if destination == "" {
		return nil, fmt.Errorf("sync pull: local_path is required")
	}

	key, err := parseEncryptionKey(p.EncryptionKey)
	if err != nil {
		return nil, err
	}
	encrypted := len(key) > 0
	downloadPath := destination
	cleanup := func() {}
	if encrypted {
		tmp, err := os.CreateTemp(filepath.Dir(destination), ".pmx-backup-pull-*.enc")
		if err != nil {
			return nil, fmt.Errorf("sync pull: create temp: %w", err)
		}
		_ = tmp.Close()
		downloadPath = tmp.Name()
		cleanup = func() {
			_ = os.Remove(downloadPath)
		}
	}
	defer cleanup()

	var bytesTransferred int64
	switch provider {
	case "s3":
		input := p.S3
		input.LocalPath = downloadPath
		res, err := s3.Pull(ctx, input, stepFn)
		if err != nil {
			return nil, err
		}
		bytesTransferred = res.BytesTransferred
	case "sftp":
		input := p.SFTP
		input.LocalPath = downloadPath
		res, err := sftp.Pull(ctx, input, stepFn)
		if err != nil {
			return nil, err
		}
		bytesTransferred = res.BytesTransferred
	case "pbs":
		input := p.PBS
		input.LocalPath = downloadPath
		if err := pbs.Pull(ctx, input, stepFn); err != nil {
			return nil, err
		}
		if st, err := os.Stat(downloadPath); err == nil {
			bytesTransferred = st.Size()
		}
	default:
		return nil, fmt.Errorf("sync pull: unsupported provider %q", provider)
	}

	if encrypted {
		if err := decryptFile(downloadPath, destination, key, stepFn); err != nil {
			return nil, err
		}
		if st, err := os.Stat(destination); err == nil {
			bytesTransferred = st.Size()
		}
	}
	return &Result{Provider: provider, BytesTransferred: bytesTransferred, Encrypted: encrypted}, nil
}

func (r *Runner) record(jobID, provider, action string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs[jobID] = jobState{Provider: provider, Action: action, Updated: time.Now().UTC()}
}

const (
	encryptedMagic = "PMXBKP01"
	chunkSize      = 1 * 1024 * 1024
)

func parseEncryptionKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if key, err := hex.DecodeString(trimmed); err == nil && len(key) == chacha20poly1305.KeySize {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(key) == chacha20poly1305.KeySize {
		return key, nil
	}
	if len(trimmed) == chacha20poly1305.KeySize {
		return []byte(trimmed), nil
	}
	return nil, fmt.Errorf("sync: encryption key must be 32 bytes (raw/base64/hex)")
}

func encryptToTemp(sourcePath string, key []byte, stepFn func(string)) (string, error) {
	src, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("sync encrypt: open source %q: %w", sourcePath, err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(sourcePath), ".pmx-backup-enc-*.bin")
	if err != nil {
		return "", fmt.Errorf("sync encrypt: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
	}()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("sync encrypt: init cipher: %w", err)
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(baseNonce); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("sync encrypt: nonce: %w", err)
	}

	header := make([]byte, 0, len(encryptedMagic)+aead.NonceSize()+4)
	header = append(header, []byte(encryptedMagic)...)
	header = append(header, baseNonce...)
	chunkSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSizeBytes, chunkSize)
	header = append(header, chunkSizeBytes...)
	if _, err := tmp.Write(header); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("sync encrypt: write header: %w", err)
	}

	buffer := make([]byte, chunkSize)
	var (
		chunkIndex uint32
		totalRead  int64
	)
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			nonce := make([]byte, len(baseNonce))
			copy(nonce, baseNonce)
			binary.LittleEndian.PutUint32(nonce[len(nonce)-4:], chunkIndex)
			sealed := aead.Seal(nil, nonce, buffer[:n], nil)

			lengthPrefix := make([]byte, 4)
			binary.LittleEndian.PutUint32(lengthPrefix, uint32(n))
			if _, err := tmp.Write(lengthPrefix); err != nil {
				_ = os.Remove(tmpPath)
				return "", fmt.Errorf("sync encrypt: write length: %w", err)
			}
			if _, err := tmp.Write(sealed); err != nil {
				_ = os.Remove(tmpPath)
				return "", fmt.Errorf("sync encrypt: write chunk: %w", err)
			}

			totalRead += int64(n)
			chunkIndex++
			if stepFn != nil && (totalRead%(64*1024*1024) == 0 || readErr == io.EOF) {
				stepFn(fmt.Sprintf("sync encrypt: %d bytes", totalRead))
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = os.Remove(tmpPath)
			return "", fmt.Errorf("sync encrypt: read source: %w", readErr)
		}
	}
	if stepFn != nil {
		stepFn("sync encrypt: completed")
	}
	return tmpPath, nil
}

func decryptFile(sourcePath, destinationPath string, key []byte, stepFn func(string)) error {
	src, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("sync decrypt: open source %q: %w", sourcePath, err)
	}
	defer src.Close()

	reader := bufio.NewReader(src)
	magic := make([]byte, len(encryptedMagic))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return fmt.Errorf("sync decrypt: read magic: %w", err)
	}
	if string(magic) != encryptedMagic {
		return fmt.Errorf("sync decrypt: invalid encrypted payload format")
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("sync decrypt: init cipher: %w", err)
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(reader, baseNonce); err != nil {
		return fmt.Errorf("sync decrypt: read nonce: %w", err)
	}
	chunkSizeHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, chunkSizeHeader); err != nil {
		return fmt.Errorf("sync decrypt: read chunk size: %w", err)
	}
	declaredChunkSize := binary.LittleEndian.Uint32(chunkSizeHeader)
	if declaredChunkSize == 0 || declaredChunkSize > 16*1024*1024 {
		return fmt.Errorf("sync decrypt: invalid chunk size %d", declaredChunkSize)
	}

	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return fmt.Errorf("sync decrypt: create output dir: %w", err)
	}
	dst, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("sync decrypt: create %q: %w", destinationPath, err)
	}
	defer dst.Close()

	var (
		chunkIndex uint32
		totalWrite int64
	)
	for {
		plainLenPrefix := make([]byte, 4)
		_, err := io.ReadFull(reader, plainLenPrefix)
		if err == io.EOF {
			break
		}
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return fmt.Errorf("sync decrypt: truncated length prefix")
			}
			return fmt.Errorf("sync decrypt: read length prefix: %w", err)
		}
		plainLen := binary.LittleEndian.Uint32(plainLenPrefix)
		if plainLen == 0 || plainLen > 16*1024*1024 {
			return fmt.Errorf("sync decrypt: invalid chunk payload length %d", plainLen)
		}
		sealed := make([]byte, int(plainLen)+chacha20poly1305.Overhead)
		if _, err := io.ReadFull(reader, sealed); err != nil {
			return fmt.Errorf("sync decrypt: read encrypted chunk: %w", err)
		}

		nonce := make([]byte, len(baseNonce))
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint32(nonce[len(nonce)-4:], chunkIndex)
		opened, err := aead.Open(nil, nonce, sealed, nil)
		if err != nil {
			return fmt.Errorf("sync decrypt: integrity check failed on chunk %d: %w", chunkIndex, err)
		}
		if _, err := dst.Write(opened); err != nil {
			return fmt.Errorf("sync decrypt: write destination: %w", err)
		}
		totalWrite += int64(len(opened))
		chunkIndex++
		if stepFn != nil && totalWrite%(64*1024*1024) == 0 {
			stepFn(fmt.Sprintf("sync decrypt: %d bytes", totalWrite))
		}
	}
	if stepFn != nil {
		stepFn("sync decrypt: completed")
	}
	return nil
}
