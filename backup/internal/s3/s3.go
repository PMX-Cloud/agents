// Package s3 implements S3-compatible backup push/pull primitives.
package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type PushParams struct {
	JobID           string `json:"job_id"`
	LocalPath       string `json:"local_path"`
	Bucket          string `json:"bucket"`
	Key             string `json:"key"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	UsePathStyle    bool   `json:"use_path_style"`
	SSE             string `json:"sse"`
}

type PullParams struct {
	LocalPath       string `json:"local_path"`
	Bucket          string `json:"bucket"`
	Key             string `json:"key"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	UsePathStyle    bool   `json:"use_path_style"`
}

type Result struct {
	BytesTransferred int64  `json:"bytes_transferred"`
	ETag             string `json:"etag,omitempty"`
}

func Push(ctx context.Context, p PushParams, stepFn func(string)) (*Result, error) {
	if strings.TrimSpace(p.LocalPath) == "" {
		return nil, fmt.Errorf("s3 push: local_path is required")
	}
	if strings.TrimSpace(p.Bucket) == "" || strings.TrimSpace(p.Key) == "" {
		return nil, fmt.Errorf("s3 push: bucket and key are required")
	}

	cfg, err := loadConfig(ctx, p.Region, p.Endpoint, p.AccessKeyID, p.SecretAccessKey, p.SessionToken)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = p.UsePathStyle
	})

	file, err := os.Open(p.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("s3 push: open %q: %w", p.LocalPath, err)
	}
	defer file.Close()

	st, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("s3 push: stat %q: %w", p.LocalPath, err)
	}

	etag, err := multipartPush(ctx, client, file, st.Size(), p, stepFn)
	if err != nil {
		return nil, err
	}
	return &Result{BytesTransferred: st.Size(), ETag: etag}, nil
}

const multipartPartSize int64 = 8 * 1024 * 1024

type uploadState struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"upload_id"`
}

func multipartPush(
	ctx context.Context,
	client *s3.Client,
	file *os.File,
	fileSize int64,
	p PushParams,
	stepFn func(string),
) (string, error) {
	statePath := uploadStatePath(p.LocalPath, p.JobID)
	state, err := loadUploadState(statePath)
	if err != nil {
		return "", err
	}
	if state.Bucket != strings.TrimSpace(p.Bucket) || state.Key != strings.TrimSpace(p.Key) {
		state = uploadState{}
	}

	if state.UploadID == "" {
		input := &s3.CreateMultipartUploadInput{Bucket: &p.Bucket, Key: &p.Key}
		if sse := strings.TrimSpace(p.SSE); sse != "" {
			input.ServerSideEncryption = types.ServerSideEncryption(sse)
		}
		out, err := client.CreateMultipartUpload(ctx, input)
		if err != nil {
			return "", fmt.Errorf("s3 push: create multipart upload: %w", err)
		}
		if out.UploadId == nil || strings.TrimSpace(*out.UploadId) == "" {
			return "", fmt.Errorf("s3 push: create multipart upload returned empty upload id")
		}
		state = uploadState{Bucket: strings.TrimSpace(p.Bucket), Key: strings.TrimSpace(p.Key), UploadID: strings.TrimSpace(*out.UploadId)}
		if err := saveUploadState(statePath, state); err != nil {
			return "", err
		}
	}

	existing, err := listCompletedParts(ctx, client, p.Bucket, p.Key, state.UploadID)
	if err != nil {
		return "", err
	}
	completed := make([]types.CompletedPart, 0, int((fileSize+multipartPartSize-1)/multipartPartSize))
	if stepFn != nil {
		stepFn(fmt.Sprintf("s3-upload: starting upload_id=%s", state.UploadID))
	}

	for partNumber, offset := int32(1), int64(0); offset < fileSize; partNumber, offset = partNumber+1, offset+multipartPartSize {
		partSize := multipartPartSize
		if remaining := fileSize - offset; remaining < partSize {
			partSize = remaining
		}
		if part, ok := existing[partNumber]; ok && part.size == partSize {
			completed = append(completed, types.CompletedPart{ETag: &part.etag, PartNumber: &partNumber})
			if stepFn != nil {
				stepFn(fmt.Sprintf("s3-upload: reused part=%d bytes=%d", partNumber, partSize))
			}
			continue
		}

		section := io.NewSectionReader(file, offset, partSize)
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        &p.Bucket,
			Key:           &p.Key,
			UploadId:      &state.UploadID,
			PartNumber:    &partNumber,
			Body:          section,
			ContentLength: &partSize,
		})
		if err != nil {
			return "", fmt.Errorf("s3 push: upload part %d: %w", partNumber, err)
		}
		if out.ETag == nil || strings.TrimSpace(*out.ETag) == "" {
			return "", fmt.Errorf("s3 push: upload part %d returned empty etag", partNumber)
		}
		completed = append(completed, types.CompletedPart{ETag: out.ETag, PartNumber: &partNumber})
		if stepFn != nil {
			stepFn(fmt.Sprintf("s3-upload: uploaded part=%d bytes=%d", partNumber, partSize))
		}
	}

	sort.Slice(completed, func(i, j int) bool {
		return aws.ToInt32(completed[i].PartNumber) < aws.ToInt32(completed[j].PartNumber)
	})
	out, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &p.Bucket,
		Key:      &p.Key,
		UploadId: &state.UploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completed,
		},
	})
	if err != nil {
		return "", fmt.Errorf("s3 push: complete multipart upload: %w", err)
	}
	_ = os.Remove(statePath)
	if stepFn != nil {
		stepFn("s3-upload: completed")
	}
	return strings.TrimSpace(aws.ToString(out.ETag)), nil
}

type completedPartState struct {
	etag string
	size int64
}

func listCompletedParts(ctx context.Context, client *s3.Client, bucket, key, uploadID string) (map[int32]completedPartState, error) {
	parts := map[int32]completedPartState{}
	paginator := s3.NewListPartsPaginator(client, &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 push: list parts: %w", err)
		}
		for _, part := range page.Parts {
			partNumber := aws.ToInt32(part.PartNumber)
			etag := strings.TrimSpace(aws.ToString(part.ETag))
			if partNumber <= 0 || etag == "" {
				continue
			}
			parts[partNumber] = completedPartState{etag: etag, size: aws.ToInt64(part.Size)}
		}
	}
	return parts, nil
}

func loadUploadState(path string) (uploadState, error) {
	if strings.TrimSpace(path) == "" {
		return uploadState{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return uploadState{}, nil
		}
		return uploadState{}, fmt.Errorf("s3 push: read upload state: %w", err)
	}
	var state uploadState
	if err := json.Unmarshal(data, &state); err != nil {
		return uploadState{}, fmt.Errorf("s3 push: parse upload state: %w", err)
	}
	return state, nil
}

func saveUploadState(path string, state uploadState) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("s3 push: marshal upload state: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

var unsafeStateNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func uploadStatePath(localPath, jobID string) string {
	trimmed := strings.TrimSpace(jobID)
	if trimmed == "" {
		return ""
	}
	safeJobID := unsafeStateNameChars.ReplaceAllString(trimmed, "_")
	return filepath.Join(filepath.Dir(localPath), ".pmx-s3-upload-"+safeJobID+".json")
}

func Pull(ctx context.Context, p PullParams, stepFn func(string)) (*Result, error) {
	if strings.TrimSpace(p.LocalPath) == "" {
		return nil, fmt.Errorf("s3 pull: local_path is required")
	}
	if strings.TrimSpace(p.Bucket) == "" || strings.TrimSpace(p.Key) == "" {
		return nil, fmt.Errorf("s3 pull: bucket and key are required")
	}

	cfg, err := loadConfig(ctx, p.Region, p.Endpoint, p.AccessKeyID, p.SecretAccessKey, p.SessionToken)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = p.UsePathStyle
	})

	if err := os.MkdirAll(filepath.Dir(p.LocalPath), 0o755); err != nil {
		return nil, fmt.Errorf("s3 pull: create dir: %w", err)
	}
	file, err := os.Create(p.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("s3 pull: create %q: %w", p.LocalPath, err)
	}
	defer file.Close()

	if stepFn != nil {
		stepFn("s3-download: starting")
	}
	downloader := manager.NewDownloader(client, func(d *manager.Downloader) {
		d.PartSize = 8 * 1024 * 1024
		d.Concurrency = 1
	})
	written, err := downloader.Download(ctx, file, &s3.GetObjectInput{
		Bucket: &p.Bucket,
		Key:    &p.Key,
	})
	if err != nil {
		return nil, fmt.Errorf("s3 pull: download failed: %w", err)
	}
	if stepFn != nil {
		stepFn(fmt.Sprintf("s3-download: completed %d bytes", written))
	}
	return &Result{BytesTransferred: written}, nil
}

func loadConfig(
	ctx context.Context,
	region,
	endpoint,
	accessKeyID,
	secretAccessKey,
	sessionToken string,
) (aws.Config, error) {
	opts := make([]func(*awsconfig.LoadOptions) error, 0, 3)
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}
	opts = append(opts, awsconfig.WithRegion(region))
	if strings.TrimSpace(accessKeyID) != "" || strings.TrimSpace(secretAccessKey) != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken),
		))
	}
	if strings.TrimSpace(endpoint) != "" {
		opts = append(opts, awsconfig.WithBaseEndpoint(strings.TrimSpace(endpoint)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("s3 config: %w", err)
	}
	return cfg, nil
}

type progressReader struct {
	r           io.Reader
	total       int64
	read        int64
	lastEmit    int64
	emitEvery   int64
	onProgress  func(string)
	prefixLabel string
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.read += int64(n)
		if r.onProgress != nil && (r.read-r.lastEmit >= r.emitEvery || (r.total > 0 && r.read >= r.total)) {
			r.onProgress(fmt.Sprintf("%s: %d/%d", r.prefixLabel, r.read, r.total))
			r.lastEmit = r.read
		}
	}
	return n, err
}
