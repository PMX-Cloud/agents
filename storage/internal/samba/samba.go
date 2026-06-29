// Package samba implements samba.share.* via net usershare.
package samba

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

// ShareParams configures Samba share operations.
type ShareParams struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Comment string `json:"comment"`
	ACL     string `json:"acl"`
}

const pmxUsersharePrefix = "pmx-"

func ShareCreate(ctx context.Context, ex storageexec.Interface, p ShareParams) error {
	id, err := normalizeID(p.ID)
	if err != nil {
		return err
	}
	if !isSafePath(p.Path) {
		return fmt.Errorf("samba.share.create: invalid path")
	}
	comment := strings.TrimSpace(p.Comment)
	if comment == "" {
		comment = "PMX share"
	}
	acl := strings.TrimSpace(p.ACL)
	if acl == "" {
		acl = "Everyone:F"
	}
	if _, err := ex.Net(ctx, "usershare", "add", pmxUsersharePrefix+id, p.Path, comment, acl); err != nil {
		return fmt.Errorf("samba.share.create: %w", err)
	}
	return nil
}

func ShareDelete(ctx context.Context, ex storageexec.Interface, p ShareParams) error {
	id, err := normalizeID(p.ID)
	if err != nil {
		return err
	}
	if _, err := ex.Net(ctx, "usershare", "delete", pmxUsersharePrefix+id); err != nil {
		return fmt.Errorf("samba.share.delete: %w", err)
	}
	return nil
}

func ShareList(ctx context.Context, ex storageexec.Interface) ([]string, error) {
	res, err := ex.Net(ctx, "usershare", "list")
	if err != nil {
		return nil, fmt.Errorf("samba.share.list: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(res.StdoutString()), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, pmxUsersharePrefix) {
			out = append(out, strings.TrimPrefix(line, pmxUsersharePrefix))
		}
	}
	sort.Strings(out)
	return out, nil
}

func normalizeID(v string) (string, error) {
	id := strings.TrimSpace(v)
	if strings.HasPrefix(id, pmxUsersharePrefix) {
		id = strings.TrimPrefix(id, pmxUsersharePrefix)
	}
	if !isSafeName(id) {
		return "", fmt.Errorf("samba.share: invalid id")
	}
	return id, nil
}

func isSafeName(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, c := range v {
		if !(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isSafePath(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.Contains(v, "..") && !strings.ContainsAny(v, "\n\r\x00")
}
