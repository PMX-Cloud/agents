/*
Package spawn implements the ephemeral agent spawning mechanism for pmx-core.

Architecture §5.1 mandates that pmx-hardware-installer, pmx-updater, and
pmx-console-broker be spawned via systemd-run with the signed envelope delivered
on the child's stdin — NEVER via argv or environment variables.

Security rationale: /proc/<pid>/cmdline and /proc/<pid>/environ are world-readable.
Any secret passed there is visible to all processes on the host. Delivering the
envelope on stdin keeps the child's cmdline/environ clean.

The envelope is staged in a 0600 root:root tmpfs file and passed via
`--property=StandardInputFile=<path>`: systemd (PID1, root) opens the file as the
unit's stdin before dropping to the unit's User=, and the child reads it from
stdin. Only the non-sensitive PATH appears in systemd-run's argv — the envelope
bytes are never in any process's cmdline or environ. The file is unlinked shortly
after the unit starts (the open fd survives the unlink).

(The previous `StandardInput=fd:3` + sealed-memfd form never worked: `fd:NAME`
references a *named* descriptor, not a numeric one, so the transient unit failed
before exec and was garbage-collected. `StandardInputData=<base64>` would have
worked but leaked the envelope into systemd-run's argv.)
*/
package spawn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

// defaultEnvFileDir is the tmpfs directory where the signed envelope is staged
// for delivery to the ephemeral unit via StandardInputFile.
const defaultEnvFileDir = "/run/pmx-cloud"

// envFileCleanupDelay is how long to wait after systemd-run before unlinking the
// staged envelope file. systemd opens StandardInputFile as it starts the unit
// (well within this window); the open fd survives the unlink.
const envFileCleanupDelay = 30 * time.Second

// EphemeralRequest describes a request to spawn an ephemeral agent.
type EphemeralRequest struct {
	// Template is the systemd template unit, e.g. "pmx-hardware-installer@.service".
	Template string
	// JobID is used to name the ephemeral unit instance.
	JobID string
	// Envelope is the signed command envelope to pass to the child via sealed FD.
	Envelope *envelope.Envelope
	// RuntimeMaxSec is the per-agent timeout (0 = no limit).
	RuntimeMaxSec int
}

// Spawner spawns ephemeral agents via systemd-run.
type Spawner struct {
	log *slog.Logger
	// cmdRunner is used to execute the systemd-run command. It is
	// injected in tests to avoid requiring root/systemd on the test host.
	cmdRunner func(ctx context.Context, args []string, extraFile *os.File) ([]byte, error)
	// memfdCreator creates the sealed envelope fd. Retained for the injectable
	// test seam; the production path now stages the envelope to envFileDir and
	// delivers it via StandardInputFile.
	memfdCreator func(env []byte) (int, error)
	// envFileDir is the directory where the signed envelope is staged before
	// systemd opens it as the unit's stdin. Tests point this at a writable temp
	// dir; production uses defaultEnvFileDir.
	envFileDir string
}

// writeEnvFile stages the marshaled envelope in a 0600 file under envFileDir and
// returns its path. The filename is derived from a sanitized jobID so a hostile
// id cannot escape the directory.
func (s *Spawner) writeEnvFile(jobID string, data []byte) (string, error) {
	dir := s.envFileDir
	if dir == "" {
		dir = defaultEnvFileDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, filepath.Base(jobID)+".env")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

type templateProfile struct {
	User            string
	Group           string
	ServiceType     string
	RemainAfterExit bool
	Restart         string
	AppArmorProfile string
	DefaultRuntime  int
}

var defaultTemplateProfiles = map[string]templateProfile{
	"pmx-hardware-installer@.service": {
		User:            "root",
		Group:           "root",
		ServiceType:     "oneshot",
		RemainAfterExit: false,
	},
	"pmx-updater@.service": {
		User:            "root",
		Group:           "root",
		ServiceType:     "oneshot",
		RemainAfterExit: false,
	},
	"pmx-console-broker@.service": {
		User:            "pmx-console",
		Group:           "pmx-console",
		ServiceType:     "simple",
		RemainAfterExit: false,
		Restart:         "no",
		AppArmorProfile: "pmx-console-broker",
		DefaultRuntime:  14_400,
	},
}

// NewSpawner creates a Spawner.
func NewSpawner(log *slog.Logger) *Spawner {
	if log == nil {
		log = slog.Default()
	}
	return &Spawner{log: log, cmdRunner: defaultCmdRunner, memfdCreator: createSealedMemfd, envFileDir: defaultEnvFileDir}
}

// defaultCmdRunner executes systemd-run with the given args. extraFile is
// retained for the injectable signature but is only attached when non-nil
// (the envelope now travels via --property=StandardInputData, not an fd).
func defaultCmdRunner(ctx context.Context, args []string, extraFile *os.File) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if extraFile != nil {
		cmd.ExtraFiles = []*os.File{extraFile}
	}
	return cmd.CombinedOutput()
}

// Spawn spawns an ephemeral agent, passing the envelope via a sealed memfd.
// Returns when the unit has been successfully started (not when it completes).
func (s *Spawner) Spawn(ctx context.Context, req EphemeralRequest) error {
	if req.Template == "" {
		return fmt.Errorf("spawn: template is required")
	}
	if req.JobID == "" {
		return fmt.Errorf("spawn: job ID is required")
	}
	if req.Envelope == nil {
		return fmt.Errorf("spawn: envelope is required")
	}

	// Encode the envelope to CBOR and write it to a 0600 root:root tmpfs file.
	// systemd (PID1) opens it as the unit's stdin via StandardInputFile; only
	// the file PATH (not the envelope bytes) appears in systemd-run's argv, so
	// the signed envelope never leaks through /proc/<pid>/cmdline or environ.
	envBytes, err := req.Envelope.Marshal()
	if err != nil {
		return fmt.Errorf("spawn: marshal envelope: %w", err)
	}
	envPath, err := s.writeEnvFile(req.JobID, envBytes)
	if err != nil {
		return fmt.Errorf("spawn: write envelope file: %w", err)
	}

	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile, envPath)

	s.log.Info("spawn: starting ephemeral unit",
		"unit", InstantiateTemplate(req.Template, req.JobID),
		"binary", TemplateToBinary(req.Template),
		"PMX_JOB_ID", req.JobID,
	)

	out, err := s.cmdRunner(ctx, args, nil)
	if err != nil {
		_ = os.Remove(envPath)
		return fmt.Errorf("spawn: systemd-run %s: %w\n%s", args[1], err, out)
	}
	// systemd opens StandardInputFile as it starts the unit (within ~1s); the
	// open fd survives unlink, so remove the path shortly after to avoid leaving
	// signed envelopes on disk.
	go func() {
		time.Sleep(envFileCleanupDelay)
		_ = os.Remove(envPath)
	}()
	return nil
}

// WaitResult polls the ephemeral unit until it exits or the context is cancelled.
// Returns the final ActiveState ("inactive", "failed", etc.).
func (s *Spawner) WaitResult(ctx context.Context, template, jobID string) (string, error) {
	unitName := InstantiateTemplate(template, jobID)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			state, err := unitActiveState(ctx, unitName)
			if err != nil {
				continue
			}
			switch state {
			case "inactive", "failed", "deactivating":
				return state, nil
			}
		}
	}
}

// unitActiveState calls systemctl show --property=ActiveState --value <unit>.
func unitActiveState(ctx context.Context, unit string) (string, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// InstantiateTemplate converts "pmx-foo@.service" + "jobid" → "pmx-foo@jobid.service".
func InstantiateTemplate(template, jobID string) string {
	// Strip ".service", insert jobID after "@", re-add ".service".
	name := strings.TrimSuffix(template, ".service")
	name = strings.TrimSuffix(name, "@")
	return name + "@" + jobID + ".service"
}

// TemplateToBinary maps a template name to the binary path.
// e.g. "pmx-hardware-installer@.service" → "/usr/local/bin/pmx-hardware-installer"
func TemplateToBinary(template string) string {
	base := strings.TrimSuffix(template, "@.service")
	base = strings.TrimSuffix(base, ".service")
	return "/usr/local/bin/" + base
}
