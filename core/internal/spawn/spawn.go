/*
Package spawn implements the ephemeral agent spawning mechanism for pmx-core.

Architecture §5.1 mandates that pmx-hardware-installer, pmx-updater, and
pmx-console-broker be spawned via systemd-run with the signed envelope passed
via a sealed memfd file descriptor — NEVER via argv or environment variables.

Security rationale: /proc/<pid>/cmdline and /proc/<pid>/environ are world-readable.
Any secret passed there is visible to all processes on the host.

The sealed memfd approach:
 1. memfd_create with MFD_CLOEXEC | MFD_ALLOW_SEALING.
 2. Write the canonical CBOR envelope bytes.
 3. Seal with F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL.
    After sealing, the contents cannot be modified even by the spawning process.
 4. Pass the fd to systemd-run as ExtraFiles[0], then bind stdin to fd:3 via
    --property=StandardInput=fd:3.

Note: memfd_create is Linux-only. On macOS (dev) the spawn call will return an
error at runtime; this is expected and does not break unit tests of other packages.
*/
package spawn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pmx-cloud/agents/shared/envelope"
)

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
	// memfdCreator creates the sealed envelope fd. Injected in tests so
	// non-Linux dev machines can exercise the full Spawn() path.
	memfdCreator func(env []byte) (int, error)
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
	return &Spawner{log: log, cmdRunner: defaultCmdRunner, memfdCreator: createSealedMemfd}
}

// defaultCmdRunner executes systemd-run with the given args and extra file.
func defaultCmdRunner(ctx context.Context, args []string, extraFile *os.File) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.ExtraFiles = []*os.File{extraFile}
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

	// Encode the envelope to CBOR.
	envBytes, err := req.Envelope.Marshal()
	if err != nil {
		return fmt.Errorf("spawn: marshal envelope: %w", err)
	}

	// Create the sealed memfd and get its fd number.
	fd, err := s.memfdCreator(envBytes)
	if err != nil {
		return fmt.Errorf("spawn: sealed memfd: %w", err)
	}
	envFD := os.NewFile(uintptr(fd), "pmx-envelope")
	if envFD == nil {
		closeFd(fd)
		return fmt.Errorf("spawn: failed to wrap memfd")
	}
	defer envFD.Close()

	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile)

	s.log.Info("spawn: starting ephemeral unit",
		"unit", InstantiateTemplate(req.Template, req.JobID),
		"binary", TemplateToBinary(req.Template),
		"PMX_JOB_ID", req.JobID,
	)

	out, err := s.cmdRunner(ctx, args, envFD)
	if err != nil {
		return fmt.Errorf("spawn: systemd-run %s: %w\n%s", args[1], err, out)
	}
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
