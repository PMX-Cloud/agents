/*
Package spawn implements the ephemeral agent spawning mechanism for pmx-core.

Architecture §5.1 mandates that pmx-hardware-installer, pmx-updater, and
pmx-console-broker be spawned via systemd-run with the signed envelope delivered
on the child's stdin — NEVER via argv or environment variables.

Security rationale: /proc/<pid>/cmdline and /proc/<pid>/environ are world-readable.
Any secret passed there is visible to all processes on the host. Delivering the
envelope on stdin keeps the child's cmdline/environ clean.

The envelope is passed via `--property=StandardInputData=<base64>`: systemd
base64-decodes it and wires it to the unit's standard input, which the child
reads. (The previous `StandardInput=fd:3` + sealed-memfd form never worked:
`fd:NAME` references a *named* descriptor, not a numeric one, so the transient
unit failed before exec and was garbage-collected.)
*/
package spawn

import (
	"context"
	"encoding/base64"
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

	// Encode the envelope to CBOR, then base64 so it can be handed to systemd
	// via --property=StandardInputData= (delivered to the child on stdin).
	envBytes, err := req.Envelope.Marshal()
	if err != nil {
		return fmt.Errorf("spawn: marshal envelope: %w", err)
	}
	envelopeB64 := base64.StdEncoding.EncodeToString(envBytes)

	profile := profileForTemplate(req.Template)
	args := buildSpawnArgs(req, profile, envelopeB64)

	s.log.Info("spawn: starting ephemeral unit",
		"unit", InstantiateTemplate(req.Template, req.JobID),
		"binary", TemplateToBinary(req.Template),
		"PMX_JOB_ID", req.JobID,
	)

	out, err := s.cmdRunner(ctx, args, nil)
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
