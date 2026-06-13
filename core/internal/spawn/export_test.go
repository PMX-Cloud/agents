package spawn

import (
	"context"
	"log/slog"
	"os"
)

// newSpawnerWithRunner creates a Spawner with an injected cmdRunner for testing.
// This allows tests to exercise the full Spawn() code path without requiring
// root or a real systemd installation.
func newSpawnerWithRunner(log *slog.Logger, runner func(ctx context.Context, args []string, extraFile *os.File) ([]byte, error)) *Spawner {
	if log == nil {
		log = slog.Default()
	}
	return &Spawner{log: log, cmdRunner: runner, memfdCreator: createSealedMemfd, envFileDir: os.TempDir()}
}

// newSpawnerWithRunnerAndMemfd injects both the runner and the memfd creator,
// letting non-Linux dev hosts exercise the full Spawn() happy path.
func newSpawnerWithRunnerAndMemfd(
	log *slog.Logger,
	runner func(ctx context.Context, args []string, extraFile *os.File) ([]byte, error),
	memfd func([]byte) (int, error),
) *Spawner {
	if log == nil {
		log = slog.Default()
	}
	return &Spawner{log: log, cmdRunner: runner, memfdCreator: memfd, envFileDir: os.TempDir()}
}
