package audit

import (
	"fmt"
	"log/slog"
)

// OpenWithFallback opens the primary audit log path and falls back to a
// secondary path when the primary is unavailable.
func OpenWithFallback(
	primaryPath string,
	fallbackPath string,
	logger *slog.Logger,
) (*Log, error) {
	logFile, err := Open(primaryPath)
	if err == nil {
		return logFile, nil
	}

	primaryErr := err
	logFile, err = Open(fallbackPath)
	if err == nil {
		if logger != nil {
			logger.Warn(
				"audit: using fallback log path",
				"primary", primaryPath,
				"fallback", fallbackPath,
				"primaryErr", primaryErr,
			)
		}
		return logFile, nil
	}

	return nil, fmt.Errorf(
		"audit: open primary %q failed: %w; fallback %q failed: %v",
		primaryPath,
		primaryErr,
		fallbackPath,
		err,
	)
}
