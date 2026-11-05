//go:build !windows

package usn

import (
	"context"
	"errors"
	"log/slog"

	"ransomwarehunter/internal/event"
)

// Run chỉ hỗ trợ trên Windows.
func Run(context.Context, SourceConfig, func([]event.FileEvent) error, func(string, map[string]int), *slog.Logger) error {
	return errors.New("USN Journal chỉ hỗ trợ trên Windows")
}
