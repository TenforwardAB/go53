//go:build linux

package config_test

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/TenforwardAB/slog"

	"go53/config"
)

// TestMergeUpdateLiveJSONAppliesLogLevel verifies that changing log_level via a
// live config update re-applies the slog level immediately — no restart needed.
// slog exposes no level getter, so we assert on the observable behaviour: whether
// a slog.Debug message is emitted. slog captured os.Stdout at init, so output is
// captured by redirecting fd 1 at the syscall level.
func TestMergeUpdateLiveJSONAppliesLogLevel(t *testing.T) {
	setupMockStorage()
	cm := &config.ConfigManager{}
	cm.UpdateLive(config.LiveConfig{LogLevel: "info"})

	// Raising verbosity to debug must take effect on the live config update.
	debugOut := captureStdout(t, func() {
		if err := cm.MergeUpdateLiveJSON([]byte(`{"log_level":"debug"}`)); err != nil {
			t.Fatalf("MergeUpdateLiveJSON: %v", err)
		}
		slog.Debug("hot-reload-debug-marker")
	})
	if !strings.Contains(debugOut, "hot-reload-debug-marker") {
		t.Errorf("expected debug logging enabled after log_level=debug, got output %q", debugOut)
	}

	// Lowering it back to info must silence debug logging again, immediately.
	infoOut := captureStdout(t, func() {
		if err := cm.MergeUpdateLiveJSON([]byte(`{"log_level":"info"}`)); err != nil {
			t.Fatalf("MergeUpdateLiveJSON: %v", err)
		}
		slog.Debug("should-be-suppressed-marker")
	})
	if strings.Contains(infoOut, "should-be-suppressed-marker") {
		t.Errorf("expected debug logging suppressed at log_level=info, got output %q", infoOut)
	}

	// An unknown level must not change the level (and must not panic).
	unknownOut := captureStdout(t, func() {
		if err := cm.MergeUpdateLiveJSON([]byte(`{"log_level":"banana"}`)); err != nil {
			t.Fatalf("MergeUpdateLiveJSON: %v", err)
		}
		slog.Debug("still-suppressed-marker")
	})
	if strings.Contains(unknownOut, "still-suppressed-marker") {
		t.Errorf("expected unknown log_level to keep info level, got output %q", unknownOut)
	}
}

// captureStdout redirects fd 1 to a pipe for the duration of fn and returns
// everything written to it. It redirects the underlying file descriptor (not the
// os.Stdout variable) because slog holds a reference to the original *os.File.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	stdoutFd := int(os.Stdout.Fd())
	saved, err := syscall.Dup(stdoutFd)
	if err != nil {
		t.Fatalf("dup stdout: %v", err)
	}
	if err := syscall.Dup3(int(w.Fd()), stdoutFd, 0); err != nil {
		t.Fatalf("redirect stdout: %v", err)
	}

	func() {
		defer func() {
			_ = syscall.Dup3(saved, stdoutFd, 0)
			_ = syscall.Close(saved)
		}()
		fn()
	}()

	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out)
}
