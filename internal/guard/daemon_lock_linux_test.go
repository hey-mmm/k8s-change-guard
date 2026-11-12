//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestDaemonLockInteroperatesWithPythonFlock proves the Go daemon and the
// still-installed Python service serialize on the same existing inode. Python's
// _StateLock opens the path with mode "a+" and calls fcntl.flock(LOCK_EX|LOCK_NB);
// this test reproduces that exact primitive without importing Python.
func TestDaemonLockInteroperatesWithPythonFlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".daemon.lock")
	if err := os.WriteFile(path, []byte("python-pid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pythonStyle, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(pythonStyle.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = pythonStyle.Close()
		t.Fatalf("python-style flock failed: %v", err)
	}

	if _, err = daemonPlatformLock(path); !errors.Is(err, errDaemonStateLockBusy) {
		_ = syscall.Flock(int(pythonStyle.Fd()), syscall.LOCK_UN)
		_ = pythonStyle.Close()
		t.Fatalf("Go ignored the live Python flock: %v", err)
	}
	if err = syscall.Flock(int(pythonStyle.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err = pythonStyle.Close(); err != nil {
		t.Fatal(err)
	}

	goLock, err := daemonPlatformLock(path)
	if err != nil {
		t.Fatalf("Go lock after Python unlock: %v", err)
	}
	pythonStyle, err = os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(pythonStyle.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		_ = pythonStyle.Close()
		t.Fatalf("Python-style flock ignored the live Go lock: %v", err)
	}
	_ = pythonStyle.Close()
	if err = daemonPlatformUnlock(goLock); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "python-pid\n" {
		t.Fatalf("cooperative lock changed the existing lock file: %q %v", content, err)
	}
}
