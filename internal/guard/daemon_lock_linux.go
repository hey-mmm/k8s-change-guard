//go:build linux

package guard

import (
	"errors"
	"os"
	"syscall"
)

// daemonPlatformLock acquires a non-blocking exclusive flock(2) on path.
//
// The file is deliberately not removed on release. Removing it would let one
// waiter unlink another waiter's inode, breaking the kernel lock identity. An
// existing lock file from Python's fcntl.flock implementation, or from a
// previous crashed process, is opened normally and the advisory lock succeeds
// as soon as no live file descriptor holds it.
func daemonPlatformLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errDaemonStateLockBusy
		}
		return nil, err
	}
	return file, nil
}

func daemonPlatformUnlock(file *os.File) error {
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
