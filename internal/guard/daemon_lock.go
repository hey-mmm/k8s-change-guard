package guard

// Cross-platform daemon state lock plumbing.
//
// The lock is a kernel advisory lock held for the lifetime of the process file
// descriptor, never an O_EXCL sentinel. A lock file left behind by a crash,
// SIGKILL, or reboot is therefore harmless: the next process opens the same
// inode and takes the advisory lock. On Linux the primitive is flock(2), which
// interoperates with the Python service's existing fcntl.flock lock on
// /var/lib/change-guard/.daemon.lock. Windows uses a LockFileEx byte-range lock
// as the test/runtime fallback, which is likewise released by the kernel when
// the handle closes.

import (
	"errors"
	"os"
)

// errDaemonStateLockBusy is matched by stateStore.lock to expose the stable
// DaemonBusyError contract regardless of the platform lock primitive.
var errDaemonStateLockBusy = errors.New("another change-guard daemon holds the state lock")

func daemonLockReleasedByKernel(file *os.File) error {
	if file == nil {
		return nil
	}
	return daemonPlatformUnlock(file)
}
