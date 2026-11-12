//go:build windows

package guard

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	daemonLockfileFailImmediately = 0x00000001
	daemonLockfileExclusiveLock   = 0x00000002
	daemonErrorLockViolation      = syscall.Errno(33)
)

var (
	daemonKernel32         = syscall.NewLazyDLL("kernel32.dll")
	daemonProcLockFileEx   = daemonKernel32.NewProc("LockFileEx")
	daemonProcUnlockFileEx = daemonKernel32.NewProc("UnlockFileEx")
)

// daemonOverlapped matches the leading OVERLAPPED fields used by
// LockFileEx/UnlockFileEx. Only Offset/OffsetHigh are read for a blocking-less
// one-byte range lock at offset zero.
type daemonOverlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       syscall.Handle
}

// daemonPlatformLock acquires a kernel byte-range lock on path. The lock is
// held by the OS until the handle is closed, so a stale lock file cannot strand
// a restarted daemon.
func daemonPlatformLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped daemonOverlapped
	result, _, callErr := daemonProcLockFileEx.Call(
		file.Fd(),
		uintptr(daemonLockfileExclusiveLock|daemonLockfileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		if errors.Is(callErr, daemonErrorLockViolation) {
			return nil, errDaemonStateLockBusy
		}
		return nil, callErr
	}
	return file, nil
}

func daemonPlatformUnlock(file *os.File) error {
	var overlapped daemonOverlapped
	result, _, callErr := daemonProcUnlockFileEx.Call(
		file.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	closeErr := file.Close()
	if result == 0 && callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
		return callErr
	}
	return closeErr
}
