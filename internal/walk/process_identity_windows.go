//go:build windows

package walk

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const processQueryLimitedInformation = 0x1000

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	openProcess               = kernel32.NewProc("OpenProcess")
	closeHandle               = kernel32.NewProc("CloseHandle")
	queryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	getProcessTimes           = kernel32.NewProc("GetProcessTimes")
)

func inspectProcess(pid int) (ProcessIdentity, error) {
	handle, _, callErr := openProcess.Call(processQueryLimitedInformation, 0, uintptr(uint32(pid)))
	if handle == 0 {
		return ProcessIdentity{}, fmt.Errorf("OpenProcess(%d): %w", pid, callErr)
	}
	defer closeHandle.Call(handle) //nolint:errcheck // process handle cleanup has no actionable recovery

	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, callErr := queryFullProcessImageName.Call(handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return ProcessIdentity{}, fmt.Errorf("QueryFullProcessImageNameW(%d): %w", pid, callErr)
	}

	var creation, exit, kernel, user syscall.Filetime
	ok, _, callErr = getProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ok == 0 {
		return ProcessIdentity{}, fmt.Errorf("GetProcessTimes(%d): %w", pid, callErr)
	}
	creationTicks := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	return ProcessIdentity{
		PID:        pid,
		Executable: syscall.UTF16ToString(buffer[:size]),
		StartTicks: strconv.FormatUint(creationTicks, 10),
	}, nil
}

func sameExecutable(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func sameProcessIdentity(left, right ProcessIdentity) bool {
	return left.PID == right.PID && sameExecutable(left.Executable, right.Executable) && left.StartTicks == right.StartTicks
}
