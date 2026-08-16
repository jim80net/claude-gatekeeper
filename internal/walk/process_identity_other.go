//go:build !linux && !windows

package walk

import "fmt"

func inspectProcess(pid int) (ProcessIdentity, error) {
	return ProcessIdentity{}, fmt.Errorf("native process identity is unsupported on this platform for PID %d", pid)
}

func sameExecutable(left, right string) bool {
	return left == right
}

func sameProcessIdentity(left, right ProcessIdentity) bool {
	return left.PID == right.PID && sameExecutable(left.Executable, right.Executable) && left.StartTicks == right.StartTicks
}
