//go:build linux

package walk

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func inspectProcess(pid int) (ProcessIdentity, error) {
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	executable, err := os.Readlink(filepath.Join(proc, "exe"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	stat, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 0 {
		return ProcessIdentity{}, errors.New("unrecognized /proc stat")
	}
	fields := strings.Fields(string(stat)[closing+1:])
	if len(fields) <= 19 {
		return ProcessIdentity{}, errors.New("short /proc stat")
	}
	return ProcessIdentity{PID: pid, Executable: executable, StartTicks: fields[19]}, nil
}

func sameExecutable(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func sameProcessIdentity(left, right ProcessIdentity) bool {
	return left.PID == right.PID && sameExecutable(left.Executable, right.Executable) && left.StartTicks == right.StartTicks
}
