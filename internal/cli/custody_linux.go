package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procStart is field 22 of /proc/<pid>/stat: start time in clock ticks
// since boot. fs.ErrNotExist when the pid is absent.
func procStart(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	// The command name (field 2) may hold spaces; fields restart after its last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if f := strings.Fields(string(b[i+1:])); i >= 0 && len(f) > 19 {
		return f[19], nil
	}
	return "", fmt.Errorf("/proc/%d/stat: malformed", pid)
}

func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), err
}
