package kernel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/tuning"
)

// readableExtra are read-only helpers the Tuning page uses to tell what the
// kernel supports; they are not tunables.
var readableExtra = map[string]bool{
	"net.ipv4.tcp_available_congestion_control": true,
	"net.core.available_qdisc":                  true,
}

var keyRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// checkSysctlKey only lets through keys from the catalogue. A key is a path
// under /proc/sys, so anything else (and any odd character) is refused.
func checkSysctlKey(key string, write bool) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("%q is not a valid setting name", key)
	}
	for _, s := range tuning.Catalog {
		for _, k := range s.Keys {
			if k == key {
				return nil
			}
		}
	}
	if !write && readableExtra[key] {
		return nil
	}
	return fmt.Errorf("%s is not a setting mini-net-man manages", key)
}

// sysctlPath maps "net.ipv4.tcp_mtu_probing" to /proc/sys/net/ipv4/tcp_mtu_probing.
func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

// ModuleFor names the kernel module that provides a value, for the settings
// whose values are loadable (a TCP congestion control, a queue discipline).
func ModuleFor(key, value string) string {
	switch key {
	case "net.ipv4.tcp_congestion_control":
		return "tcp_" + value
	case "net.core.default_qdisc":
		return "sch_" + value
	}
	return ""
}
