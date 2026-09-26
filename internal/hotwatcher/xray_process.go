package hotwatcher

import (
	"path/filepath"
	"strings"
)

// IsXrayServerCommand distinguishes the production server from Xray's API
// helper, validation commands and temporary probe servers.
func IsXrayServerCommand(args []string, binary, stateDir string) bool {
	if len(args) == 0 || filepath.Base(args[0]) != filepath.Base(binary) {
		return false
	}
	if len(args) > 1 && args[1] != "run" && !strings.HasPrefix(args[1], "-") {
		return false
	}
	statePrefix := filepath.Clean(stateDir) + string(filepath.Separator)
	for _, arg := range args[1:] {
		if arg == "-test" || arg == "--test" || strings.HasPrefix(arg, "-test=") || strings.HasPrefix(arg, "--test=") || arg == "-version" || arg == "--version" || arg == "-h" || arg == "--help" {
			return false
		}
		if _, value, found := strings.Cut(arg, "="); found {
			arg = value
		}
		if stateDir != "" && strings.HasPrefix(filepath.Clean(arg), statePrefix) {
			return false
		}
	}
	return true
}
