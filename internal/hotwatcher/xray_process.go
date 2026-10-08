package hotwatcher

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IsXrayServerCommand accepts XKeen's `xray run` and an explicit production
// confdir, but never an API client, validator, or temporary single-file Xray.
// The command line alone cannot prove that traffic is flowing through Xray.
func IsXrayServerCommand(args []string, binary, configDir, stateDir string) bool {
	if len(args) < 2 || filepath.Base(args[0]) != filepath.Base(binary) {
		return false
	}
	first := 1
	if args[1] == "run" {
		first = 2
	} else if !strings.HasPrefix(args[1], "-") {
		return false
	}
	for i := first; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-test" || arg == "--test" || strings.HasPrefix(arg, "-test=") || strings.HasPrefix(arg, "--test="),
			arg == "-version" || arg == "--version" || arg == "-h" || arg == "--help":
			return false
		case arg == "-config" || arg == "--config" || arg == "-c" ||
			strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-c="):
			// XKeen uses a config directory. A single-file `run` is an auxiliary
			// probe, regardless of which directory contains that file.
			return false
		case arg == "-confdir" || arg == "--confdir":
			i++
			if i >= len(args) || !sameDirectory(args[i], configDir) {
				return false
			}
		case strings.HasPrefix(arg, "-confdir=") || strings.HasPrefix(arg, "--confdir="):
			_, value, _ := strings.Cut(arg, "=")
			if !sameDirectory(value, configDir) {
				return false
			}
		default:
			if stateDir != "" && pathWithin(arg, stateDir) {
				return false
			}
		}
	}
	return true
}

func sameDirectory(path, expected string) bool {
	return expected != "" && filepath.IsAbs(path) && filepath.Clean(path) == filepath.Clean(expected)
}

func pathWithin(path, dir string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	root := filepath.Clean(dir)
	return clean == root || strings.HasPrefix(clean, root+string(filepath.Separator))
}

// XrayServerRunning inspects /proc without starting an `xray api` helper.
// An unreadable process list is reported as an error so callers can avoid
// contacting the API when the production server's state is uncertain.
func XrayServerRunning(procDir, binary, configDir, stateDir string) (bool, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false, err
	}
	var uncertain bool
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "cmdline"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				uncertain = true
			}
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if IsXrayServerCommand(args, binary, configDir, stateDir) {
			return true, nil
		}
	}
	if uncertain {
		return false, errors.New("one or more process command lines could not be inspected")
	}
	return false, nil
}

// StatusWithProductionXray avoids even a short-lived `xray api` process while
// XKeen's server is stopped. XKeen's pidof guard may mistake that API helper
// for the server and refuse a subsequent start.
func StatusWithProductionXray(c Config, procDir string) (map[string]any, error) {
	e := New(c)
	running, err := XrayServerRunning(procDir, c.XrayBinary, c.ConfigDir, c.StateDir)
	if err != nil || !running {
		return e.StatusWithoutRuntime()
	}
	return e.Status()
}
