package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type xkeenStatus struct {
	Installed           bool      `json:"installed"`
	CommandOK           bool      `json:"command_ok"`
	Status              []string  `json:"status"`
	DetachedLog         []string  `json:"detached_log"`
	XrayErrorLog        []string  `json:"xray_error_log"`
	XrayAccessLog       []string  `json:"xray_access_log"`
	XrayLogLevel        string    `json:"xray_log_level,omitempty"`
	XrayErrorPath       string    `json:"xray_error_path,omitempty"`
	XrayAccessPath      string    `json:"xray_access_path,omitempty"`
	XrayLogConfigKnown  bool      `json:"xray_log_config_known"`
	XrayErrorPathKnown  bool      `json:"xray_error_path_known"`
	XrayAccessPathKnown bool      `json:"xray_access_path_known"`
	CheckedAt           time.Time `json:"checked_at"`
	XrayRunning         *bool     `json:"xray_running"`
}

type startupCommandResult struct {
	OK    bool     `json:"ok"`
	Lines []string `json:"lines"`
}

type startupCheckResult struct {
	ConfigTest   startupCommandResult `json:"config_test"`
	PBRStatus    startupCommandResult `json:"pbr_status"`
	ProxyStatus  startupCommandResult `json:"proxy_status"`
	OutboundMark int                  `json:"outbound_mark"`
}

// These fixed XKeen commands inspect startup prerequisites without changing the
// router. -xtest checks Xray syntax; XKeen's strict PBR runs separately at start.
func readStartupCommand(parent context.Context, command string, args ...string) startupCommandResult {
	result := startupCommandResult{}
	info, err := os.Stat(command)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		result.Lines = []string{"Исполняемый файл XKeen не найден"}
		return result
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = entwareStatusEnv()
	cmd.WaitDelay = 250 * time.Millisecond
	output := &cappedOutput{max: 8192}
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	result.OK = err == nil
	result.Lines = safeLines(output.buf.String(), 15)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Lines = append(result.Lines, "Команда превысила 15 секунд")
	} else if err != nil && len(result.Lines) == 0 {
		result.Lines = []string{"Команда завершилась с ошибкой без вывода"}
	}
	return result
}

func checkXKeenStartup(parent context.Context, outboundMark int) startupCheckResult {
	return startupCheckResult{
		ConfigTest:   readStartupCommand(parent, xkeenCommand, "-xtest"),
		PBRStatus:    readStartupCommand(parent, xkeenCommand, "-pbr", "status"),
		ProxyStatus:  readStartupCommand(parent, xkeenCommand, "-pr", "status"),
		OutboundMark: outboundMark,
	}
}

func startupCheckError(result startupCheckResult) error {
	if !result.ConfigTest.OK {
		return errors.New("xkeen -xtest не прошёл; конфигурация Xray требует проверки")
	}
	if !result.PBRStatus.OK || !result.ProxyStatus.OK {
		return errors.New("не все проверки условий запуска XKeen завершились успешно; см. детали")
	}
	return nil
}

var (
	ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	secretURI  = regexp.MustCompile(`(?i)(vless|trojan|vmess|ss)://\S+`)
	uuidText   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	webURL     = regexp.MustCompile(`(?i)https?://\S+`)
	queryKey   = regexp.MustCompile(`(?i)\b(token|password|pbk|sid|uuid|secret)=\S+`)
	bearerKey  = regexp.MustCompile(`(?i)\b(bearer|authorization:|api[_-]?key:?)\s+\S+`)
)

func safeStatusLine(line string) string {
	line = ansiEscape.ReplaceAllString(line, "")
	line = secretURI.ReplaceAllString(line, "[ключ скрыт]")
	line = webURL.ReplaceAllString(line, "[URL скрыт]")
	line = uuidText.ReplaceAllString(line, "[UUID скрыт]")
	line = queryKey.ReplaceAllString(line, "$1=[скрыто]")
	line = bearerKey.ReplaceAllString(line, "$1 [скрыто]")
	line = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, line)
	runes := []rune(strings.TrimSpace(line))
	if len(runes) > 240 {
		runes = append(runes[:240], '…')
	}
	return string(runes)
}

func safeLines(text string, max int) []string {
	parts := strings.Split(text, "\n")
	if len(parts) > max {
		parts = parts[len(parts)-max:]
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if line := safeStatusLine(part); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func tailLog(path string) []string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	start := info.Size() - 64*1024
	if start < 0 {
		start = 0
	}
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return nil
	}
	if start > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return safeLines(string(b), 30)
}

type xrayLogSettings struct {
	Level           string
	ErrorPath       string
	AccessPath      string
	ConfigKnown     bool
	ErrorPathKnown  bool
	AccessPathKnown bool
}

const (
	maxXrayConfigEntries   = 128
	maxXrayLogFragments    = 64
	maxXrayLogFragmentSize = 1024 * 1024
	maxXrayLogConfigBytes  = 8 * 1024 * 1024
)

// Xray loads .json fragments in lexical order. Apply only explicit log fields
// from each fragment so the panel follows later overrides without reading the
// whole (potentially subscription-bearing) configuration into its response.
func readXrayLogSettings(configDir string) xrayLogSettings {
	settings := xrayLogSettings{ErrorPath: "/opt/var/log/xray/error.log", AccessPath: "/opt/var/log/xray/access.log", ConfigKnown: true, ErrorPathKnown: true, AccessPathKnown: true}
	dir, err := os.Open(configDir)
	if err != nil {
		return xrayLogSettings{}
	}
	defer dir.Close()
	// File.ReadDir bounds enumeration; os.ReadDir(path) loads and sorts
	// every entry before we could enforce the limit.
	entries, err := dir.ReadDir(maxXrayConfigEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return xrayLogSettings{}
	}
	if len(entries) > maxXrayConfigEntries {
		return xrayLogSettings{}
	}
	names := make([]string, 0, len(entries))
	files := make(map[string]os.FileInfo, len(entries))
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue // Do not follow symlinks or read special files as fragments.
		}
		names = append(names, entry.Name())
		files[entry.Name()] = info
		if len(names) > maxXrayLogFragments {
			return xrayLogSettings{}
		}
	}
	sort.Strings(names)
	totalBytes := 0
	for _, name := range names {
		f, err := os.Open(filepath.Join(configDir, name))
		if err != nil {
			continue
		}
		openedInfo, err := f.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(files[name], openedInfo) {
			_ = f.Close()
			continue // Reject a fragment replaced after directory enumeration.
		}
		// A fragment with a huge embedded ruleset must not stall health polling.
		b, readErr := io.ReadAll(io.LimitReader(f, maxXrayLogFragmentSize+1))
		_ = f.Close()
		totalBytes += len(b)
		if totalBytes > maxXrayLogConfigBytes {
			return xrayLogSettings{}
		}
		if readErr != nil || len(b) > maxXrayLogFragmentSize {
			continue
		}
		var fragment struct {
			Log map[string]json.RawMessage `json:"log"`
		}
		if hw.DecodeXrayJSONC(b, &fragment) != nil || fragment.Log == nil {
			continue
		}
		for key, dest := range map[string]struct {
			path  *string
			known *bool
		}{
			"error":  {&settings.ErrorPath, &settings.ErrorPathKnown},
			"access": {&settings.AccessPath, &settings.AccessPathKnown},
		} {
			var value string
			if raw, ok := fragment.Log[key]; ok {
				// An explicit later setting supersedes an earlier path even when
				// the panel cannot safely resolve that path.
				*dest.path = ""
				*dest.known = false
				if json.Unmarshal(raw, &value) == nil {
					if clean, valid := xrayLogPath(value); valid {
						*dest.path = clean
						*dest.known = true
					}
				}
			}
		}
		var level string
		if raw, ok := fragment.Log["loglevel"]; ok && json.Unmarshal(raw, &level) == nil {
			switch level {
			case "debug", "info", "warning", "error", "none":
				settings.Level = level
			}
		}
	}
	return settings
}

// Xray accepts absolute POSIX paths or "none" for disabled file output.
// Relative paths are not followed by the panel because its working directory
// may differ from the Xray process.
func xrayLogPath(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "none") {
		return "", true
	}
	if !strings.HasPrefix(value, "/") || strings.ContainsRune(value, 0) || len(value) > 1024 {
		return "", false
	}
	return path.Clean(value), true
}

func readXrayLogLevel(configDir string) string { return readXrayLogSettings(configDir).Level }

type cappedOutput struct {
	buf bytes.Buffer
	max int
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	if remaining := w.max - w.buf.Len(); remaining > 0 {
		_, _ = w.buf.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}

func readXKeenStatus() xkeenStatus {
	return readXKeenStatusContext(context.Background())
}

func readXKeenStatusContext(parent context.Context) xkeenStatus {
	return readXKeenStatusCommand(parent, xkeenCommand)
}

func readXKeenStatusCommand(parent context.Context, command string) xkeenStatus {
	return readXKeenStatusCommandWithConfig(parent, command, "/opt/etc/xray/configs")
}

func readXKeenStatusCommandWithConfig(parent context.Context, command, configDir string) xkeenStatus {
	result := xkeenStatus{CheckedAt: time.Now().UTC()}
	logs := readXrayLogSettings(configDir)
	result.XrayLogLevel = logs.Level
	result.XrayErrorPath = safeStatusLine(logs.ErrorPath)
	result.XrayAccessPath = safeStatusLine(logs.AccessPath)
	result.XrayLogConfigKnown = logs.ConfigKnown
	result.XrayErrorPathKnown = logs.ErrorPathKnown
	result.XrayAccessPathKnown = logs.AccessPathKnown
	result.DetachedLog = tailLog("/opt/var/log/xkeen-detached.log")
	if logs.Level != "none" && logs.ErrorPath != "" {
		result.XrayErrorLog = tailLog(logs.ErrorPath)
	}
	if logs.AccessPath != "" {
		result.XrayAccessLog = tailLog(logs.AccessPath)
	}
	// XKeen may be installed as an executable symlink.
	info, err := os.Stat(command)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		result.Status = []string{"Исполняемый файл XKeen не найден"}
		return result
	}
	result.Installed = true
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, "-status")
	cmd.Env = entwareStatusEnv()
	cmd.WaitDelay = 250 * time.Millisecond
	output := &cappedOutput{max: 8192}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.Stdin = nil
	err = cmd.Run()
	result.CommandOK = err == nil
	result.Status = safeLines(output.buf.String(), 30)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status = append(result.Status, "Команда xkeen -status превысила 5 секунд")
	} else if err != nil && len(result.Status) == 0 {
		result.Status = []string{"Не удалось получить статус XKeen"}
	}
	return result
}
