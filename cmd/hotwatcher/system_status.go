package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type xkeenStatus struct {
	Installed    bool      `json:"installed"`
	CommandOK    bool      `json:"command_ok"`
	Status       []string  `json:"status"`
	DetachedLog  []string  `json:"detached_log"`
	XrayErrorLog []string  `json:"xray_error_log"`
	CheckedAt    time.Time `json:"checked_at"`
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
	result := xkeenStatus{CheckedAt: time.Now().UTC()}
	result.DetachedLog = tailLog("/opt/var/log/xkeen-detached.log")
	result.XrayErrorLog = tailLog("/opt/var/log/xray/error.log")
	info, err := os.Lstat(xkeenCommand)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		result.Status = []string{"Исполняемый файл XKeen не найден"}
		return result
	}
	result.Installed = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xkeenCommand, "-status")
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
