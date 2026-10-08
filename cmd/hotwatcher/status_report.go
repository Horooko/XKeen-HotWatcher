package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const reportLogLimit = 256 * 1024

type reportSection struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

type statusReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Sections    []reportSection `json:"sections"`
	Text        string          `json:"text"`
}

var (
	reportIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reportIPv6   = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:%[a-z0-9_.-]+)?`)
	reportDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b`)
	reportLong   = regexp.MustCompile(`\b[A-Za-z0-9_+/=-]{32,}\b`)
	reportField  = regexp.MustCompile(`(?i)("?(?:password|publickey|shortid|serverName|address|host|token|secret|uuid|pbk)"?\s*[:=]\s*"?)[^",\s}]+`)
)

// Reports may be shared for diagnosis. Use a stricter sanitizer than the live
// System panel: server addresses and long opaque credential strings are hidden.
func safeReportLine(line string) string {
	line = safeStatusLine(line)
	line = reportIPv4.ReplaceAllString(line, "[IP скрыт]")
	line = reportIPv6.ReplaceAllStringFunc(line, func(candidate string) string {
		if net.ParseIP(strings.SplitN(candidate, "%", 2)[0]) != nil {
			return "[IP скрыт]"
		}
		return candidate
	})
	line = reportDomain.ReplaceAllString(line, "[домен скрыт]")
	line = reportField.ReplaceAllString(line, "${1}[значение скрыто]")
	line = reportLong.ReplaceAllString(line, "[значение скрыто]")
	return line
}

func reportLines(lines ...string) []string {
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if clean := safeReportLine(line); clean != "" {
			result = append(result, clean)
		}
	}
	return result
}

func (r *statusReport) add(title string, lines ...string) {
	clean := reportLines(lines...)
	if len(clean) == 0 {
		clean = []string{"Нет данных"}
	}
	r.Sections = append(r.Sections, reportSection{Title: title, Lines: clean})
}

func (r *statusReport) finish() {
	var b strings.Builder
	fmt.Fprintf(&b, "Hot Watcher — диагностический отчёт\nДата UTC: %s\n", r.GeneratedAt.Format(time.RFC3339))
	for _, section := range r.Sections {
		fmt.Fprintf(&b, "\n=== %s ===\n", section.Title)
		for _, line := range section.Lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	r.Text = b.String()
}

func fixedReadCommand(parent context.Context, command string, args ...string) []string {
	info, err := os.Stat(command)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return []string{"Исполняемый файл недоступен"}
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = entwareStatusEnv()
	cmd.Stdin = nil
	cmd.WaitDelay = 250 * time.Millisecond
	output := &cappedOutput{max: 16 * 1024}
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	lines := reportLines(strings.Split(output.buf.String(), "\n")...)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		lines = append(lines, "Команда превысила 6 секунд")
	} else if err != nil {
		lines = append(lines, "Команда завершилась с ошибкой")
	}
	if len(lines) == 0 {
		lines = []string{"Команда не вернула вывод"}
	}
	return lines
}

// Read the currently available complete file up to reportLogLimit. The size
// marker is part of the exported report so a tail is never mistaken for a full
// historical journal. No symlinks or unbounded file reads are permitted.
func boundedReportLog(path string) []string {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return []string{"Файл журнала отсутствует"}
	}
	if err != nil || !info.Mode().IsRegular() {
		return []string{"Файл журнала недоступен или небезопасен"}
	}
	f, err := os.Open(path)
	if err != nil {
		return []string{"Файл журнала не читается"}
	}
	defer f.Close()
	start := info.Size() - reportLogLimit
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return []string{"Файл журнала не читается"}
	}
	b, err := io.ReadAll(io.LimitReader(f, reportLogLimit))
	if err != nil {
		return []string{"Файл журнала не читается"}
	}
	lines := []string{fmt.Sprintf("Размер файла: %d байт; включено: не более %d байт. Секреты скрыты; строки длиннее 240 символов усечены.", info.Size(), reportLogLimit)}
	if start > 0 {
		lines = append(lines, "Начало журнала усечено из-за лимита 256 КиБ")
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	if len(b) == 0 {
		return append(lines, "Журнал пуст")
	}
	for _, part := range bytes.Split(b, []byte{'\n'}) {
		if clean := safeReportLine(string(part)); clean != "" {
			lines = append(lines, clean)
		}
	}
	return lines
}

type processBrief struct {
	PID  int
	Name string
	Role string
}

func reportProcesses(procDir, xrayBinary, configDir, stateDir string) []string {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return []string{"/proc недоступен; процессы не определены"}
	}
	list := make([]processBrief, 0, min(len(entries), 512))
	count := map[string]int{}
	omitted := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		nameBytes, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(nameBytes))
		if len(name) > 32 || name == "" {
			name = "[имя скрыто]"
		}
		name = safeReportLine(name)
		count[name]++
		if len(list) >= 512 {
			omitted++
			continue
		}
		role := ""
		if strings.Contains(strings.ToLower(name), "xray") || strings.Contains(strings.ToLower(name), "hotwatcher") {
			role = "процесс программы"
			f, err := os.Open(filepath.Join(procDir, entry.Name(), "cmdline"))
			var b []byte
			if err == nil {
				b, err = io.ReadAll(io.LimitReader(f, 2049))
				_ = f.Close()
			}
			if err == nil && len(b) <= 2048 {
				args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
				if hw.IsXrayServerCommand(args, xrayBinary, configDir, stateDir) {
					role = "основной Xray"
				} else if len(args) > 1 && filepath.Base(args[0]) == filepath.Base(xrayBinary) && args[1] == "api" {
					role = "клиент Xray API"
				} else if strings.Contains(strings.ToLower(name), "xray") {
					role = "вспомогательный Xray или команда"
				}
			}
		}
		list = append(list, processBrief{PID: pid, Name: name, Role: role})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].PID < list[j].PID })
	lines := []string{fmt.Sprintf("Процессов прочитано: %d; не включено из-за лимита: %d", len(list), omitted)}
	dupes := make([]string, 0)
	for name, n := range count {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s: %d", name, n))
		}
	}
	sort.Strings(dupes)
	if len(dupes) > 0 {
		lines = append(lines, "Повторяющиеся имена процессов: "+strings.Join(dupes, ", "))
	}
	serverCount := 0
	for _, item := range list {
		if item.Role == "основной Xray" {
			serverCount++
		}
		line := fmt.Sprintf("PID %d  %s", item.PID, item.Name)
		if item.Role != "" {
			line += "  — " + item.Role
		}
		lines = append(lines, line)
	}
	lines = append(lines, fmt.Sprintf("Основных процессов Xray: %d", serverCount))
	return lines
}

func (w *webUI) generateStatusReport(ctx context.Context) statusReport {
	report := statusReport{GeneratedAt: time.Now().UTC()}
	report.add("Пояснение", "API, корректный конфиг и HTTPS-проба выбранного ключа не доказывают прохождение трафика ПК через маршрутизацию XKeen.")
	report.add("Версии", "Hot Watcher: "+hw.Version, "Xray: "+strings.Join(fixedReadCommand(ctx, w.config.XrayBinary, "version"), " | "))
	status, statusErr, _ := w.health.snapshot()
	keys := []string{"adopted", "active_nodes", "selected", "selection_mode", "selected_present", "runtime_override", "api_reachable", "balancer_api_reachable", "balancer_pin_matches", "disk_matches_state", "pending_transaction", "hold", "outbound_mark", "api_checked_at", "last_applied_utc"}
	statusLines := make([]string, 0, len(keys)+2)
	if statusErr != nil {
		statusLines = append(statusLines, "Снимок состояния содержит ошибку")
	}
	if status == nil {
		statusLines = append(statusLines, "Снимок состояния ещё не готов")
	}
	for _, key := range keys {
		if value, ok := status[key]; ok {
			statusLines = append(statusLines, fmt.Sprintf("%s: %v", key, value))
		}
	}
	report.add("Состояние Hot Watcher (последний фоновый снимок)", statusLines...)
	if activity, err := hw.ActivityStatus(w.config); err == nil {
		lines := []string{fmt.Sprintf("busy: %v; PID: %d; операция: %s; длительность: %d сек; фон приостановлен: %v", activity.Lock.Busy, activity.Lock.PID, activity.Lock.Operation, activity.ElapsedSeconds, activity.BackgroundPaused), activity.Message}
		w.mu.Lock()
		job := w.job
		w.mu.Unlock()
		if job.State == "running" {
			lines = append(lines, fmt.Sprintf("Задача панели: %s; ID: %d; длительность: %d сек", job.Action, job.ID, max(0, int64(time.Since(job.StartedAt).Seconds()))))
		}
		report.add("Текущая операция", lines...)
	} else {
		report.add("Текущая операция", "Состояние операции недоступно")
	}
	if recovery, err := w.engine.RecoveryStatus(); err == nil {
		lines := []string{fmt.Sprintf("Незавершённая транзакция: %v", recovery.PendingTransaction), recovery.SuggestedCommand}
		if recovery.HardSync != nil {
			lines = append(lines, "Сохранённый hard-sync: этап "+recovery.HardSync.Stage, "Обновлён: "+recovery.HardSync.UpdatedAt.Format(time.RFC3339))
		}
		report.add("Восстановление", lines...)
	} else {
		report.add("Восстановление", "Состояние восстановления недоступно")
	}
	if dns, err := w.engine.DNSStatus(); err == nil {
		report.add("DNS Xray", fmt.Sprintf("Автонастройка Hot Watcher: %v; параллельные запросы: %v; запуск текущего DNS в Xray не подтверждён: %v", dns.Managed, dns.ParallelQueries, dns.RuntimeActivationUnverified), fmt.Sprintf("Серверов в конфиге: %d; автоподбор: %v", len(dns.Servers), dns.AutoSelectionEnabled), "Выбраны в интерфейсе: "+strings.Join(dns.SelectedProviderIDs, ", "), "Записаны в DNS: "+strings.Join(dns.AppliedProviderIDs, ", "), dns.Note)
	} else {
		report.add("DNS Xray", "Состояние DNS недоступно")
	}
	lan := readLANInterception(ctx, w.config.ConfigDir)
	lanLines := make([]string, 0, 4)
	for _, item := range []struct {
		name string
		path lanInterceptionPath
	}{{"TCP IPv4", lan.TCP}, {"UDP IPv4", lan.UDP}, {"TCP IPv6", lan.TCPIPv6}, {"UDP IPv6", lan.UDPIPv6}} {
		lanLines = append(lanLines, fmt.Sprintf("%s: известно=%v; правило=%v; порт=%d; входящих=%d; перенаправлено=%d; причина=%s", item.name, item.path.Known, item.path.Present, item.path.ExpectedPort, item.path.IngressPackets, item.path.RedirectedPackets, item.path.Missing))
	}
	report.add("Перехват LAN (счётчики накопительные)", lanLines...)
	report.add("Netfilter XKeen (независимая проверка)", firewallEvidence(ctx, w.config.ConfigDir)...)
	report.add("Сокеты входов Xray", transparentListenerReport(lan.TCP.ExpectedPort, lan.UDP.ExpectedPort)...)
	report.add("Маршруты трафика LAN в Xray", routingSummary(w.config.ConfigDir)...)
	ipBinary := findIPTablesSave("ip")
	if ipBinary == "" {
		report.add("Политика маршрутизации", "Утилита ip недоступна")
	} else {
		routeLines := []string{"IPv4 rules:"}
		routeLines = append(routeLines, fixedReadCommand(ctx, ipBinary, "-4", "rule", "show")...)
		routeLines = append(routeLines, "IPv4 routes:")
		routeLines = append(routeLines, fixedReadCommand(ctx, ipBinary, "-4", "route", "show")...)
		routeLines = append(routeLines, "IPv4 table 111 (fwmark 0x111):")
		routeLines = append(routeLines, fixedReadCommand(ctx, ipBinary, "-4", "route", "show", "table", "111")...)
		routeLines = append(routeLines, "IPv6 rules:")
		routeLines = append(routeLines, fixedReadCommand(ctx, ipBinary, "-6", "rule", "show")...)
		routeLines = append(routeLines, "IPv6 table 111 (fwmark 0x111):")
		routeLines = append(routeLines, fixedReadCommand(ctx, ipBinary, "-6", "route", "show", "table", "111")...)
		report.add("Политика маршрутизации", routeLines...)
	}
	report.add("Процессы /proc", reportProcesses("/proc", w.config.XrayBinary, w.config.ConfigDir, w.config.StateDir)...)
	report.add("XKeen -status", fixedReadCommand(ctx, xkeenCommand, "-status")...)
	report.add("XKeen -pbr status", fixedReadCommand(ctx, xkeenCommand, "-pbr", "status")...)
	report.add("Проксирование Entware XKeen", readXKeenEntwareProxyMode().Lines...)
	report.add("XKeen -xtest (только синтаксис)", fixedReadCommand(ctx, xkeenCommand, "-xtest")...)
	if last, err := w.engine.LastURLTest(); err == nil && last != nil {
		lines := []string{fmt.Sprintf("Дата: %s; успешен: %v; сайтов: %d", last.Time.Format(time.RFC3339), last.Passed, len(last.Results))}
		for _, result := range last.Results {
			lines = append(lines, fmt.Sprintf("%s: ok=%v; status=%d; причина=%s", result.Site, result.OK, result.Status, result.Reason))
		}
		report.add("Последний URL Test (сохранённый, не новый)", lines...)
	} else {
		report.add("Последний URL Test", "Нет сохранённого результата")
	}
	if latency, err := w.engine.SelectedIsolatedHTTPSProbe(); err == nil {
		report.add("Выбранный ключ", fmt.Sprintf("HTTPS-проба через отдельный временный Xray: %d мс", latency.Milliseconds()), "Проверка не измеряет ICMP ping и не подтверждает маршрут с ПК через LAN.")
	} else {
		report.add("Выбранный ключ", "HTTPS-проба через отдельный временный Xray неуспешна или недоступна", "Проверка не переключала ключи и не меняла работающий Xray.")
	}
	logs := readXrayLogSettings(w.config.ConfigDir)
	if !logs.ConfigKnown {
		report.add("Журнал Xray", "Настройки журнала не удалось прочитать")
	} else {
		if logs.Level == "none" {
			report.add("Журнал Xray", "Журналирование Xray выключено в конфигурации (loglevel: none); новые события подключения не записываются. Ниже доступны существующие файлы журнала, если они остались.")
		} else {
			report.add("Журнал Xray", "Уровень: "+logs.Level)
		}
		if logs.ErrorPath != "" && logs.ErrorPathKnown {
			report.add("Журнал ошибок Xray", boundedReportLog(logs.ErrorPath)...)
		} else {
			report.add("Журнал ошибок Xray", "Путь не задан или небезопасен")
		}
		if logs.AccessPath != "" && logs.AccessPathKnown {
			report.add("Журнал доступа Xray", boundedReportLog(logs.AccessPath)...)
		} else {
			report.add("Журнал доступа Xray", "Путь не задан или небезопасен")
		}
	}
	report.add("Журнал запуска XKeen", boundedReportLog("/opt/var/log/xkeen-detached.log")...)
	report.add("Журнал Hot Watcher", boundedReportLog(filepath.Join(w.config.StateDir, "events.jsonl"))...)
	report.finish()
	return report
}
