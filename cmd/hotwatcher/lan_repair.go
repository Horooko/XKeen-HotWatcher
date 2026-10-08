package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	xkeenReadyMarker = "/tmp/.xkeen/ready"
)

// LAN repair is an explicit WebUI action. It runs XKeen's own rule generator;
// Hot Watcher never writes its own iptables rules or calls xkeen -restart.
// If Xray exits in the narrow gap before xkeen -start, XKeen may start it;
// the postcheck detects a changed main PID and reports this as a failure.
type lanRepairResult struct {
	Mode          string                `json:"mode"`
	MainXrayPID   int                   `json:"main_xray_pid"`
	Before        lanInterceptionStatus `json:"before"`
	After         lanInterceptionStatus `json:"after"`
	SyslogBefore  []string              `json:"syslog_before"`
	SyslogAfter   []string              `json:"syslog_after"`
	CommandOutput []string              `json:"command_output"`
	Recovered     bool                  `json:"recovered"`
}

type lanRepairDeps struct {
	procDir    string
	netDir     string
	hookPath   string
	readyPath  string
	xkeenPath  string
	shellPath  string
	findTool   func(string) string
	readLAN    func(context.Context, string) lanInterceptionStatus
	captureLog func(context.Context) []string
	runCommand func(context.Context, string, ...string) ([]string, error)
}

func productionLANRepairDeps() lanRepairDeps {
	return lanRepairDeps{
		procDir:    "/proc",
		netDir:     "/proc/net",
		hookPath:   xkeenNetfilterHook,
		readyPath:  xkeenReadyMarker,
		xkeenPath:  xkeenCommand,
		shellPath:  "/bin/sh",
		findTool:   findIPTablesSave,
		readLAN:    readLANInterception,
		captureLog: xkeenSyslogEvidence,
		runCommand: runLANRepairCommand,
	}
}

func (w *webUI) repairLAN(parent context.Context) (lanRepairResult, error) {
	ctx, cancel := context.WithTimeout(parent, 75*time.Second)
	defer cancel()
	return runLANRepair(ctx, w.config, productionLANRepairDeps())
}

func runLANRepair(ctx context.Context, config hw.Config, deps lanRepairDeps) (lanRepairResult, error) {
	result := lanRepairResult{}
	if ctx.Err() != nil {
		return result, errors.New("восстановление LAN отменено до запуска")
	}
	tcpPort, udpPort := transparentPorts(config.ConfigDir)
	if tcpPort == 0 || udpPort == 0 {
		return result, errors.New("в конфигурации Xray не найдены оба прозрачных входа TCP/UDP; правила не менялись")
	}
	for _, tool := range []string{"iptables", "iptables-save", "iptables-restore"} {
		if deps.findTool(tool) == "" {
			return result, fmt.Errorf("утилита %s недоступна в PATH XKeen; правила не менялись", tool)
		}
	}
	needIPv6 := nonLoopbackIPv6Active(deps.netDir)
	if needIPv6 {
		for _, tool := range []string{"ip6tables", "ip6tables-save", "ip6tables-restore"} {
			if deps.findTool(tool) == "" {
				return result, fmt.Errorf("IPv6 активен, но утилита %s недоступна; правила не менялись", tool)
			}
		}
	}
	if err := validateLANRepairFile(deps.hookPath, true); err != nil {
		return result, fmt.Errorf("netfilter-хук XKeen недоступен: %w; правила не менялись", err)
	}
	if err := validateTrustedShell(deps.shellPath); err != nil {
		return result, errors.New("/bin/sh недоступен; правила не менялись")
	}
	pid, err := exactlyOneMainXray(deps.procDir, config)
	if err != nil {
		return result, fmt.Errorf("невозможно безопасно восстановить LAN: %w; правила не менялись", err)
	}
	result.MainXrayPID = pid
	if err := checkXKeenRepairLocks(deps.procDir, filepath.Dir(deps.readyPath)); err != nil {
		return result, fmt.Errorf("XKeen занят: %w; правила не менялись", err)
	}
	if !transparentPortsListening(deps.netDir, tcpPort, udpPort) {
		return result, errors.New("прозрачные TCP/UDP входы Xray не слушают нужные порты; правила не менялись")
	}
	result.Before = deps.readLAN(ctx, config.ConfigDir)
	if !result.Before.TCP.Known || !result.Before.UDP.Known {
		return result, errors.New("состояние IPv4 netfilter не прочитано; правила не менялись")
	}
	if result.Before.TCP.Present && result.Before.UDP.Present && (!needIPv6 || result.Before.TCPIPv6.Present && result.Before.UDPIPv6.Present) {
		result.After = result.Before
		result.Recovered = true
		result.Mode = "already_present"
		return result, nil
	}
	flags := readXKeenHookFlags(deps.hookPath)
	ready, err := xkeenReadyForRepair(deps.readyPath)
	if err != nil {
		return result, fmt.Errorf("маркер готовности XKeen небезопасен: %w; правила не менялись", err)
	}
	useHook := ready && flags.IPTables && (!needIPv6 || flags.IP6Tables) && flags.Mode == "Hybrid" && flags.RedirectPort == tcpPort && flags.TProxyPort == udpPort
	command := deps.shellPath
	args := []string{deps.hookPath}
	result.Mode = "netfilter_hook"
	if !useHook {
		if err := validateLANRepairFile(deps.xkeenPath, true); err != nil {
			return result, errors.New("XKeen не найден для пересоздания netfilter-хука; правила не менялись")
		}
		command = deps.xkeenPath
		args = []string{"-start"}
		result.Mode = "xkeen_start_existing_xray"
	}
	// Save the relevant syslog lines before xkeen -start can rotate its own log.
	result.SyslogBefore = deps.captureLog(ctx)
	if currentPID, err := exactlyOneMainXray(deps.procDir, config); err != nil || currentPID != pid {
		return result, errors.New("основной процесс Xray изменился перед применением; правила не менялись")
	}
	if err := checkXKeenRepairLocks(deps.procDir, filepath.Dir(deps.readyPath)); err != nil {
		return result, errors.New("XKeen начал другую операцию; правила не менялись")
	}
	runCtx, cancel := context.WithTimeout(ctx, 55*time.Second)
	result.CommandOutput, err = deps.runCommand(runCtx, command, args...)
	cancel()
	result.After = deps.readLAN(ctx, config.ConfigDir)
	result.SyslogAfter = deps.captureLog(ctx)
	currentPID, processErr := exactlyOneMainXray(deps.procDir, config)
	if processErr != nil || currentPID != pid {
		return result, errors.New("после восстановления основной процесс Xray изменился или появились дубли; проверьте отчёт")
	}
	if ctx.Err() != nil || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return result, errors.New("восстановление LAN превысило лимит времени; результат требует проверки")
	}
	if !result.After.TCP.Known || !result.After.UDP.Known || !result.After.TCP.Present || !result.After.UDP.Present {
		return result, errors.New("цепочки XKeen для TCP/UDP IPv4 не появились; Xray не перезапускался, причина может быть в iptables-restore или маркере готовности")
	}
	if needIPv6 && (!result.After.TCPIPv6.Known || !result.After.UDPIPv6.Known || !result.After.TCPIPv6.Present || !result.After.UDPIPv6.Present) {
		return result, errors.New("цепочки XKeen для TCP/UDP IPv6 не появились; проверьте системный журнал и поддержку ip6tables")
	}
	if err != nil {
		// XKeen's existing-Xray branch may report "already running" even after
		// successfully applying its hook. The postcondition is authoritative.
		result.CommandOutput = append(result.CommandOutput, "Команда завершилась с ошибкой, но правила LAN проверены после неё")
	}
	result.Recovered = true
	return result, nil
}

func validateLANRepairFile(path string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 || executable && info.Mode().Perm()&0111 == 0 {
		return errors.New("требуется обычный исполняемый файл")
	}
	return nil
}

func validateTrustedShell(path string) error {
	info, err := os.Stat(path) // BusyBox /bin/sh is commonly a symlink.
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("shell недоступен")
	}
	return nil
}

type xkeenHookFlags struct {
	IPTables     bool
	IP6Tables    bool
	Mode         string
	RedirectPort int
	TProxyPort   int
}

func readXKeenHookFlags(path string) xkeenHookFlags {
	var result xkeenHookFlags
	values := xkeenHookSettings(path)
	result.IPTables = values["iptables_supported"] == "true"
	result.IP6Tables = values["ip6tables_supported"] == "true"
	result.Mode = values["mode_proxy"]
	result.RedirectPort, _ = strconv.Atoi(values["port_redirect"])
	result.TProxyPort, _ = strconv.Atoi(values["port_tproxy"])
	return result
}

func xkeenReadyForRepair(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return false, errors.New("ready не является обычным файлом")
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return false, errors.New("каталог ready недоступен или имеет открытые права")
	}
	return true, nil
}

func exactlyOneMainXray(procDir string, config hw.Config) (int, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return 0, errors.New("/proc недоступен")
	}
	var main []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "comm"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || strings.TrimSpace(string(comm)) != filepath.Base(config.XrayBinary) {
			continue
		}
		f, err := os.Open(filepath.Join(procDir, entry.Name(), "cmdline"))
		if err != nil {
			return 0, errors.New("командная строка процесса Xray не читается")
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		_ = f.Close()
		if err != nil || len(b) > 4096 {
			return 0, errors.New("командная строка процесса Xray недоступна")
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if hw.IsXrayServerCommand(args, config.XrayBinary, config.ConfigDir, config.StateDir) {
			main = append(main, pid)
		}
	}
	if len(main) != 1 {
		return 0, fmt.Errorf("ожидался ровно один основной xray run, найдено %d", len(main))
	}
	return main[0], nil
}

func checkXKeenRepairLocks(procDir, runtimeDir string) error {
	for _, name := range []string{"proxy.mutex.d", "netfilter.lock.d"} {
		path := filepath.Join(runtimeDir, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("состояние блокировки XKeen не определено")
		}
		pidText, err := os.ReadFile(filepath.Join(path, "pid"))
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidText)))
		if err != nil || parseErr != nil || pid <= 0 {
			return errors.New("блокировка XKeen без корректного PID")
		}
		if _, err := os.Stat(filepath.Join(procDir, strconv.Itoa(pid))); err == nil {
			return fmt.Errorf("%s удерживается PID %d", name, pid)
		}
	}
	return nil
}

func transparentPortsListening(netDir string, tcpPort, udpPort int) bool {
	tcp4, ok4 := countPortSockets(filepath.Join(netDir, "tcp"), tcpPort, true)
	tcp6, ok6 := countPortSockets(filepath.Join(netDir, "tcp6"), tcpPort, true)
	udp4, uok4 := countPortSockets(filepath.Join(netDir, "udp"), udpPort, false)
	udp6, uok6 := countPortSockets(filepath.Join(netDir, "udp6"), udpPort, false)
	return (ok4 || ok6) && tcp4+tcp6 > 0 && (uok4 || uok6) && udp4+udp6 > 0
}

func nonLoopbackIPv6Active(netDir string) bool {
	f, err := os.Open(filepath.Join(netDir, "if_inet6"))
	if err != nil {
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		// Match XKeen's check_ipv6_active rather than treating every
		// non-loopback address as a supported IPv6 LAN family.
		if len(fields) >= 6 && fields[3] == "20" && fields[5] != "ezcfg0" && !strings.HasPrefix(fields[5], "t2s") {
			return true
		}
	}
	return false
}

func runLANRepairCommand(parent context.Context, binary string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(parent, binary, args...)
	cmd.Env = entwareStatusEnv()
	if len(args) == 1 && args[0] == "-start" {
		// XKeen otherwise self-detaches without a TTY and returns before its
		// netfilter hook runs, making the postcheck race the real repair.
		cmd.Env = append(cmd.Env, "XKEEN_FOREGROUND=1")
	}
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 500 * time.Millisecond
	output := &cappedOutput{max: 16 * 1024}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	return reportLines(strings.Split(output.buf.String(), "\n")...), err
}
