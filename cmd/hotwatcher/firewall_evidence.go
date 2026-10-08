package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// XKeen resolves iptables through this PATH (see its generated S05xkeen).
// Inspect every installed save frontend: different frontends can expose
// different rule sets, and the normal LAN summary reads only the first one.
var xkeenFirewallPath = []string{"/opt/bin", "/opt/sbin", "/sbin", "/bin", "/usr/sbin", "/usr/bin"}

const xkeenNetfilterHook = "/opt/etc/ndm/netfilter.d/proxy.sh"

var xkeenHookSetting = regexp.MustCompile(`^\s*(iptables_supported|ip6tables_supported|mode_proxy|port_redirect|port_tproxy)=(?:'([^']*)'|"([^"]*)"|([^\s#;]+))\s*(?:#.*)?$`)

// The generated hook can include credentials. Only inspect fixed, harmless
// assignments; never print its source or arbitrary assignment values.
func xkeenHookSettings(path string) map[string]string {
	result := map[string]string{}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 {
		return result
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(b), "\n") {
		match := xkeenHookSetting.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value := match[2] + match[3] + match[4]
		switch match[1] {
		case "iptables_supported", "ip6tables_supported":
			if value == "true" || value == "false" {
				result[match[1]] = value
			}
		case "mode_proxy":
			if value == "Hybrid" || value == "TProxy" || value == "Redirect" || value == "Other" {
				result[match[1]] = value
			}
		case "port_redirect", "port_tproxy":
			if port, err := strconv.Atoi(value); err == nil && port > 0 && port <= 65535 {
				result[match[1]] = value
			}
		}
	}
	return result
}

func xkeenHookPreconditions() []string {
	lines := []string{}
	info, err := os.Lstat("/tmp/.xkeen/ready")
	lines = append(lines, fmt.Sprintf("Маркер /tmp/.xkeen/ready: существует=%v; обычный файл=%v", err == nil, err == nil && info.Mode().IsRegular()))
	settings := xkeenHookSettings(xkeenNetfilterHook)
	for _, name := range []string{"iptables_supported", "ip6tables_supported", "mode_proxy", "port_redirect", "port_tproxy"} {
		value := settings[name]
		if value == "" {
			value = "не найдено или значение неизвестно"
		}
		lines = append(lines, "Хук XKeen "+name+": "+value)
	}
	for _, name := range []string{"iptables", "iptables-restore", "ip6tables", "ip6tables-restore"} {
		lines = append(lines, fmt.Sprintf("%s доступен в PATH XKeen: %v", name, findIPTablesSave(name) != ""))
	}
	return lines
}

type tailBuffer struct {
	max int
	buf []byte
}

func (w *tailBuffer) Write(data []byte) (int, error) {
	n := len(data)
	if n >= w.max {
		w.buf = append(w.buf[:0], data[n-w.max:]...)
		return n, nil
	}
	w.buf = append(w.buf, data...)
	if len(w.buf) > w.max {
		copy(w.buf, w.buf[len(w.buf)-w.max:])
		w.buf = w.buf[:w.max]
	}
	return n, nil
}

func xkeenSyslogEvidence(parent context.Context) []string {
	binary := findIPTablesSave("ndmc")
	args := []string{"-c", "show log"}
	if binary == "" {
		binary = findIPTablesSave("logread")
		args = nil
	}
	if binary == "" {
		return []string{"ndmc и logread недоступны; системный журнал XKeen не прочитан"}
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = entwareStatusEnv()
	cmd.Stdin = nil
	cmd.WaitDelay = 250 * time.Millisecond
	output := &tailBuffer{max: 128 * 1024}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return []string{"Системный журнал XKeen недоступен или чтение превысило 4 секунды"}
	}
	var matched []string
	for _, line := range strings.Split(string(output.buf), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "xkeen") || strings.Contains(lower, "iptables-restore") || strings.Contains(lower, "ip6tables-restore") {
			if clean := safeReportLine(line); clean != "" {
				matched = append(matched, clean)
			}
		}
	}
	if len(matched) > 40 {
		matched = matched[len(matched)-40:]
	}
	if len(matched) == 0 {
		return []string{"В последних 128 КиБ системного журнала нет сообщений XKeen/iptables-restore"}
	}
	return append([]string{"Последние сообщения XKeen/iptables-restore; адреса и секреты скрыты."}, matched...)
}

type firewallRuleEvidence struct {
	Chain      bool
	ForceChain bool
	Jump       bool
	ForceJump  bool
	Target     int
	PortTarget int
}

func summarizeFirewallRules(rules, network, target string, port int) firewallRuleEvidence {
	var result firewallRuleEvidence
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == ":xkeen" {
			result.Chain = true
		} else if fields[0] == ":xkeen_force" {
			result.ForceChain = true
		}
		if strings.HasPrefix(fields[0], "[") {
			fields = fields[1:]
		}
		if len(fields) < 4 || fields[0] != "-A" || !ruleNetwork(fields, network) {
			continue
		}
		jump := ruleArg(fields, "-j")
		if fields[1] == "PREROUTING" {
			result.Jump = result.Jump || jump == "xkeen"
			result.ForceJump = result.ForceJump || jump == "xkeen_force"
		}
		if (fields[1] != "xkeen" && fields[1] != "xkeen_force") || jump != target {
			continue
		}
		result.Target++
		portArg := "--to-ports"
		if target == "TPROXY" {
			portArg = "--on-port"
		}
		actualPort := ruleArg(fields, portArg)
		if actualPort == "" && target == "REDIRECT" {
			actualPort = ruleArg(fields, "--to-port")
		}
		if port > 0 && actualPort == strconv.Itoa(port) {
			result.PortTarget++
		}
	}
	return result
}

func installedFirewallSaves(name string) []string {
	var paths []string
	for _, dir := range xkeenFirewallPath {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			paths = append(paths, path)
		}
	}
	return paths
}

func firewallEvidence(parent context.Context, configDir string) []string {
	lines := []string{"Проверка читает правила без их изменения. XKeen ищет iptables в PATH: /opt/bin, /opt/sbin, /sbin, /bin, /usr/sbin, /usr/bin."}
	hook := xkeenNetfilterHook
	info, err := os.Lstat(hook)
	switch {
	case os.IsNotExist(err):
		lines = append(lines, "Netfilter hook: отсутствует")
	case err != nil:
		lines = append(lines, "Netfilter hook: метаданные недоступны")
	default:
		kind := "необычный тип"
		if info.Mode().IsRegular() {
			kind = "обычный файл"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "символическая ссылка"
		}
		lines = append(lines, fmt.Sprintf("Netfilter hook: %s; исполняемый=%v; размер=%d байт; изменён=%s", kind, info.Mode().Perm()&0111 != 0, info.Size(), info.ModTime().UTC().Format("2006-01-02T15:04:05Z")))
	}
	tcpPort, udpPort := transparentPorts(configDir)
	for _, family := range []struct {
		name string
		tool string
	}{{"IPv4", "iptables-save"}, {"IPv6", "ip6tables-save"}} {
		candidates := installedFirewallSaves(family.tool)
		if len(candidates) == 0 {
			lines = append(lines, family.name+": ни один iptables-save не найден в PATH XKeen")
			continue
		}
		for _, path := range candidates {
			for _, table := range []struct {
				name    string
				network string
				target  string
				port    int
			}{{"nat", "tcp", "REDIRECT", tcpPort}, {"mangle", "udp", "TPROXY", udpPort}} {
				rules, err := readIPTablesSave(parent, path, table.name)
				if err != nil {
					lines = append(lines, fmt.Sprintf("%s %s %s: правила недоступны", family.name, path, table.name))
					continue
				}
				e := summarizeFirewallRules(rules, table.network, table.target, table.port)
				lines = append(lines, fmt.Sprintf("%s %s %s: xkeen=%v; xkeen_force=%v; PREROUTING→xkeen=%v; PREROUTING→force=%v; %s=%d; порт %d=%d", family.name, path, table.name, e.Chain, e.ForceChain, e.Jump, e.ForceJump, table.target, e.Target, table.port, e.PortTarget))
			}
		}
	}
	return lines
}
