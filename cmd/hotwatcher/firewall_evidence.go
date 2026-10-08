package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// XKeen resolves iptables through this PATH (see its generated S05xkeen).
// Inspect every installed save frontend: different frontends can expose
// different rule sets, and the normal LAN summary reads only the first one.
var xkeenFirewallPath = []string{"/opt/bin", "/opt/sbin", "/sbin", "/bin", "/usr/sbin", "/usr/bin"}

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
	hook := "/opt/etc/ndm/netfilter.d/proxy.sh"
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
