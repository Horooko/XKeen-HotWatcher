package main

import (
	"context"
	"errors"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lanInterceptionStatus describes XKeen's LAN interception path. It never
// returns raw firewall rules, which can contain client addresses or MACs.
// Counters are cumulative since XKeen last installed the rules; one snapshot
// alone does not prove that a particular client's connection used the proxy.
type lanInterceptionStatus struct {
	CheckedAt time.Time           `json:"checked_at"`
	TCP       lanInterceptionPath `json:"tcp"`
	UDP       lanInterceptionPath `json:"udp"`
	TCPIPv6   lanInterceptionPath `json:"tcp_ipv6"`
	UDPIPv6   lanInterceptionPath `json:"udp_ipv6"`
}

type lanInterceptionPath struct {
	Known             bool   `json:"known"`
	Present           bool   `json:"present"`
	ExpectedPort      int    `json:"expected_port,omitempty"`
	IngressPackets    uint64 `json:"ingress_packets"`
	RedirectedPackets uint64 `json:"redirected_packets"`
	Missing           string `json:"missing,omitempty"`
}

type transparentInbound struct {
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Settings struct {
		Network        string `json:"network"`
		FollowRedirect bool   `json:"followRedirect"`
	} `json:"settings"`
	StreamSettings struct {
		Sockopt struct {
			TProxy string `json:"tproxy"`
		} `json:"sockopt"`
	} `json:"streamSettings"`
}

func transparentPorts(configDir string) (tcp, udp int) {
	path := filepath.Join(configDir, "03_inbounds.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return 0, 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var config struct {
		Inbounds []transparentInbound `json:"inbounds"`
	}
	if hw.DecodeXrayJSONC(b, &config) != nil || len(config.Inbounds) > 128 {
		return 0, 0
	}
	for _, in := range config.Inbounds {
		if in.Protocol != "dokodemo-door" || in.Port < 1 || in.Port > 65535 || !in.Settings.FollowRedirect {
			continue
		}
		switch {
		case in.Settings.Network == "tcp" && in.StreamSettings.Sockopt.TProxy == "":
			tcp = in.Port
		case in.Settings.Network == "udp" && in.StreamSettings.Sockopt.TProxy == "tproxy":
			udp = in.Port
		}
	}
	return tcp, udp
}

// readLANInterception is a bounded, read-only check. iptables-save -c reads
// rules and their packet counters but does not install or flush anything.
func readLANInterception(parent context.Context, configDir string) lanInterceptionStatus {
	result := lanInterceptionStatus{CheckedAt: time.Now().UTC()}
	tcpPort, udpPort := transparentPorts(configDir)
	for _, path := range []*lanInterceptionPath{&result.TCP, &result.TCPIPv6} {
		path.ExpectedPort = tcpPort
		if tcpPort == 0 {
			path.Missing = "xray_inbound_unknown"
		}
	}
	for _, path := range []*lanInterceptionPath{&result.UDP, &result.UDPIPv6} {
		path.ExpectedPort = udpPort
		if udpPort == 0 {
			path.Missing = "xray_inbound_unknown"
		}
	}
	if tcpPort == 0 && udpPort == 0 {
		return result
	}
	readFamilyInterception(parent, "iptables-save", tcpPort, udpPort, &result.TCP, &result.UDP)
	readFamilyInterception(parent, "ip6tables-save", tcpPort, udpPort, &result.TCPIPv6, &result.UDPIPv6)
	return result
}

func findIPTablesSave(name string) string {
	for _, dir := range []string{"/opt/sbin", "/opt/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return candidate
		}
	}
	return ""
}

func readFamilyInterception(parent context.Context, tool string, tcpPort, udpPort int, tcp, udp *lanInterceptionPath) {
	binary := findIPTablesSave(tool)
	if binary == "" {
		if tcpPort != 0 {
			tcp.Missing = "iptables_save_unavailable"
		}
		if udpPort != 0 {
			udp.Missing = "iptables_save_unavailable"
		}
		return
	}
	if tcpPort != 0 {
		if rules, err := readIPTablesSave(parent, binary, "nat"); err == nil {
			*tcp = parseInterceptionRules(rules, "tcp", "REDIRECT", tcpPort)
		} else {
			tcp.Missing = "rules_unavailable"
		}
	}
	if udpPort != 0 {
		if rules, err := readIPTablesSave(parent, binary, "mangle"); err == nil {
			*udp = parseInterceptionRules(rules, "udp", "TPROXY", udpPort)
		} else {
			udp.Missing = "rules_unavailable"
		}
	}
}

func readIPTablesSave(parent context.Context, binary, table string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-c", "-t", table)
	cmd.Env = entwareStatusEnv()
	cmd.WaitDelay = 250 * time.Millisecond
	output := &cappedOutput{max: 2 * 1024 * 1024}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || ctx.Err() != nil || output.buf.Len() >= output.max {
		return "", errors.New("iptables-save unavailable")
	}
	return output.buf.String(), nil
}

func parseInterceptionRules(rules, network, target string, port int) lanInterceptionPath {
	result := lanInterceptionPath{Known: true, ExpectedPort: port}
	chains := map[string]bool{"xkeen": false, "xkeen_force": false}
	ingress := map[string]bool{}
	redirect := map[string]bool{}
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], ":") {
			if name := strings.TrimPrefix(fields[0], ":"); name == "xkeen" || name == "xkeen_force" {
				chains[name] = true
			}
			continue
		}
		packets := uint64(0)
		if strings.HasPrefix(fields[0], "[") && strings.HasSuffix(fields[0], "]") {
			parts := strings.SplitN(strings.Trim(fields[0], "[]"), ":", 2)
			if len(parts) == 2 {
				packets, _ = strconv.ParseUint(parts[0], 10, 64)
			}
			fields = fields[1:]
		}
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		if fields[1] == "PREROUTING" && ruleNetwork(fields, network) {
			if jump := ruleArg(fields, "-j"); jump == "xkeen" || jump == "xkeen_force" {
				ingress[jump] = true
				result.IngressPackets += packets
			}
		}
		if (fields[1] != "xkeen" && fields[1] != "xkeen_force") || ruleArg(fields, "-j") != target || !ruleNetwork(fields, network) {
			continue
		}
		portArg := "--to-ports"
		if target == "TPROXY" {
			portArg = "--on-port"
		}
		actualPort := ruleArg(fields, portArg)
		if actualPort == "" && target == "REDIRECT" {
			actualPort = ruleArg(fields, "--to-port")
		}
		if actualPort == strconv.Itoa(port) {
			redirect[fields[1]] = true
			result.RedirectedPackets += packets
		}
	}
	for name, exists := range chains {
		if exists && ingress[name] && redirect[name] {
			result.Present = true
			break
		}
	}
	switch {
	case !chains["xkeen"] && !chains["xkeen_force"]:
		result.Missing = "xkeen_chain_missing"
	case len(ingress) == 0:
		result.Missing = "prerouting_jump_missing"
	case len(redirect) == 0:
		result.Missing = "redirect_target_missing"
	case !result.Present:
		result.Missing = "route_disconnected"
	}
	return result
}

func ruleArg(fields []string, name string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == name {
			return fields[i+1]
		}
	}
	return ""
}

func ruleNetwork(fields []string, network string) bool {
	protocol := ruleArg(fields, "-p")
	return protocol == "" || protocol == network
}
