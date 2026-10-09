package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Inspect only the allowlisted setting. S05xkeen can contain user data and
// must never be included as raw text in a downloadable diagnostic report.
var proxyDNSAssignment = regexp.MustCompile(`^proxy_dns=["'](on|off)["']$`)

func savedProxyDNS(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for scanner.Scan() {
		if match := proxyDNSAssignment.FindStringSubmatch(scanner.Text()); match != nil {
			return match[1]
		}
	}
	return ""
}

type dnsFirewallPath struct {
	BypassPosition         int
	XKeenPosition          int
	PrivateReturn          bool
	OldDNSException        bool
	KeeneticDNSRedirect    bool
	KeeneticChainReachable bool
	KeeneticProxyPort      int
}

type dnsUDPSockets struct {
	Count      int
	QueuedByte uint64
	Known      bool
}

func readDNSUDPSockets(path string, port int) dnsUDPSockets {
	f, err := os.Open(path)
	if err != nil {
		return dnsUDPSockets{}
	}
	defer f.Close()
	result := dnsUDPSockets{Known: true}
	scanner := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for rows := 0; scanner.Scan() && rows < 8192; rows++ {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		endpoint := strings.Split(fields[1], ":")
		if len(endpoint) != 2 {
			continue
		}
		actualPort, err := strconv.ParseUint(endpoint[1], 16, 16)
		if err != nil || int(actualPort) != port {
			continue
		}
		result.Count++
		queue := strings.Split(fields[4], ":")
		if len(queue) == 2 {
			if bytes, err := strconv.ParseUint(queue[1], 16, 64); err == nil {
				result.QueuedByte += bytes
			}
		}
	}
	result.Known = scanner.Err() == nil
	return result
}

func parseDNSFirewall(mangle, nat string) dnsFirewallPath {
	var path dnsFirewallPath
	position := 0
	for _, line := range strings.Split(mangle, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "[") {
			fields = fields[1:]
		}
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		chain := fields[1]
		if chain == "PREROUTING" {
			position++
			jump := ruleArg(fields, "-j")
			if (jump == "xkeen" || jump == "xkeen_force") && path.XKeenPosition == 0 {
				path.XKeenPosition = position
			}
			if unconditionalDNSBypass(fields) && path.BypassPosition == 0 {
				path.BypassPosition = position
			}
		}
		if chain == "xkeen" && ruleArg(fields, "-d") == "192.168.0.0/16" && ruleArg(fields, "-j") == "RETURN" {
			if strings.Contains(line, "! --dport 53") || strings.Contains(line, "--dport 53 !") {
				path.OldDNSException = true
			} else if ruleArg(fields, "-p") == "" && ruleArg(fields, "--dport") == "" {
				path.PrivateReturn = true
			}
		}
	}
	for _, line := range strings.Split(nat, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "[") {
			fields = fields[1:]
		}
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		if fields[1] == "PREROUTING" && ruleArg(fields, "-j") == "_NDM_DNS_REDIRECT" {
			path.KeeneticChainReachable = true
		}
		if fields[1] != "_NDM_HOTSPOT_DNSREDIR" {
			continue
		}
		if ruleArg(fields, "-p") == "udp" && ruleArg(fields, "--dport") == "53" && ruleArg(fields, "-j") == "REDIRECT" {
			path.KeeneticDNSRedirect = true
			port, _ := strconv.Atoi(ruleArg(fields, "--to-ports"))
			path.KeeneticProxyPort = port
		}
	}
	if path.KeeneticChainReachable {
		path.KeeneticChainReachable = strings.Contains(nat, "-A _NDM_DNS_REDIRECT -j _NDM_HOTSPOT_DNSREDIR")
	}
	return path
}

// A scoped RETURN is insufficient evidence: it may match another bridge,
// source, mark, or destination while LAN DNS still enters Xray.
func unconditionalDNSBypass(fields []string) bool {
	if len(fields) < 8 || fields[0] != "-A" || fields[1] != "PREROUTING" {
		return false
	}
	proto, port, jump := false, false, false
	for i := 2; i < len(fields); {
		if i+1 >= len(fields) {
			return false
		}
		switch fields[i] {
		case "-p":
			proto = fields[i+1] == "udp"
		case "-m":
			if fields[i+1] != "udp" {
				return false
			}
		case "--dport":
			port = fields[i+1] == "53"
		case "-j":
			jump = fields[i+1] == "RETURN"
		default:
			return false
		}
		i += 2
	}
	return proto && port && jump
}

func routerLANIPv4() (net.IP, string) {
	// br0 is Keenetic's primary LAN bridge. Guessing from all private
	// interfaces could select a VPN or guest network instead.
	bridge, err := net.InterfaceByName("br0")
	if err != nil || bridge.Flags&net.FlagUp == 0 {
		return nil, ""
	}
	addresses, err := bridge.Addrs()
	if err != nil {
		return nil, ""
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && ip.IsPrivate() {
			return ip.To4(), bridge.Name
		}
	}
	return nil, ""
}

func queryRouterDNS(ctx context.Context, address, network string) (time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address, "53"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, err
	}
	// Fixed public name; no user domain or credentials are sent or saved.
	question := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := rand.Read(question[:2]); err != nil {
		return 0, err
	}
	if network == "tcp4" {
		length := []byte{0, byte(len(question))}
		if _, err := conn.Write(append(length, question...)); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(conn, length); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(length))
		if size < 12 || size > 4096 {
			return 0, fmt.Errorf("invalid DNS reply size")
		}
		reply := make([]byte, size)
		if _, err := io.ReadFull(conn, reply); err != nil {
			return 0, err
		}
		if !validRouterDNSReply(reply, question[:2]) {
			return 0, fmt.Errorf("invalid DNS reply")
		}
	} else {
		if _, err := conn.Write(question); err != nil {
			return 0, err
		}
		reply := make([]byte, 4096)
		n, err := conn.Read(reply)
		if err != nil {
			return 0, err
		}
		if !validRouterDNSReply(reply[:n], question[:2]) {
			return 0, fmt.Errorf("invalid DNS reply")
		}
	}
	return time.Since(start), nil
}

func validRouterDNSReply(reply, id []byte) bool {
	if len(reply) < 12 || len(id) != 2 || reply[0] != id[0] || reply[1] != id[1] {
		return false
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	return flags&0x8000 != 0 && flags&0x000f == 0 && binary.BigEndian.Uint16(reply[4:6]) == 1 && binary.BigEndian.Uint16(reply[6:8]) > 0
}

func dnsPathDiagnostics(ctx context.Context) ([]statusCheck, []string) {
	checks := make([]statusCheck, 0, 5)
	lines := []string{"Проверки выполняются на самом роутере. Успех не подтверждает DNS и маршрут отдельного клиента LAN."}
	hook := xkeenHookSettings(xkeenNetfilterHook)
	saved, active := savedProxyDNS("/opt/etc/init.d/S05xkeen"), hook["proxy_dns"]
	lines = append(lines, fmt.Sprintf("Перехват DNS XKeen: в S05=%s; в текущем хуке=%s; mode=%s; file_dns=%s", knownValue(saved), knownValue(active), knownValue(hook["mode_proxy"]), knownValue(hook["file_dns"])))
	switch {
	case saved == "" || active == "":
		checks = append(checks, newStatusCheck("dns-xkeen-config", "DNS LAN", "Перехват DNS XKeen", "unknown", "Настройки S05 или текущего хука не удалось прочитать"))
	case saved != active:
		checks = append(checks, newStatusCheck("dns-xkeen-config", "DNS LAN", "Перехват DNS XKeen", "issue", "S05 и текущий хук расходятся; при следующем запуске правила могут измениться"))
	case active == "on" && hook["mode_proxy"] == "Hybrid" && hook["file_dns"] == "true":
		checks = append(checks, newStatusCheck("dns-xkeen-config", "DNS LAN", "Перехват DNS XKeen", "info", "Hybrid перехватывает UDP/53; если DNS Xray не отвечает, LAN останется без DNS. Проверьте функциональные проверки ниже"))
	default:
		checks = append(checks, newStatusCheck("dns-xkeen-config", "DNS LAN", "Перехват DNS XKeen", "ok", "Постоянная и текущая настройки совпадают: "+active))
	}
	iptablesSave := findIPTablesSave("iptables-save")
	var mangle, nat string
	var mangleErr, natErr error
	if iptablesSave != "" {
		mangle, mangleErr = readIPTablesSave(ctx, iptablesSave, "mangle")
	} else {
		mangleErr = fmt.Errorf("unavailable")
	}
	if iptablesSave != "" {
		nat, natErr = readIPTablesSave(ctx, iptablesSave, "nat")
	} else {
		natErr = fmt.Errorf("unavailable")
	}
	path := parseDNSFirewall(mangle, nat)
	if mangleErr != nil {
		checks = append(checks, newStatusCheck("dns-firewall-path", "DNS LAN", "Путь UDP/53 через firewall", "unknown", "Таблица mangle недоступна"))
		lines = append(lines, "Таблица mangle: недоступна")
	} else {
		lines = append(lines, fmt.Sprintf("mangle PREROUTING: обход UDP/53 на позиции %d; переход в xkeen на позиции %d; внутри xkeen возврат для локальной сети=%v; старое исключение UDP/53=%v", path.BypassPosition, path.XKeenPosition, path.PrivateReturn, path.OldDNSException))
		if natErr == nil {
			lines = append(lines, fmt.Sprintf("nat: путь PREROUTING → DNS_REDIRECT → HOTSPOT_DNSREDIR=%v; перенаправление Keenetic UDP/53=%v; порт назначения=%d", path.KeeneticChainReachable, path.KeeneticDNSRedirect, path.KeeneticProxyPort))
		} else {
			lines = append(lines, "Таблица nat: недоступна")
		}
		if path.BypassPosition > 0 && (path.XKeenPosition == 0 || path.BypassPosition < path.XKeenPosition) {
			checks = append(checks, newStatusCheck("dns-firewall-path", "DNS LAN", "Путь UDP/53 через firewall", "ok", "Общий обход UDP/53 стоит до переходов в xkeen и xkeen_force"))
		} else if path.XKeenPosition > 0 && path.OldDNSException {
			checks = append(checks, newStatusCheck("dns-firewall-path", "DNS LAN", "Путь UDP/53 через firewall", "issue", "Правила всё ещё направляют локальный UDP/53 в Xray; нужен безопасный пересбор правил XKeen"))
		} else if path.PrivateReturn {
			checks = append(checks, newStatusCheck("dns-firewall-path", "DNS LAN", "Путь UDP/53 через firewall", "info", "Возврат из xkeen для локальной сети найден; результат для конкретного LAN-клиента требует отдельной проверки"))
		} else {
			checks = append(checks, newStatusCheck("dns-firewall-path", "DNS LAN", "Путь UDP/53 через firewall", "unknown", "Порядок обработки UDP/53 не удалось подтвердить"))
		}
		if active == "off" && path.OldDNSException {
			checks = append(checks, newStatusCheck("dns-stale-rules", "DNS LAN", "Актуальность правил XKeen", "info", "Хук уже настроен на обход DNS, но активная цепочка ещё создана со старым исключением; временный обход должен стоять перед xkeen"))
		}
	}
	udp53, udp41100 := readDNSUDPSockets("/proc/net/udp", 53), readDNSUDPSockets("/proc/net/udp", 41100)
	udp6port53 := readDNSUDPSockets("/proc/net/udp6", 53)
	lines = append(lines, fmt.Sprintf("UDP-сокеты /proc: порт 53=%d, накоплено в очередях=%d байт (прочитан=%v); порт 41100=%d (прочитан=%v). Число сокетов не определяет владельца процесса.", udp53.Count, udp53.QueuedByte, udp53.Known, udp41100.Count, udp41100.Known))
	lines = append(lines, fmt.Sprintf("IPv6 UDP-сокеты на порту 53: %d (прочитан=%v)", udp6port53.Count, udp6port53.Known))
	if !udp53.Known {
		checks = append(checks, newStatusCheck("dns-udp-listener", "DNS LAN", "UDP-служба DNS", "unknown", "/proc/net/udp недоступен"))
	} else if udp53.Count == 0 && udp6port53.Count > 0 {
		checks = append(checks, newStatusCheck("dns-udp-listener", "DNS LAN", "UDP-служба DNS", "unknown", "Найден только IPv6 UDP/53; поддержку IPv4 этим сокетом не удалось подтвердить"))
	} else if udp53.Count == 0 {
		checks = append(checks, newStatusCheck("dns-udp-listener", "DNS LAN", "UDP-служба DNS", "issue", "На порту 53 нет UDP-сокета"))
	} else {
		checks = append(checks, newStatusCheck("dns-udp-listener", "DNS LAN", "UDP-служба DNS", "info", fmt.Sprintf("Сокетов на UDP/53: %d; очередь: %d байт; ответ службы проверяется отдельно", udp53.Count, udp53.QueuedByte)))
	}
	if natErr != nil || !udp41100.Known {
		checks = append(checks, newStatusCheck("dns-keenetic-redirect", "DNS LAN", "DNS-перенаправление Keenetic", "unknown", "NAT или UDP-сокеты недоступны"))
	} else if path.KeeneticChainReachable && path.KeeneticDNSRedirect && path.KeeneticProxyPort == 41100 && udp41100.Count == 0 {
		checks = append(checks, newStatusCheck("dns-keenetic-redirect", "DNS LAN", "DNS-перенаправление Keenetic", "issue", "NAT отправляет DNS на UDP/41100, но слушающий сокет не найден"))
	} else if path.KeeneticChainReachable && path.KeeneticDNSRedirect && path.KeeneticProxyPort == 41100 {
		checks = append(checks, newStatusCheck("dns-keenetic-redirect", "DNS LAN", "DNS-перенаправление Keenetic", "info", "Цепочка NAT достижима и UDP/41100 слушает; условия правила и путь конкретного клиента не проверены"))
	} else {
		checks = append(checks, newStatusCheck("dns-keenetic-redirect", "DNS LAN", "DNS-перенаправление Keenetic", "info", "Правило перенаправления на 41100 не найдено; конфигурация Keenetic может отличаться"))
	}
	loopLatency, loopErr := queryRouterDNS(ctx, "127.0.0.1", "udp4")
	if loopErr == nil {
		checks = append(checks, newStatusCheck("dns-loopback", "DNS LAN", "DNS роутера через loopback", "ok", fmt.Sprintf("UDP-ответ получен за %d мс", loopLatency.Milliseconds())))
		lines = append(lines, fmt.Sprintf("Локальный запрос UDP/53 через loopback: OK, %d мс", loopLatency.Milliseconds()))
	} else {
		checks = append(checks, newStatusCheck("dns-loopback", "DNS LAN", "DNS роутера через loopback", "issue", "UDP-запрос не получил корректный ответ за 2 секунды"))
		lines = append(lines, "Локальный запрос UDP/53 через loopback: неуспешен или превысил 2 секунды")
	}
	lanIP, interfaceName := routerLANIPv4()
	if lanIP == nil {
		checks = append(checks, newStatusCheck("dns-lan-udp", "DNS LAN", "DNS к адресу LAN с роутера", "unknown", "IPv4-адрес основного моста br0 не найден"))
		lines = append(lines, "Основной мост br0: IPv4-адрес не найден")
	} else {
		udpLatency, udpErr := queryRouterDNS(ctx, lanIP.String(), "udp4")
		lines = append(lines, fmt.Sprintf("Основной мост %s: локальный запрос UDP/53=%v; длительность=%d мс", interfaceName, udpErr == nil, udpLatency.Milliseconds()))
		if udpErr == nil {
			checks = append(checks, newStatusCheck("dns-lan-udp", "DNS LAN", "DNS к адресу LAN с роутера", "ok", fmt.Sprintf("UDP-ответ через %s получен за %d мс; клиентский PREROUTING не проверен", interfaceName, udpLatency.Milliseconds())))
		} else {
			checks = append(checks, newStatusCheck("dns-lan-udp", "DNS LAN", "DNS к адресу LAN с роутера", "issue", "UDP-запрос к адресу br0 не получил ответ; проверьте перехват и службу DNS Keenetic"))
			tcpLatency, tcpErr := queryRouterDNS(ctx, lanIP.String(), "tcp4")
			lines = append(lines, fmt.Sprintf("Тот же запрос TCP/53: успешен=%v; длительность=%d мс", tcpErr == nil, tcpLatency.Milliseconds()))
			if tcpErr == nil {
				checks = append(checks, newStatusCheck("dns-lan-tcp", "DNS LAN", "Контрольный DNS через TCP", "info", "TCP/53 отвечает при отказе UDP/53; проблема в UDP-пути или службе"))
			} else {
				checks = append(checks, newStatusCheck("dns-lan-tcp", "DNS LAN", "Контрольный DNS через TCP", "issue", "TCP/53 также не отвечает; проверьте службу DNS и входящий firewall"))
			}
		}
	}
	return checks, lines
}

func knownValue(value string) string {
	if value == "" {
		return "неизвестно"
	}
	return value
}
