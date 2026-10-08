package main

import (
	"context"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A check is a present-time observation, not a claim that a particular LAN
// client can open a website. The detailed, redacted evidence stays in Sections.
type statusCheck struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Title  string `json:"title"`
	State  string `json:"state"` // ok, issue, unknown, info
	Detail string `json:"detail"`
}

func newStatusCheck(id, group, title, state, detail string) statusCheck {
	return statusCheck{ID: id, Group: group, Title: title, State: state, Detail: safeReportLine(detail)}
}

var xkeenHybridModules = []string{"xt_comment", "xt_dscp", "xt_multiport", "xt_socket", "xt_TPROXY"}

func moduleCheck(procModules string, moduleDirectories, names []string) (filesMissing, notLoaded []string, readOK bool) {
	data, err := os.ReadFile(procModules)
	if err != nil {
		return nil, nil, false
	}
	loaded := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			loaded[fields[0]] = true
		}
	}
	for _, name := range names {
		foundFile := false
		for _, directory := range moduleDirectories {
			path := filepath.Join(directory, name+".ko")
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
				foundFile = true
				break
			}
		}
		if !foundFile {
			filesMissing = append(filesMissing, name)
		}
		if !loaded[name] {
			notLoaded = append(notLoaded, name)
		}
	}
	return filesMissing, notLoaded, true
}

func boolHealthCheck(status map[string]any, key, id, title string) statusCheck {
	value, ok := status[key].(bool)
	if !ok {
		return newStatusCheck(id, "Xray и ключ", title, "unknown", "Последний снимок состояния не содержит результата")
	}
	if !value {
		return newStatusCheck(id, "Xray и ключ", title, "issue", "Последняя проверка сообщила об ошибке")
	}
	return newStatusCheck(id, "Xray и ключ", title, "ok", "Последняя проверка прошла")
}

func lanPathCheck(id, title string, path lanInterceptionPath) statusCheck {
	if path.ExpectedPort == 0 || !path.Known {
		return newStatusCheck(id, "Перехват LAN", title, "unknown", "Вход Xray или правила firewall не удалось проверить")
	}
	if !path.Present {
		return newStatusCheck(id, "Перехват LAN", title, "issue", "Цепочка, переход или правило на порт Xray отсутствует")
	}
	return newStatusCheck(id, "Перехват LAN", title, "ok", fmt.Sprintf("Правило установлено на порт %d", path.ExpectedPort))
}

func bootLoaderCheck(path string) statusCheck {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return newStatusCheck("boot-loader", "Ядро и запуск", "Загрузка модулей до XKeen", "info", "Отдельный загрузчик S04 не установлен; XKeen может загружать модули самостоятельно")
	}
	if err != nil || !info.Mode().IsRegular() {
		return newStatusCheck("boot-loader", "Ядро и запуск", "Загрузка модулей до XKeen", "unknown", "Файл автозагрузки недоступен или имеет неожиданный тип")
	}
	if info.Mode().Perm()&0111 == 0 {
		return newStatusCheck("boot-loader", "Ядро и запуск", "Загрузка модулей до XKeen", "issue", "S04xkeen-netfilter-modules существует, но не является исполняемым")
	}
	return newStatusCheck("boot-loader", "Ядро и запуск", "Загрузка модулей до XKeen", "ok", "S04 загрузит модули перед S05xkeen; выполнение после перезагрузки ещё не проверено")
}

func netfilterComponentState(output string) string {
	if strings.Contains(output, "kmod-netfilter") {
		return "ok"
	}
	if strings.Contains(output, "components:") {
		return "issue"
	}
	return "unknown"
}

func keeneticNetfilterComponent(parent context.Context) statusCheck {
	binary := findIPTablesSave("ndmc")
	if binary == "" {
		return newStatusCheck("netfilter-component", "Ядро и запуск", "Компонент KeeneticOS Netfilter", "unknown", "ndmc недоступен")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-c", "show version")
	cmd.Env = entwareStatusEnv()
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	output := &cappedOutput{max: 64 * 1024}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil || ctx.Err() != nil || output.buf.Len() >= output.max {
		return newStatusCheck("netfilter-component", "Ядро и запуск", "Компонент KeeneticOS Netfilter", "unknown", "Список компонентов недоступен")
	}
	switch netfilterComponentState(output.buf.String()) {
	case "ok":
		return newStatusCheck("netfilter-component", "Ядро и запуск", "Компонент KeeneticOS Netfilter", "ok", "kmod-netfilter найден в списке установленных компонентов")
	case "issue":
		return newStatusCheck("netfilter-component", "Ядро и запуск", "Компонент KeeneticOS Netfilter", "issue", "kmod-netfilter отсутствует в списке установленных компонентов")
	default:
		return newStatusCheck("netfilter-component", "Ядро и запуск", "Компонент KeeneticOS Netfilter", "unknown", "Список компонентов не распознан")
	}
}

func tproxyPolicyCheck(parent context.Context, mark, tableID string) statusCheck {
	if mark == "" || tableID == "" {
		return newStatusCheck("tproxy-route", "Перехват LAN", "Маршрут TPROXY IPv4", "unknown", "Метка или таблица не найдены в хуке XKeen")
	}
	binary := findIPTablesSave("ip")
	if binary == "" {
		return newStatusCheck("tproxy-route", "Перехват LAN", "Маршрут TPROXY IPv4", "unknown", "Утилита ip недоступна")
	}
	read := func(args ...string) (string, bool) {
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = entwareStatusEnv()
		cmd.Stderr = io.Discard
		output := &cappedOutput{max: 16 * 1024}
		cmd.Stdout = output
		if err := cmd.Run(); err != nil || ctx.Err() != nil || output.buf.Len() >= output.max {
			return "", false
		}
		return output.buf.String(), true
	}
	rules, rulesOK := read("-4", "rule", "show")
	routes, routesOK := read("-4", "route", "show", "table", tableID)
	if !rulesOK || !routesOK {
		return newStatusCheck("tproxy-route", "Перехват LAN", "Маршрут TPROXY IPv4", "unknown", "Правила policy routing не удалось прочитать")
	}
	if hasTPROXYPolicyRoute(rules, routes, mark, tableID) {
		return newStatusCheck("tproxy-route", "Перехват LAN", "Маршрут TPROXY IPv4", "ok", "Метка "+mark+" направлена в таблицу "+tableID+" с локальным маршрутом")
	}
	return newStatusCheck("tproxy-route", "Перехват LAN", "Маршрут TPROXY IPv4", "issue", "Не найдены правило fwmark → таблица "+tableID+" или локальный маршрут")
}

func hasTPROXYPolicyRoute(rules, routes, mark, tableID string) bool {
	pattern := regexp.MustCompile(`fwmark\s+` + regexp.QuoteMeta(mark) + `(?:/0x[0-9a-fA-F]+)?\s+lookup\s+` + regexp.QuoteMeta(tableID) + `(?:\s|$)`)
	return pattern.MatchString(rules) && strings.Contains(routes, "local default dev lo")
}

func buildStatusChecks(ctx context.Context, config hw.Config, status map[string]any, statusErr error, lan lanInterceptionStatus) []statusCheck {
	checks := make([]statusCheck, 0, 16)
	add := func(c statusCheck) { checks = append(checks, c) }
	flags := readXKeenHookFlags(xkeenNetfilterHook)
	lanReady := lan.TCP.Known && lan.TCP.Present && lan.UDP.Known && lan.UDP.Present
	add(keeneticNetfilterComponent(ctx))
	moduleDir := ""
	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		name := strings.TrimSpace(string(release))
		if name != "" && !strings.ContainsAny(name, `/\`) {
			moduleDir = filepath.Join("/lib/modules", name)
		}
	}
	if moduleDir == "" {
		add(newStatusCheck("module-files", "Ядро и запуск", "Файлы модулей Netfilter", "unknown", "Версию ядра не удалось прочитать"))
		add(newStatusCheck("module-loaded", "Ядро и запуск", "Модули Netfilter загружены", "unknown", "Версию ядра не удалось прочитать"))
	} else {
		moduleDirs := []string{moduleDir, "/opt/lib/modules", filepath.Join("/opt/lib/system-modules", filepath.Base(moduleDir)), filepath.Join("/lib/system-modules", filepath.Base(moduleDir))}
		missingFiles, notLoaded, readOK := moduleCheck("/proc/modules", moduleDirs, xkeenHybridModules)
		if !readOK {
			add(newStatusCheck("module-files", "Ядро и запуск", "Файлы модулей Netfilter", "unknown", "/proc/modules недоступен"))
			add(newStatusCheck("module-loaded", "Ядро и запуск", "Модули Netfilter загружены", "unknown", "/proc/modules недоступен"))
		} else {
			if len(missingFiles) == 0 {
				add(newStatusCheck("module-files", "Ядро и запуск", "Файлы модулей Netfilter", "ok", "Все 5 модулей для Hybrid найдены для текущего ядра"))
			} else {
				state := "issue"
				if flags.Mode != "Hybrid" || lanReady {
					state = "info"
				}
				add(newStatusCheck("module-files", "Ядро и запуск", "Файлы модулей Netfilter", state, "Не найдены файлы: "+strings.Join(missingFiles, ", ")+"; модуль может быть встроен в ядро"))
			}
			if len(notLoaded) == 0 {
				add(newStatusCheck("module-loaded", "Ядро и запуск", "Модули Netfilter загружены", "ok", "comment, dscp, multiport, socket и TPROXY перечислены в /proc/modules"))
			} else {
				state := "issue"
				if flags.Mode != "Hybrid" || lanReady {
					state = "info"
				}
				add(newStatusCheck("module-loaded", "Ядро и запуск", "Модули Netfilter загружены", state, "Не перечислены в /proc/modules: "+strings.Join(notLoaded, ", ")+"; модуль может быть встроен в ядро"))
			}
		}
	}
	add(bootLoaderCheck("/opt/etc/init.d/S04xkeen-netfilter-modules"))
	if flags.Mode == "Hybrid" {
		if ready, err := xkeenReadyForRepair(xkeenReadyMarker); err == nil && ready && flags.IPTables && flags.RedirectPort > 0 && flags.TProxyPort > 0 {
			add(newStatusCheck("xkeen-hook", "Ядро и запуск", "Хук XKeen готов", "ok", "Режим Hybrid, маркер готовности и порты перехвата найдены"))
		} else {
			add(newStatusCheck("xkeen-hook", "Ядро и запуск", "Хук XKeen готов", "issue", "Не подтверждён маркер готовности, iptables или порты перехвата"))
		}
	} else {
		add(newStatusCheck("xkeen-hook", "Ядро и запуск", "Режим XKeen", "info", "Хук Hybrid не обнаружен; текущий режим: "+flags.Mode))
	}
	if _, err := exactlyOneMainXray("/proc", config); err == nil {
		add(newStatusCheck("xray-process", "Xray и ключ", "Основной процесс Xray", "ok", "Найден ровно один xray run"))
	} else {
		add(newStatusCheck("xray-process", "Xray и ключ", "Основной процесс Xray", "issue", "Не удалось подтвердить ровно один основной xray run"))
	}
	if statusErr == nil && status != nil {
		add(boolHealthCheck(status, "api_reachable", "xray-api", "API Xray"))
		add(boolHealthCheck(status, "selected_present", "selected-outbound", "Выбранный ключ присутствует"))
	} else {
		add(newStatusCheck("xray-api", "Xray и ключ", "API Xray", "unknown", "Снимок состояния Hot Watcher недоступен"))
		add(newStatusCheck("selected-outbound", "Xray и ключ", "Выбранный ключ присутствует", "unknown", "Снимок состояния Hot Watcher недоступен"))
	}
	if lan.TCP.ExpectedPort > 0 && lan.UDP.ExpectedPort > 0 {
		if transparentPortsListening("/proc/net", lan.TCP.ExpectedPort, lan.UDP.ExpectedPort) {
			add(newStatusCheck("xray-listeners", "Xray и ключ", "Прозрачные входы TCP/UDP", "ok", "Xray слушает оба порта перехвата"))
		} else {
			add(newStatusCheck("xray-listeners", "Xray и ключ", "Прозрачные входы TCP/UDP", "issue", "Не подтверждены оба слушающих сокета"))
		}
	} else {
		add(newStatusCheck("xray-listeners", "Xray и ключ", "Прозрачные входы TCP/UDP", "unknown", "Порты входов не найдены в конфигурации"))
	}
	add(lanPathCheck("lan-tcp", "IPv4 TCP → REDIRECT", lan.TCP))
	add(lanPathCheck("lan-udp", "IPv4 UDP → TPROXY", lan.UDP))
	if flags.Mode == "Hybrid" {
		routing := xkeenHookSettings(xkeenNetfilterHook)
		add(tproxyPolicyCheck(ctx, routing["table_mark"], routing["table_id"]))
	}
	if nonLoopbackIPv6Active("/proc/net") {
		add(lanPathCheck("lan-tcp-v6", "IPv6 TCP → REDIRECT", lan.TCPIPv6))
		add(lanPathCheck("lan-udp-v6", "IPv6 UDP → TPROXY", lan.UDPIPv6))
	} else {
		add(newStatusCheck("lan-ipv6", "Перехват LAN", "IPv6", "info", "Активный глобальный IPv6 не обнаружен; правила IPv6 не обязательны для этого снимка"))
	}
	add(newStatusCheck("lan-counters", "Перехват LAN", "Счётчики пакетов", "info", fmt.Sprintf("TCP в Xray: %d; UDP в Xray: %d. Счётчики накопительные и не доказывают доступ конкретного клиента", lan.TCP.RedirectedPackets, lan.UDP.RedirectedPackets)))
	return checks
}
