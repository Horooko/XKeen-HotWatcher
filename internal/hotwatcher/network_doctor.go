package hotwatcher

import (
	"os"
	"strconv"
	"time"
)

type NetworkCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Action string `json:"action,omitempty"`
}

type NetworkDoctorReport struct {
	Version        string           `json:"version"`
	Healthy        bool             `json:"healthy"`
	Checks         []NetworkCheck   `json:"checks"`
	DNS            *DNSVerification `json:"dns,omitempty"`
	SecretsPrinted bool             `json:"secrets_printed"`
}

// DoctorNetwork makes only read-only network and runtime probes. Every error
// is reduced to a fixed diagnostic category before being shown to the user.
func (e *Engine) DoctorNetwork() NetworkDoctorReport {
	return e.DoctorNetworkWithProgress(nil)
}

func (e *Engine) DoctorNetworkWithProgress(progress func(NetworkCheck)) NetworkDoctorReport {
	report := NetworkDoctorReport{Version: Version, Healthy: true, Checks: []NetworkCheck{}}
	add := func(name string, ok bool, detail, action string, critical bool) {
		check := NetworkCheck{Name: name, OK: ok, Detail: detail, Action: action}
		report.Checks = append(report.Checks, check)
		if progress != nil {
			progress(check)
		}
		if critical && !ok {
			report.Healthy = false
		}
	}
	if _, err := e.C.URL(); err != nil {
		add("subscription_url", false, "не удалось прочитать адрес подписки", "проверьте hotwatcher url и права файла", true)
	} else {
		add("subscription_url", true, "адрес сохранён и читается", "", true)
		body, err := e.Fetcher(e.C)
		if err != nil {
			add("subscription_download", false, "загрузка с текущего маршрута роутера не удалась", "если VPN мешает загрузке, используйте hard-sync вне игры", true)
		} else if parsed, parseErr := Parse(body, e.C); parseErr != nil {
			add("subscription_download", false, "ответ получен, но ключи не распознаны", "проверьте формат и содержимое подписки у провайдера", true)
		} else {
			add("subscription_download", true, "ключей VLESS: "+strconv.Itoa(len(parsed.Nodes)), "", true)
		}
	}
	if info, err := os.Stat(e.C.XrayBinary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		add("xray_binary", false, "исполняемый Xray не найден", "проверьте установку XKeen и xray_binary", true)
	} else {
		add("xray_binary", true, "исполняемый Xray доступен", "", true)
	}
	if lock, err := CurrentLock(e.C); err != nil {
		add("operation_lock", false, "не удалось прочитать блокировку", "проверьте права state_dir", false)
	} else if lock.Busy {
		add("operation_lock", false, "выполняется "+lock.Operation, "hotwatcher recovery status покажет этап и PID", false)
	} else {
		add("operation_lock", true, "операция Hot Watcher не занята", "", false)
	}
	_, listErr := e.R.List()
	_, balanceErr := e.R.Balance()
	apiOK := listErr == nil && balanceErr == nil
	if apiOK {
		add("xray_api", true, "список узлов и балансировщик отвечают", "", true)
	} else {
		add("xray_api", false, "API Xray или балансировщик не отвечает", "проверьте xkeen -status и hotwatcher doctor", true)
	}
	s, stateErr := e.state()
	if stateErr != nil {
		add("active_key", false, "сохранённое состояние ключей не читается", "hotwatcher recovery status", true)
	} else if s == nil {
		add("active_key", false, "ключи ещё не приняты Hot Watcher", "выполните hotwatcher adopt", true)
	} else if node, found := findNode(s.Active, s.Selected); !found {
		add("active_key", false, "выбранный ключ отсутствует в сохранённом списке", "hotwatcher recovery status", true)
	} else if latency, err := e.R.ProbeLatency(node); err != nil {
		add("active_key", false, "HTTPS-проба через выбранный ключ не удалась", "hotwatcher keys --check или hard-sync вне игры", true)
	} else {
		add("active_key", true, "HTTPS-проба через ключ: "+strconv.Itoa(int(latency/time.Millisecond))+" мс", "", true)
	}
	if dns, err := e.DNSVerify(); err != nil {
		add("dns_xray", false, "DNS-проба не подготовлена", "проверьте hotwatcher dns status", false)
	} else {
		report.DNS = &dns
		ok := dns.Direct.Success || dns.SelectedVLESS.Success
		if ok {
			add("dns_xray", true, "DNS ответил через временный Xray; прямой и VLESS-маршруты показаны отдельно", "", false)
		} else {
			add("dns_xray", false, "DNS не ответил ни напрямую, ни через выбранный VLESS", "проверьте hotwatcher dns verify и маршрут dns.tag", dns.Managed)
		}
	}
	return report
}
