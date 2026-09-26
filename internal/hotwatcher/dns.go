package hotwatcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DNS auto mode affects only Xray's built-in DNS module. XKeen/Keenetic DNS
// policy is deliberately outside this file's ownership.
type DNSStatus struct {
	ConfigFile                  string   `json:"config_file"`
	Managed                     bool     `json:"managed"`
	ParallelQueries             bool     `json:"parallel_queries"`
	Servers                     []string `json:"servers"`
	RuntimeActivationUnverified bool     `json:"runtime_activation_unverified"`
	Note                        string   `json:"note,omitempty"`
}

type DNSChange struct {
	ConfigFile string           `json:"config_file"`
	Servers    []string         `json:"servers"`
	Probes     []DNSProbeResult `json:"probes"`
	Restart    string           `json:"restart"`
}

type dnsSource struct {
	path     string
	original []byte
	root     map[string]json.RawMessage
	dns      map[string]json.RawMessage
	created  bool
}

type dnsJournal struct {
	Schema       int       `json:"schema"`
	Path         string    `json:"path"`
	Original     []byte    `json:"original"`
	OriginalHash string    `json:"original_hash"`
	AppliedHash  string    `json:"applied_hash"`
	Created      bool      `json:"created"`
	At           time.Time `json:"at"`
}

func dnsSourceUnchanged(src dnsSource) error {
	if src.created {
		if _, err := os.Lstat(src.path); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("DNS-файл был создан другим процессом; изменение отменено")
	}
	current, err := readLimited(src.path, 8*1024*1024)
	if err != nil {
		return err
	}
	if digest(current) != digest(src.original) {
		return errors.New("DNS-файл изменён другим процессом; изменение отменено")
	}
	return nil
}

func (e *Engine) dnsJournalPath() string { return filepath.Join(e.C.StateDir, "dns-auto-backup.json") }

// jsoncToJSON accepts the comments and trailing commas commonly used in Xray
// fragments. Other JSON5 syntax is refused instead of being misinterpreted.
func jsoncToJSON(src []byte) ([]byte, error) {
	out := append([]byte(nil), src...)
	inString, escape := false, false
	for i := 0; i < len(out); i++ {
		switch {
		case inString:
			if escape {
				escape = false
			} else if out[i] == '\\' {
				escape = true
			} else if out[i] == '"' {
				inString = false
			}
		case out[i] == '"':
			inString = true
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '/':
			out[i], out[i+1] = ' ', ' '
			i += 2
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			i += 2
			closed := false
			for ; i < len(out); i++ {
				if i+1 < len(out) && out[i] == '*' && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					closed = true
					break
				}
				if out[i] != '\n' && out[i] != '\r' {
					out[i] = ' '
				}
			}
			if !closed {
				return nil, errors.New("незакрытый комментарий в DNS-конфигурации")
			}
		}
	}
	if inString {
		return nil, errors.New("незакрытая строка в DNS-конфигурации")
	}
	inString, escape = false, false
	for i := 0; i < len(out); i++ {
		if inString {
			if escape {
				escape = false
			} else if out[i] == '\\' {
				escape = true
			} else if out[i] == '"' {
				inString = false
			}
			continue
		}
		if out[i] == '"' {
			inString = true
			continue
		}
		if out[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(out) && (out[j] == ' ' || out[j] == '\n' || out[j] == '\r' || out[j] == '\t') {
			j++
		}
		if j < len(out) && (out[j] == '}' || out[j] == ']') {
			out[i] = ' '
		}
	}
	return out, nil
}

func parseDNSFragment(b []byte) (map[string]json.RawMessage, error) {
	clean, err := jsoncToJSON(b)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(clean, &root); err != nil || root == nil {
		return nil, errors.New("DNS-фрагмент должен быть объектом JSON/JSONC")
	}
	return root, nil
}

func findDNSSource(c Config) (dnsSource, error) {
	var found dnsSource
	entries, err := os.ReadDir(c.ConfigDir)
	if err != nil {
		return found, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(c.ConfigDir, entry.Name())
		b, readErr := readLimited(path, 8*1024*1024)
		if readErr != nil {
			return found, readErr
		}
		root, parseErr := parseDNSFragment(b)
		if parseErr != nil {
			if strings.Contains(strings.ToLower(entry.Name()), "dns") || bytes.Contains(b, []byte(`"dns"`)) {
				return found, fmt.Errorf("не могу безопасно прочитать %s: %w", entry.Name(), parseErr)
			}
			continue
		}
		raw, hasDNS := root["dns"]
		if !hasDNS {
			continue
		}
		if found.path != "" {
			return found, errors.New("найдено несколько DNS-фрагментов Xray; автоматическое изменение небезопасно")
		}
		var dns map[string]json.RawMessage
		if err := json.Unmarshal(raw, &dns); err != nil || dns == nil {
			return found, fmt.Errorf("некорректный объект dns в %s", entry.Name())
		}
		found = dnsSource{path: path, original: b, root: root, dns: dns}
	}
	if found.path != "" {
		return found, nil
	}
	path := filepath.Join(c.ConfigDir, "02_hotwatcher_dns.json")
	if _, err := os.Lstat(path); err == nil {
		return found, errors.New("02_hotwatcher_dns.json уже существует без объекта dns; файл не изменён")
	} else if !os.IsNotExist(err) {
		return found, err
	}
	return dnsSource{path: path, root: map[string]json.RawMessage{}, dns: map[string]json.RawMessage{}, created: true}, nil
}

// DOH Local Mode bypasses routing, including rules matching dns.tag. Refuse
// automatic replacement when a configured DNS-over-proxy route would be lost.
func dnsTagRouted(c Config, tag string) (bool, error) {
	if tag == "" {
		return false, nil
	}
	entries, err := os.ReadDir(c.ConfigDir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		b, err := readLimited(filepath.Join(c.ConfigDir, entry.Name()), 8*1024*1024)
		if err != nil {
			return false, err
		}
		root, err := parseDNSFragment(b)
		if err != nil {
			if bytes.Contains(b, []byte(`"routing"`)) {
				return false, fmt.Errorf("не могу проверить маршрутизацию DNS в %s: %w", entry.Name(), err)
			}
			continue
		}
		raw := root["routing"]
		if len(raw) == 0 {
			continue
		}
		var routing struct {
			Rules []struct {
				InboundTag json.RawMessage `json:"inboundTag"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(raw, &routing); err != nil {
			return false, fmt.Errorf("не могу проверить маршрутизацию DNS в %s: %w", entry.Name(), err)
		}
		for _, rule := range routing.Rules {
			if len(rule.InboundTag) == 0 {
				continue
			}
			var tags []string
			if err := json.Unmarshal(rule.InboundTag, &tags); err != nil {
				var single string
				if json.Unmarshal(rule.InboundTag, &single) != nil {
					return false, errors.New("не могу проверить inboundTag в маршрутизации DNS")
				}
				tags = []string{single}
			}
			for _, used := range tags {
				if used == tag {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (e *Engine) DNSStatus() (DNSStatus, error) {
	src, err := findDNSSource(e.C)
	if err != nil {
		return DNSStatus{}, err
	}
	status := DNSStatus{ConfigFile: src.path, Servers: []string{}}
	if raw := src.dns["enableParallelQuery"]; len(raw) != 0 {
		_ = json.Unmarshal(raw, &status.ParallelQueries)
	}
	var servers []json.RawMessage
	if err := json.Unmarshal(src.dns["servers"], &servers); err == nil {
		for _, item := range servers {
			var address string
			if json.Unmarshal(item, &address) == nil {
				status.Servers = append(status.Servers, address)
			} else {
				status.Servers = append(status.Servers, "(сервер с отдельными правилами)")
			}
		}
	}
	var journal dnsJournal
	if err := mustJSON(e.dnsJournalPath(), &journal); err == nil {
		status.Managed = journal.Schema == 1 && journal.Path == src.path
		if status.Managed {
			current, readErr := readLimited(src.path, 8*1024*1024)
			if readErr != nil || digest(current) != journal.AppliedHash {
				status.Note = "DNS-файл изменился после включения; автоматический откат требует проверки"
			}
			status.RuntimeActivationUnverified = true // Live DNS state is not exposed by Xray API.
		} else {
			status.Note = "резервная копия DNS указывает на другой файл; требуется ручная проверка"
		}
	} else if !os.IsNotExist(err) {
		return status, errors.New("повреждён файл резервной копии DNS")
	}
	if src.created && status.Note == "" {
		status.Note = "DNS-фрагмент Xray отсутствует; текущий Xray использует системный DNS"
	}
	return status, nil
}

func prepareDNS(src dnsSource, available []dnsCandidate) ([]byte, []string, error) {
	if len(available) < 2 {
		return nil, nil, errors.New("доступно менее двух доверенных DNS-провайдеров; конфигурация не изменена")
	}
	dns := make(map[string]json.RawMessage, len(src.dns))
	for key, value := range src.dns {
		dns[key] = value
	}
	root := make(map[string]json.RawMessage, len(src.root))
	for key, value := range src.root {
		root[key] = value
	}
	if raw := dns["servers"]; len(raw) > 0 {
		var old []json.RawMessage
		if err := json.Unmarshal(raw, &old); err != nil {
			return nil, nil, errors.New("неподдерживаемый список DNS-серверов; конфигурация не изменена")
		}
		for _, item := range old {
			var simple string
			if json.Unmarshal(item, &simple) != nil {
				return nil, nil, errors.New("DNS содержит серверы с отдельными правилами; автоматический режим их не заменяет")
			}
			if specialDNSResolver(simple) {
				return nil, nil, fmt.Errorf("DNS содержит локальный или специальный сервер %q; автоматическая замена могла бы нарушить локальные домены", simple)
			}
		}
	}
	var hosts map[string]json.RawMessage
	if raw := dns["hosts"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &hosts); err != nil || hosts == nil {
			return nil, nil, errors.New("неподдерживаемый DNS hosts; конфигурация не изменена")
		}
	} else {
		hosts = map[string]json.RawMessage{}
	}
	servers := make([]string, 0, len(available))
	for _, candidate := range available {
		endpoint, err := url.Parse(candidate.URL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() != candidate.Hostname || endpoint.Path == "" {
			return nil, nil, errors.New("неверный адрес доверенного DNS-провайдера")
		}
		// The direct DoH probe above only proves direct access. Xray's plain
		// https:// DoH enters routing and may recursively require the proxy
		// whose server hostname is being resolved. Match the probed route.
		endpoint.Scheme = "https+local"
		servers = append(servers, endpoint.String())
		if candidate.Hostname == candidate.BootstrapIP {
			continue
		}
		if existing, ok := hosts[candidate.Hostname]; ok {
			var address string
			if json.Unmarshal(existing, &address) == nil && (address == candidate.BootstrapIP || candidate.Hostname == "dns.google" && address == "8.8.4.4") {
				continue
			}
			var addresses []string
			if candidate.Hostname == "dns.google" && json.Unmarshal(existing, &addresses) == nil && len(addresses) > 0 {
				trusted := true
				for _, addr := range addresses {
					if addr != "8.8.8.8" && addr != "8.8.4.4" {
						trusted = false
					}
				}
				if trusted {
					continue
				}
			}
			return nil, nil, fmt.Errorf("DNS hosts для %s уже задан иначе; конфигурация не изменена", candidate.Hostname)
		} else {
			hosts[candidate.Hostname], _ = json.Marshal(candidate.BootstrapIP)
		}
	}
	dns["hosts"], _ = json.Marshal(hosts)
	dns["servers"], _ = json.Marshal(servers)
	dns["enableParallelQuery"] = json.RawMessage("true")
	if len(dns["queryStrategy"]) == 0 {
		dns["queryStrategy"] = json.RawMessage(`"UseIP"`)
	}
	root["dns"], _ = json.Marshal(dns)
	return encode(root), servers, nil
}

func specialDNSResolver(server string) bool {
	s := strings.ToLower(strings.TrimSpace(server))
	if s == "localhost" || s == "fakedns" || strings.HasPrefix(s, "https+local://") || strings.HasPrefix(s, "quic+local://") {
		return true
	}
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		s = u.Hostname()
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if s == "localhost" || strings.HasSuffix(s, ".local") || strings.HasSuffix(s, ".lan") || strings.HasSuffix(s, ".home.arpa") {
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	return false
}

func validateDNSStaged(c Config, target string, candidate []byte) error {
	if err := privateDir(c.StateDir); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(c.StateDir, "dns-validate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	entries, err := os.ReadDir(c.ConfigDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(c.ConfigDir, entry.Name())
		b, err := readLimited(path, 8*1024*1024)
		if err != nil {
			return err
		}
		if path == target {
			b = candidate
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), b, 0600); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(target)), candidate, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := (Xray{C: c}).run(nil, "run", "-test", "-confdir", dir); err != nil {
		return fmt.Errorf("Xray отклонил подготовленную DNS-конфигурацию: %w", err)
	}
	return nil
}

func (e *Engine) DNSAutoOn() (DNSChange, error) {
	var result DNSChange
	if err := privateDir(e.C.StateDir); err != nil {
		return result, err
	}
	if _, err := os.Lstat(e.dnsJournalPath()); err == nil {
		return result, errors.New("DNS auto уже подготовлен; проверьте dns status или выполните dns auto off")
	} else if !os.IsNotExist(err) {
		return result, err
	}
	src, err := findDNSSource(e.C)
	if err != nil {
		return result, err
	}
	var tag string
	if raw := src.dns["tag"]; len(raw) != 0 {
		if err := json.Unmarshal(raw, &tag); err != nil {
			return result, errors.New("неверный tag в DNS-конфигурации")
		}
	}
	if routed, err := dnsTagRouted(e.C, tag); err != nil {
		return result, err
	} else if routed {
		return result, errors.New("DNS tag направлен через routing; прямой DoH изменил бы DNS-over-VLESS, конфигурация не изменена")
	}
	if _, _, err := prepareDNS(src, dnsCandidates); err != nil {
		return result, err
	}
	probes, err := e.DNSTest()
	if err != nil {
		return result, err
	}
	result.Probes = probes
	available := []dnsCandidate{}
	for _, candidate := range dnsCandidates {
		for _, probe := range probes {
			if candidate.Name == probe.Name && probe.Success {
				available = append(available, candidate)
			}
		}
	}
	prepared, servers, err := prepareDNS(src, available)
	if err != nil {
		return result, err
	}
	if err := validateDNSStaged(e.C, src.path, prepared); err != nil {
		return result, err
	}
	preparedRoot, err := parseDNSFragment(prepared)
	if err != nil {
		return result, err
	}
	var preparedDNS map[string]json.RawMessage
	if err := json.Unmarshal(preparedRoot["dns"], &preparedDNS); err != nil {
		return result, err
	}
	direct := map[string]any{"tag": "hw-dns-direct", "protocol": "freedom", "settings": map[string]any{}}
	if _, err := e.probeDNSRoute(preparedDNS, direct); err != nil {
		return result, fmt.Errorf("новый DNS не ответил в изолированном Xray; конфигурация не изменена: %w", err)
	}
	if err := dnsSourceUnchanged(src); err != nil {
		return result, err
	}
	journal := dnsJournal{Schema: 1, Path: src.path, Original: src.original, OriginalHash: digest(src.original), AppliedHash: digest(prepared), Created: src.created, At: e.Now().UTC()}
	if err := atomicWrite(e.dnsJournalPath(), encode(journal), 0600); err != nil {
		return result, err
	}
	if err := dnsSourceUnchanged(src); err != nil {
		if removeErr := removeSync(e.dnsJournalPath()); removeErr != nil {
			return result, fmt.Errorf("%v; резервная копия не удалена: %w", err, removeErr)
		}
		return result, err
	}
	if err := atomicWrite(src.path, prepared, 0600); err != nil {
		current, readErr := readLimited(src.path, 8*1024*1024)
		if readErr == nil && digest(current) == journal.AppliedHash {
			return result, fmt.Errorf("DNS-файл записан, но подтверждение записи не удалось; резервная копия сохранена, проверьте dns status: %w", err)
		}
		if (readErr == nil && digest(current) == journal.OriginalHash) || (os.IsNotExist(readErr) && journal.Created) {
			if removeErr := removeSync(e.dnsJournalPath()); removeErr != nil {
				return result, fmt.Errorf("DNS-файл не записан; не удалось убрать резервную копию: %w", removeErr)
			}
		}
		return result, fmt.Errorf("DNS-файл не подтверждён; проверьте dns status, резервная копия сохранена при неопределённом состоянии: %w", err)
	}
	result.ConfigFile, result.Servers = src.path, servers
	result.Restart = "Проверка: xkeen -xtest; затем вне игры: xkeen -restart"
	return result, nil
}

func (e *Engine) DNSAutoOff() error {
	var journal dnsJournal
	if err := mustJSON(e.dnsJournalPath(), &journal); err != nil {
		return err
	}
	if journal.Schema != 1 || filepath.Dir(journal.Path) != filepath.Clean(e.C.ConfigDir) || !strings.HasSuffix(filepath.Base(journal.Path), ".json") || journal.OriginalHash != digest(journal.Original) {
		return errors.New("повреждена резервная копия DNS; автоматическое восстановление остановлено")
	}
	current, err := readLimited(journal.Path, 8*1024*1024)
	if os.IsNotExist(err) && journal.Created {
		current = nil
	} else if err != nil {
		return err
	}
	if digest(current) != journal.AppliedHash && digest(current) != journal.OriginalHash {
		return errors.New("DNS-файл изменён после включения; автоматическое восстановление остановлено")
	}
	if journal.Created {
		if err := removeSync(journal.Path); err != nil {
			return err
		}
	} else if err := atomicWrite(journal.Path, journal.Original, 0600); err != nil {
		return err
	}
	return removeSync(e.dnsJournalPath())
}
