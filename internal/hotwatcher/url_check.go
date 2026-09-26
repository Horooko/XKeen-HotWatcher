package hotwatcher

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type URLTestResult struct {
	Site      string   `json:"site"`
	OK        bool     `json:"ok"`
	Completed bool     `json:"completed,omitempty"`
	Status    int      `json:"status,omitempty"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type URLTestReport struct {
	Tag           string          `json:"tag"`
	Time          time.Time       `json:"time"`
	Passed        bool            `json:"passed"`
	ProgressKnown bool            `json:"progress_known,omitempty"`
	Results       []URLTestResult `json:"results"`
}

type urlTestSettings struct {
	Schema int      `json:"schema"`
	Sites  []string `json:"sites"`
}

// URL Test accepts only public HTTPS origins. It must not become a browser
// endpoint for probing router services or URLs containing credentials.
func NormalizeURLTestSites(input []string) ([]string, error) {
	if len(input) < 1 || len(input) > 12 {
		return nil, errors.New("URL Test: укажите от 1 до 12 сайтов")
	}
	result := make([]string, 0, len(input))
	seen := map[string]bool{}
	for _, raw := range input {
		raw = strings.TrimSpace(raw)
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("URL Test: разрешены только HTTPS-домены без пути, порта и параметров")
		}
		host := strings.ToLower(u.Hostname())
		if len(host) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
			return nil, errors.New("URL Test: требуется публичное доменное имя")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("URL Test: неверное доменное имя")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return nil, errors.New("URL Test: домен должен содержать только латинские буквы, цифры и дефис")
				}
			}
		}
		canonical := "https://" + host + "/"
		if seen[canonical] {
			return nil, fmt.Errorf("URL Test: сайт %s повторяется", host)
		}
		seen[canonical] = true
		result = append(result, canonical)
	}
	return result, nil
}

func (e *Engine) urlTestSettingsPath() string {
	return filepath.Join(e.C.StateDir, "url-test-sites.json")
}
func (e *Engine) urlTestReportPath() string { return filepath.Join(e.C.StateDir, "url-test-last.json") }

func (e *Engine) URLTestSites() ([]string, error) {
	var settings urlTestSettings
	if err := mustJSON(e.urlTestSettingsPath(), &settings); os.IsNotExist(err) {
		return NormalizeURLTestSites(e.C.URLTestSites)
	} else if err != nil {
		return nil, errors.New("не удалось прочитать сохранённые сайты URL Test")
	}
	if settings.Schema != 1 {
		return nil, errors.New("неподдерживаемый формат списка URL Test")
	}
	return NormalizeURLTestSites(settings.Sites)
}

func (e *Engine) SaveURLTestSites(sites []string) ([]string, error) {
	normalized, err := NormalizeURLTestSites(sites)
	if err != nil {
		return nil, err
	}
	if err := privateDir(e.C.StateDir); err != nil {
		return nil, err
	}
	if err := atomicWrite(e.urlTestSettingsPath(), encode(urlTestSettings{Schema: 1, Sites: normalized}), 0600); err != nil {
		return nil, err
	}
	return normalized, nil
}

func (e *Engine) LastURLTest() (*URLTestReport, error) {
	var report URLTestReport
	if err := mustJSON(e.urlTestReportPath(), &report); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("не удалось прочитать последний URL Test")
	}
	if report.Tag == "" || report.Time.IsZero() || len(report.Results) < 1 || len(report.Results) > 12 {
		return nil, errors.New("повреждён отчёт URL Test")
	}
	return &report, nil
}

func (e *Engine) urlTestNode(node Node) (URLTestReport, error) {
	return e.urlTestNodeProgress(node, nil)
}

func (e *Engine) urlTestNodeProgress(node Node, progress func(URLTestReport)) (URLTestReport, error) {
	sites, err := e.URLTestSites()
	if err != nil {
		return URLTestReport{}, err
	}
	var report URLTestReport
	var probeErr error
	if runtime, ok := e.R.(interface {
		URLTestWithProgress(Node, []string, func(URLTestReport)) (URLTestReport, error)
	}); ok && progress != nil {
		report, probeErr = runtime.URLTestWithProgress(node, sites, progress)
	} else {
		report, probeErr = e.R.URLTest(node, sites)
	}
	report.Tag, report.Time = node.Tag, e.Now()
	if len(report.Results) > 0 {
		if writeErr := atomicWrite(e.urlTestReportPath(), encode(report), 0600); writeErr != nil {
			e.event("url_test_report_write_failed", map[string]any{"tag": node.Tag})
		}
	}
	if probeErr != nil {
		return report, probeErr
	}
	if !report.Passed {
		return report, errors.New("URL Test: один или несколько сайтов не открылись через этот ключ")
	}
	return report, nil
}

// URLTestKey tests a saved key without switching the production balancer.
func (e *Engine) URLTestKey(tag string) (URLTestReport, error) {
	return e.URLTestKeyWithProgress(tag, nil)
}

// URLTestKeyWithProgress publishes immutable snapshots as each site finishes.
// The callback must return promptly; the final report is saved by urlTestNode.
func (e *Engine) URLTestKeyWithProgress(tag string, progress func(URLTestReport)) (URLTestReport, error) {
	s, err := e.state()
	if err != nil {
		return URLTestReport{}, err
	}
	if s == nil {
		return URLTestReport{}, errors.New("ключи ещё не подключены")
	}
	if tag == "" {
		tag = s.Selected
	}
	node, ok := findNode(s.Active, tag)
	if !ok {
		return URLTestReport{}, errors.New("ключ не найден в применённом списке")
	}
	return e.urlTestNodeProgress(node, progress)
}
