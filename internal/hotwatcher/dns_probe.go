package hotwatcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type dnsCandidate struct {
	Name        string
	URL         string
	Hostname    string
	BootstrapIP string
}

// Only explicitly trusted providers are candidates. No system, DHCP, local,
// plaintext or Yandex resolver enters automatic selection.
var dnsCandidates = []dnsCandidate{
	{Name: "Cloudflare", URL: "https://1.1.1.1/dns-query", Hostname: "1.1.1.1", BootstrapIP: "1.1.1.1"},
	{Name: "Google", URL: "https://dns.google/dns-query", Hostname: "dns.google", BootstrapIP: "8.8.8.8"},
}

type DNSProbeResult struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Success   bool     `json:"success"`
	MedianMS  *float64 `json:"median_ms,omitempty"`
	Responses int      `json:"responses"`
	Note      string   `json:"note,omitempty"`
}

func dnsQuestion() ([]byte, uint16, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	// Standard recursive A query for example.com. The same wire format works
	// with every RFC 8484 DoH endpoint in the allowlist.
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	binary.BigEndian.PutUint16(q[:2], id)
	return q, id, nil
}

func validDNSAnswer(body []byte, id uint16) bool {
	if len(body) < 12 || binary.BigEndian.Uint16(body[:2]) != id {
		return false
	}
	flags := binary.BigEndian.Uint16(body[2:4])
	return flags&0x8000 != 0 && flags&0x000f == 0 && binary.BigEndian.Uint16(body[4:6]) == 1 && binary.BigEndian.Uint16(body[6:8]) > 0
}

func probeDoH(c Config, candidate dnsCandidate) (time.Duration, error) {
	endpoint, err := url.Parse(candidate.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() != candidate.Hostname || net.ParseIP(candidate.BootstrapIP) == nil {
		return 0, errors.New("неверная запись доверенного DNS-провайдера")
	}
	tlsSettings, err := tlsConfig(c)
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{
		TLSClientConfig:   tlsSettings,
		ForceAttemptHTTP2: true,
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil || !strings.EqualFold(host, candidate.Hostname) {
				return nil, errors.New("DNS-проба попыталась подключиться к другому адресу")
			}
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, net.JoinHostPort(candidate.BootstrapIP, port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("DNS-проба не следует перенаправлениям")
	}}
	query, id, err := dnsQuestion()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", candidate.URL, bytes.NewReader(query))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	started := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return 0, errors.New("DNS-запрос не завершился (сеть или TLS)")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "application/dns-message") {
		return 0, fmt.Errorf("неожиданный ответ DoH: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(body) > 4096 || !validDNSAnswer(body, id) {
		return 0, errors.New("DoH не вернул корректный ответ DNS")
	}
	return time.Since(started), nil
}

func (e *Engine) DNSTest() ([]DNSProbeResult, error) {
	results := make([]DNSProbeResult, len(dnsCandidates))
	var wg sync.WaitGroup
	for i, candidate := range dnsCandidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := DNSProbeResult{Name: candidate.Name, URL: candidate.URL}
			latencies := []time.Duration{}
			for n := 0; n < 3; n++ {
				if latency, err := probeDoH(e.C, candidate); err == nil {
					latencies = append(latencies, latency)
				}
			}
			result.Responses = len(latencies)
			if len(latencies) >= 2 {
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				ms := float64(latencies[len(latencies)/2].Microseconds()) / 1000
				result.MedianMS, result.Success = &ms, true
			} else {
				result.Note = "меньше двух успешных DNS-ответов из трёх"
			}
			results[i] = result
		}()
	}
	wg.Wait()
	return results, nil
}
