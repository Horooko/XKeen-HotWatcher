package hotwatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The allowlist is compiled in. Browser input can select entries, never supply
// arbitrary probe URLs or bootstrap addresses.
type DNSProvider struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Selected bool   `json:"selected"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

// Keep the complete list from the user's DNS client visible in the editor.
// Entries here are references, not probe targets: their protocols either
// cannot be represented by Xray's direct DoH mode or could recurse through
// transparent routing. The UI explains the exact reason on activation.
var dnsReferenceProviders = []DNSProvider{
	{ID: "ref-local", Name: "Local", URL: "local", Reason: "локальный DNS зависит от системного resolver и может замкнуть маршрут Xray"},
	{ID: "ref-dhcp", Name: "DHCP", URL: "dhcp://auto", Reason: "DHCP DNS зависит от системного resolver и не является прямым DoH"},
	{ID: "ref-alidns-udp-1", Name: "AliDNS", URL: "udp://223.5.5.5", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-alidns-udp-2", Name: "AliDNS", URL: "udp://223.6.6.6", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-alidns-tls-1", Name: "AliDNS", URL: "tls://223.5.5.5", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-alidns-tls-2", Name: "AliDNS", URL: "tls://223.6.6.6", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-alidns-tls-domain", Name: "AliDNS", URL: "tls://dns.alidns.com", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-alidns-https-domain", Name: "AliDNS", URL: "https://dns.alidns.com/dns-query", Reason: "прямой DoH с доменным именем использует системный DNS и может замкнуть маршрут"},
	{ID: "ref-alidns-udp-v6", Name: "AliDNS", URL: "udp://[2400:3200::1]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-dnspod-tls-dot", Name: "DNSPod", URL: "tls://dot.pub", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-dnspod-tls-dns", Name: "DNSPod", URL: "tls://dns.pub", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-dnspod-https-domain", Name: "DNSPod", URL: "https://doh.pub/dns-query", Reason: "прямой DoH с доменным именем использует системный DNS и может замкнуть маршрут"},
	{ID: "ref-dnspod-udp-v6", Name: "DNSPod", URL: "udp://[2402:4e00::]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-cloudflare-udp-1", Name: "Cloudflare", URL: "udp://1.0.0.1", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-cloudflare-udp-2", Name: "Cloudflare", URL: "udp://1.1.1.1", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-cloudflare-tls-1", Name: "Cloudflare", URL: "tls://1.0.0.1", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-cloudflare-tls-2", Name: "Cloudflare", URL: "tls://1.1.1.1", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-cloudflare-https-domain", Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Reason: "прямой DoH с доменным именем использует системный DNS и может замкнуть маршрут"},
	{ID: "ref-cloudflare-udp-v6-1", Name: "Cloudflare", URL: "udp://[2606:4700:4700::1111]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-cloudflare-udp-v6-2", Name: "Cloudflare", URL: "udp://[2606:4700:4700::1001]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-cloudflare-tls-v6-1", Name: "Cloudflare", URL: "tls://[2606:4700:4700::1111]", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-cloudflare-tls-v6-2", Name: "Cloudflare", URL: "tls://[2606:4700:4700::1001]", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-google-udp-1", Name: "Google", URL: "udp://8.8.8.8", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-google-udp-2", Name: "Google", URL: "udp://8.8.4.4", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-google-tls-1", Name: "Google", URL: "tls://8.8.8.8", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-google-tls-2", Name: "Google", URL: "tls://8.8.4.4", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-google-https-domain", Name: "Google", URL: "https://dns.google/dns-query", Reason: "прямой DoH с доменным именем использует системный DNS и может замкнуть маршрут"},
	{ID: "ref-google-h3-1", Name: "Google", URL: "h3://8.8.8.8/dns-query", Reason: "Xray DNS не поддерживает DoH3 h3://"},
	{ID: "ref-google-h3-2", Name: "Google", URL: "h3://8.8.4.4/dns-query", Reason: "Xray DNS не поддерживает DoH3 h3://"},
	{ID: "ref-google-udp-v6-1", Name: "Google", URL: "udp://[2001:4860:4860::8888]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-google-udp-v6-2", Name: "Google", URL: "udp://[2001:4860:4860::8844]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-google-tls-v6-1", Name: "Google", URL: "tls://[2001:4860:4860::8888]", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-google-tls-v6-2", Name: "Google", URL: "tls://[2001:4860:4860::8844]", Reason: "Xray DNS не поддерживает DoT tls:// напрямую"},
	{ID: "ref-trafficroute-udp-1", Name: "TrafficRoute", URL: "udp://180.184.1.1", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-trafficroute-udp-2", Name: "TrafficRoute", URL: "udp://180.184.2.2", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-opendns-udp-1", Name: "OpenDNS", URL: "udp://208.67.222.222", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-opendns-udp-2", Name: "OpenDNS", URL: "udp://208.67.220.220", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-yandex-udp-1", Name: "Yandex", URL: "udp://77.88.8.1", Reason: "UDP DNS входит в routing Xray; Яндекс также исключён из выбора по умолчанию"},
	{ID: "ref-yandex-udp-2", Name: "Yandex", URL: "udp://77.88.8.8", Reason: "UDP DNS входит в routing Xray; Яндекс также исключён из выбора по умолчанию"},
	{ID: "ref-yandex-udp-domain", Name: "Yandex", URL: "udp://dns.yandex.net", Reason: "UDP DNS и системное разрешение имени могут замкнуть маршрут Xray"},
	{ID: "ref-yandex-udp-v6-1", Name: "Yandex", URL: "udp://[2a02:6b8::feed:0ff]", Reason: "UDP DNS входит в routing Xray; Яндекс также исключён из выбора по умолчанию"},
	{ID: "ref-yandex-udp-v6-2", Name: "Yandex", URL: "udp://[2a02:6b8:0:1::feed:0ff]", Reason: "UDP DNS входит в routing Xray; Яндекс также исключён из выбора по умолчанию"},
	{ID: "ref-comodo-udp-1", Name: "Comodo", URL: "udp://8.26.56.26", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-comodo-udp-2", Name: "Comodo", URL: "udp://8.20.247.20", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-adguard-udp-1", Name: "AdGuard", URL: "udp://94.140.14.14", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-adguard-udp-2", Name: "AdGuard", URL: "udp://94.140.15.15", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-adguard-quic", Name: "AdGuard", URL: "quic://dns.adguard.com", Reason: "DoQ есть в Xray как quic+local, но для него пока нет полноценной DNS-пробы"},
	{ID: "ref-adguard-udp-v6-1", Name: "AdGuard", URL: "udp://[2a10:50c0::ad1:ff]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
	{ID: "ref-adguard-udp-v6-2", Name: "AdGuard", URL: "udp://[2a10:50c0::ad2:ff]", Reason: "UDP DNS входит в routing Xray; для DNS auto нужен прямой DoH"},
}

type dnsProviderPreferences struct {
	Schema     int      `json:"schema"`
	IDs        []string `json:"ids"`
	AutoSelect *bool    `json:"auto_select,omitempty"`
}

func defaultDNSProviderIDs() []string {
	ids := make([]string, 0, len(dnsCandidates))
	for _, candidate := range dnsCandidates {
		if candidate.Default {
			ids = append(ids, candidate.ID)
		}
	}
	return ids
}

func dnsCandidatesForIDs(ids []string) ([]dnsCandidate, error) {
	if len(ids) == 0 {
		return nil, errors.New("выберите хотя бы один DNS-провайдер")
	}
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if selected[id] {
			return nil, fmt.Errorf("DNS-провайдер %q указан дважды", id)
		}
		selected[id] = true
	}
	result := make([]dnsCandidate, 0, len(ids))
	for _, candidate := range dnsCandidates {
		if selected[candidate.ID] {
			result = append(result, candidate)
			delete(selected, candidate.ID)
		}
	}
	if len(selected) != 0 {
		return nil, errors.New("неизвестный DNS-провайдер")
	}
	return result, nil
}

func (e *Engine) dnsProviderPreferencesPath() string {
	return filepath.Join(e.C.StateDir, "dns-provider-preferences.json")
}

func (e *Engine) DNSSelectedProviderIDs() ([]string, error) {
	var prefs dnsProviderPreferences
	err := mustJSON(e.dnsProviderPreferencesPath(), &prefs)
	if os.IsNotExist(err) {
		return defaultDNSProviderIDs(), nil
	}
	if err != nil {
		return nil, err
	}
	if prefs.Schema != 1 {
		return nil, errors.New("неизвестная версия настроек DNS-провайдеров")
	}
	candidates, err := dnsCandidatesForIDs(prefs.IDs)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.ID)
	}
	return ids, nil
}

func (e *Engine) DNSAutoSelectionEnabled() (bool, error) {
	var prefs dnsProviderPreferences
	err := mustJSON(e.dnsProviderPreferencesPath(), &prefs)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if prefs.Schema != 1 {
		return false, errors.New("неизвестная версия настроек DNS-провайдеров")
	}
	if prefs.AutoSelect == nil {
		return true, nil
	}
	return *prefs.AutoSelect, nil
}

func (e *Engine) SaveDNSProviderSelection(ids []string, autoSelect bool) error {
	candidates, err := dnsCandidatesForIDs(ids)
	if err != nil {
		return err
	}
	ordered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate.ID)
	}
	if err := privateDir(e.C.StateDir); err != nil {
		return err
	}
	return atomicWrite(e.dnsProviderPreferencesPath(), encode(dnsProviderPreferences{Schema: 1, IDs: ordered, AutoSelect: &autoSelect}), 0600)
}

func (e *Engine) DNSProviderCatalog() ([]DNSProvider, []string, error) {
	ids, err := e.DNSSelectedProviderIDs()
	if err != nil {
		return nil, nil, err
	}
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		selected[id] = true
	}
	providers := make([]DNSProvider, 0, len(dnsCandidates)+len(dnsReferenceProviders))
	for _, candidate := range dnsCandidates {
		providers = append(providers, DNSProvider{ID: candidate.ID, Name: candidate.Name, URL: candidate.URL, Selected: selected[candidate.ID], Eligible: true})
	}
	providers = append(providers, dnsReferenceProviders...)
	return providers, ids, nil
}
