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
	providers := make([]DNSProvider, 0, len(dnsCandidates))
	for _, candidate := range dnsCandidates {
		providers = append(providers, DNSProvider{ID: candidate.ID, Name: candidate.Name, URL: candidate.URL, Selected: selected[candidate.ID], Eligible: true})
	}
	return providers, ids, nil
}
