package hotwatcher

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FetchedKey struct {
	Tag       string   `json:"tag"`
	Name      string   `json:"name"`
	Checked   bool     `json:"checked"`
	Verified  bool     `json:"verified"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
}

type fetchedKeys struct {
	Schema int          `json:"schema"`
	Time   time.Time    `json:"time"`
	Keys   []FetchedKey `json:"keys"`
}

type KeyInventoryEntry struct {
	FetchedKey
	Selected bool
	Applied  bool
	Latest   bool
}

type KeyInventory struct {
	Selected         string
	FetchedAt        *time.Time
	Keys             []KeyInventoryEntry
	Note             string
	LastCheckAgo     *time.Duration
	LastCheckSuccess *bool
	SelectedAgo      *time.Duration
}

func (e *Engine) fetchedPath() string { return filepath.Join(e.C.StateDir, "last-fetched-keys.json") }

// SaveFetched stores only display names, opaque tags and probe outcomes. It
// does not copy subscription URLs or outbound configuration to this file.
func (e *Engine) SaveFetched(parsed Parsed, verified map[string]time.Duration, checked bool) error {
	keys := make([]FetchedKey, 0, len(parsed.Nodes))
	for _, node := range parsed.Nodes {
		entry := FetchedKey{Tag: node.Tag, Name: safeLabel(node.Name), Checked: checked}
		if latency, ok := verified[node.Tag]; ok {
			ms := float64(latency.Microseconds()) / 1000
			entry.Verified, entry.LatencyMS = true, &ms
		}
		keys = append(keys, entry)
	}
	return atomicWrite(e.fetchedPath(), encode(fetchedKeys{Schema: 1, Time: e.Now(), Keys: keys}), 0600)
}

// KeysSnapshot is immediate and independent of the Xray API. It shows the
// latest fetched subscription as well as still-applied older keys.
func (e *Engine) KeysSnapshot() (KeyInventory, error) {
	var report KeyInventory
	s, err := e.state()
	if err != nil {
		return report, err
	}
	if s == nil {
		return report, errors.New("not adopted; run adopt before keys")
	}
	report.Selected = s.Selected
	if age, ok := elapsed(e.Now(), s.SelectedAt); ok {
		report.SelectedAgo = &age
	}
	if marker, markerErr := readPrivateOptional(filepath.Join(e.C.StateDir, "last-check.json")); markerErr == nil {
		var check struct {
			Time    time.Time `json:"time"`
			Success bool      `json:"success"`
		}
		if json.Unmarshal(marker, &check) == nil {
			if age, ok := elapsed(e.Now(), check.Time); ok {
				report.LastCheckAgo, report.LastCheckSuccess = &age, &check.Success
			}
		}
	}
	active := make(map[string]Node, len(s.Active))
	for _, node := range s.Active {
		active[node.Tag] = node
	}
	b, err := readPrivate(e.fetchedPath(), 128*1024)
	var fetched fetchedKeys
	if err == nil {
		if json.Unmarshal(b, &fetched) != nil || fetched.Schema != 1 || len(fetched.Keys) > e.C.MaxNodes {
			report.Note = "Последний список загрузки повреждён; показаны применённые ключи."
		} else {
			valid := true
			seen := map[string]bool{}
			for _, key := range fetched.Keys {
				if !strings.HasPrefix(key.Tag, TagPrefix) || seen[key.Tag] {
					valid = false
					break
				}
				seen[key.Tag] = true
			}
			if valid {
				report.FetchedAt = &fetched.Time
				for _, key := range fetched.Keys {
					_, applied := active[key.Tag]
					report.Keys = append(report.Keys, KeyInventoryEntry{FetchedKey: key, Selected: key.Tag == s.Selected, Applied: applied, Latest: true})
				}
			} else {
				report.Note = "Последний список загрузки повреждён; показаны применённые ключи."
			}
		}
	} else if !os.IsNotExist(err) {
		report.Note = "Последний список загрузки недоступен; показаны применённые ключи."
	}
	seen := map[string]bool{}
	for _, key := range report.Keys {
		seen[key.Tag] = true
	}
	for _, node := range s.Active {
		if !seen[node.Tag] {
			report.Keys = append(report.Keys, KeyInventoryEntry{FetchedKey: FetchedKey{Tag: node.Tag, Name: safeLabel(node.Name)}, Selected: node.Tag == s.Selected, Applied: true})
		}
	}
	sort.Slice(report.Keys, func(i, j int) bool {
		a, b := report.Keys[i], report.Keys[j]
		if a.Selected != b.Selected {
			return a.Selected
		}
		if a.Latest != b.Latest {
			return a.Latest
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Tag < b.Tag
	})
	return report, nil
}
