package hotwatcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Retired struct {
	Node  Node      `json:"node"`
	After time.Time `json:"remove_after"`
}
type State struct {
	Schema        int       `json:"schema"`
	Selected      string    `json:"selected"`
	SelectionMode string    `json:"selection_mode,omitempty"`
	SelectedAt    time.Time `json:"selected_at,omitempty"`
	Active        []Node    `json:"active"`
	Retired       []Retired `json:"retired"`
	DiskHash      string    `json:"disk_hash"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type Transaction struct {
	Schema         int       `json:"schema"`
	Created        time.Time `json:"created"`
	Previous       *State    `json:"previous_state"`
	PreviousFile   []byte    `json:"previous_file"`
	PreviousTarget string    `json:"previous_target"`
	Next           State     `json:"next_state"`
}
type Engine struct {
	C       Config
	R       Runtime
	Fetcher func(Config) ([]byte, error)
	Now     func() time.Time
	// VerifiedLatencies is used only by an explicit hard-sync operation. Its
	// probes run while XKeen is stopped and must be discarded afterwards.
	VerifiedLatencies map[string]time.Duration
	UnreachableCount  int
}

func New(c Config) *Engine {
	return &Engine{C: c, R: Xray{c}, Fetcher: Fetch, Now: func() time.Time { return time.Now().UTC() }}
}
func (e *Engine) probe(node Node) error {
	if _, ok := e.VerifiedLatencies[node.Tag]; ok {
		return nil
	}
	if e.VerifiedLatencies != nil {
		return errors.New("candidate was not verified during direct sync")
	}
	return e.R.Probe(node)
}
func (e *Engine) probeLatency(node Node) (time.Duration, error) {
	if latency, ok := e.VerifiedLatencies[node.Tag]; ok {
		return latency, nil
	}
	if e.VerifiedLatencies != nil {
		return 0, errors.New("candidate was not verified during direct sync")
	}
	return e.R.ProbeLatency(node)
}
func (e *Engine) statePath() string   { return filepath.Join(e.C.StateDir, "state.json") }
func (e *Engine) journalPath() string { return filepath.Join(e.C.StateDir, "pending.json") }
func (e *Engine) held() bool          { _, er := os.Stat(filepath.Join(e.C.StateDir, "hold")); return er == nil }
func (e *Engine) state() (*State, error) {
	var s State
	err := mustJSON(e.statePath(), &s)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Schema != 1 || len(s.Active) == 0 || s.Selected == "" || (s.SelectionMode != "" && s.SelectionMode != "manual") {
		return nil, errors.New("invalid state schema or empty active pool")
	}
	for _, n := range s.Active {
		if !strings.HasPrefix(n.Tag, TagPrefix) || n.Outbound["tag"] != n.Tag {
			return nil, errors.New("invalid owned node in state")
		}
	}
	if _, ok := findNode(s.Active, s.Selected); !ok {
		return nil, errors.New("selected node is not active")
	}
	return &s, nil
}
func (e *Engine) pending() bool { _, err := os.Lstat(e.journalPath()); return err == nil }
func (e *Engine) checkDisk(s *State) ([]byte, error) {
	b, err := readLimited(outputFile(e.C), 8*1024*1024)
	if err != nil {
		return nil, errors.New("cannot read managed outbound file")
	}
	if s != nil && digest(b) != s.DiskHash {
		return nil, errors.New("outbound file was changed outside Hot Watcher; refusing to overwrite it")
	}
	return b, nil
}
func (e *Engine) event(name string, fields map[string]any) { _ = logEvent(e.C.StateDir, name, fields) }
func (e *Engine) Plan() (map[string]any, error) {
	b, er := e.Fetcher(e.C)
	if er != nil {
		return nil, er
	}
	p, er := Parse(b, e.C)
	if er != nil {
		return nil, er
	}
	s, er := e.state()
	if er != nil {
		return nil, er
	}
	current := []Node{}
	if s != nil {
		current = s.Active
	}
	added := 0
	for _, n := range p.Nodes {
		if _, ok := findNode(current, n.Tag); !ok {
			added++
		}
	}
	return map[string]any{"supported_nodes": len(p.Nodes), "ignored_non_vless": p.Skipped, "new_or_changed": added, "configuration_changed": !sameNodes(current, p.Nodes), "runtime_modified": false}, nil
}

// Sync must run under the filesystem lock. The selected node must pass an
// isolated end-to-end HTTP probe; unreachable nodes remain available for
// future checks but are not selected.
func (e *Engine) Sync(adopt bool) error { return e.sync(adopt, nil) }

// SyncPrepared applies an already downloaded and validated subscription. It is
// used by hard-sync after the direct download and isolated probes finish.
func (e *Engine) SyncPrepared(parsed Parsed) error { return e.sync(false, &parsed) }

func (e *Engine) sync(adopt bool, prepared *Parsed) error {
	e.UnreachableCount = 0
	if err := e.ensureSubscriptionMode(); err != nil {
		return err
	}
	if e.held() {
		e.event("held", nil)
		return nil
	}
	if e.pending() {
		return errors.New("pending transaction exists: inspect status, then run recover or abort")
	}
	s, er := e.state()
	if er != nil {
		return er
	}
	if s == nil && !adopt {
		return errors.New("first use requires adopt (backs up and takes ownership of generated_file)")
	}
	if s != nil && adopt {
		return errors.New("already adopted; use sync")
	}
	oldFile, er := e.checkDisk(s)
	if er != nil {
		return er
	}
	if er = checkSelector(e.C); er != nil {
		return er
	}
	var parsed Parsed
	if prepared == nil {
		b, fetchErr := e.Fetcher(e.C)
		if fetchErr != nil {
			return fetchErr
		}
		parsed, er = Parse(b, e.C)
		if er != nil {
			return er
		}
	} else {
		parsed = *prepared
		if len(parsed.Nodes) == 0 || len(parsed.Nodes) > e.C.MaxNodes {
			return errors.New("prepared subscription has no valid nodes")
		}
	}
	if prepared == nil {
		if cacheErr := e.SaveFetched(parsed, nil, false); cacheErr != nil {
			e.event("fetched_inventory_write_failed", map[string]any{"message": cacheErr.Error()})
		}
	}
	nodes := append([]Node(nil), parsed.Nodes...)
	if s != nil {
		for _, old := range s.Active {
			if !old.Emergency && (s.SelectionMode != "manual" || old.Tag != s.Selected) {
				continue
			}
			if index := nodeIndex(nodes, old.Tag); index >= 0 {
				if old.Emergency {
					nodes[index].Emergency = true
				}
			} else {
				nodes = append(nodes, old)
			}
		}
	}
	if len(nodes) > e.C.MaxNodes {
		return errors.New("слишком много ключей с учётом закреплённого и аварийного; старый список сохранён")
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Tag < nodes[j].Tag })
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	bal, er := e.R.Balance()
	if er != nil {
		return er
	}
	if s != nil && sameNodes(s.Active, nodes) {
		if er = e.reconcile(s, tags); er != nil {
			return er
		}
		if s.SelectionMode != "manual" && (e.C.SelectionPolicy == "latency" || e.VerifiedLatencies != nil) {
			selected, probeErr := e.fastest(nodes, s.Selected, s.SelectedAt)
			if probeErr != nil {
				return probeErr
			}
			if selected != s.Selected {
				return e.Select(selected)
			}
		} else if s.SelectionMode != "manual" {
			node, ok := findNode(nodes, s.Selected)
			if !ok {
				return errors.New("выбранный ключ отсутствует")
			}
			if _, er = e.urlTestNode(node); er != nil {
				return er
			}
		}
		e.event("unchanged", map[string]any{"active_nodes": len(s.Active), "ignored_non_vless": parsed.Skipped})
		if e.C.AutoGC {
			return e.gc(s)
		}
		return nil
	}
	oldTarget := bal.Override
	if oldTarget == "" && len(bal.Selected) > 0 {
		oldTarget = bal.Selected[0]
	}
	if s != nil {
		oldTarget = s.Selected
	}
	if oldTarget == "" || !tags[oldTarget] {
		return errors.New("cannot pin an existing outbound before update; balancer must have a live selection")
	}
	oldNodes := []Node{}
	if s != nil {
		oldNodes = s.Active
	}
	previousIdentity := ""
	if n, ok := findNode(oldNodes, oldTarget); ok {
		previousIdentity = n.Identity
	} else {
		previousIdentity = legacyIdentity(oldFile, oldTarget)
	}
	selected := choose(nodes, oldTarget, previousIdentity, e.C.PreferredName)
	if s != nil && s.SelectionMode == "manual" {
		selected = s.Selected
	} else if e.C.SelectionPolicy == "latency" || e.VerifiedLatencies != nil {
		selectedAt := time.Time{}
		if s != nil && selected == s.Selected {
			selectedAt = s.SelectedAt
		}
		selected, er = e.fastest(nodes, selected, selectedAt)
		if er != nil {
			return er
		}
	} else {
		for _, n := range nodes {
			_, known := findNode(oldNodes, n.Tag)
			if !known || !tags[n.Tag] {
				if er = e.probe(n); er != nil {
					return fmt.Errorf("candidate %s failed health check; old configuration kept: %w", n.Tag, er)
				}
			}
		}
		if node, ok := findNode(nodes, selected); ok {
			if _, er = e.urlTestNode(node); er != nil {
				return er
			}
		}
	}
	if er = e.R.Validate(nodes, selected); er != nil {
		return er
	}
	retired := []Retired{}
	if s != nil {
		for _, r := range s.Retired {
			if _, active := findNode(nodes, r.Node.Tag); !active {
				retired = append(retired, r)
			}
		}
	}
	for _, n := range oldNodes {
		if _, ok := findNode(nodes, n.Tag); !ok {
			retired = append(retired, Retired{Node: n, After: e.Now().Add(time.Duration(e.C.GraceSeconds) * time.Second)})
		}
	}
	if len(retired) > e.C.MaxRetired {
		return errors.New("retired pool limit reached; run gc outside a game session before another update")
	}
	next := State{Schema: 1, Active: nodes, Retired: retired, Selected: selected, UpdatedAt: e.Now()}
	if s != nil {
		next.SelectionMode = s.SelectionMode
	}
	if s == nil || s.Selected != selected {
		next.SelectedAt = next.UpdatedAt
	} else {
		next.SelectedAt = s.SelectedAt
	}
	next.DiskHash = digest(configBytes(nodes, selected))
	t := Transaction{Schema: 1, Created: e.Now(), Previous: s, PreviousFile: oldFile, PreviousTarget: oldTarget, Next: next}
	if s == nil {
		// Never overwrite the original migration backup on retries.
		p := filepath.Join(e.C.StateDir, "pre-migration-outbounds.json")
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			if er = atomicWrite(p, oldFile, 0600); er != nil {
				return er
			}
		} else if err != nil {
			return err
		}
	}
	if len(encode(t)) > 16*1024*1024 {
		return errors.New("transaction exceeds 16 MiB limit; old configuration kept")
	}
	if er = atomicWrite(e.journalPath(), encode(t), 0600); er != nil {
		return er
	}
	e.event("prepared", map[string]any{"active_nodes": len(nodes), "selected": selected, "retired_nodes": len(retired)})
	// Freeze the old live target before staging additions into the prefix-matched pool.
	if er = e.setVerified(oldTarget); er != nil {
		return fmt.Errorf("transaction pending before staging: %w", er)
	}
	return e.commit(&t, false)
}

// fastest measures the complete HTTPS request through each isolated VLESS
// outbound. Unreachable nodes remain in the pool but are never selected.
// If no node passes, the old configuration is kept.
func (e *Engine) fastest(nodes []Node, fallback string, selectedAt time.Time) (string, error) {
	best := ""
	bestLatency := time.Duration(0)
	currentLatency := time.Duration(0)
	currentVerified := false
	type measured struct {
		node    Node
		latency time.Duration
	}
	var candidates []measured
	for _, n := range nodes {
		latency, err := e.probeLatency(n)
		if err != nil {
			e.UnreachableCount++
			continue
		}
		if best == "" || latency < bestLatency || (latency == bestLatency && n.Tag == fallback) {
			best, bestLatency = n.Tag, latency
		}
		candidates = append(candidates, measured{n, latency})
		if n.Tag == fallback {
			currentLatency, currentVerified = latency, true
		}
	}
	if best == "" {
		return "", errors.New("all active nodes failed HTTPS latency probes; old selection kept")
	}
	preferred := best
	if best != fallback && currentVerified {
		if age, ok := elapsed(e.Now(), selectedAt); ok && age < time.Duration(e.C.KeySwitchCooldownSeconds)*time.Second {
			preferred = fallback
		}
		gain := currentLatency - bestLatency
		minimum := time.Duration(e.C.KeySwitchMinImprovementMS) * time.Millisecond
		percentage := currentLatency * time.Duration(e.C.KeySwitchMinImprovementPercent) / 100
		if percentage > minimum {
			minimum = percentage
		}
		if gain < minimum {
			preferred = fallback
		}
	}
	if _, err := e.URLTestSites(); err != nil {
		return "", err
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].latency == candidates[j].latency {
			return candidates[i].node.Tag < candidates[j].node.Tag
		}
		return candidates[i].latency < candidates[j].latency
	})
	for _, candidate := range candidates {
		if candidate.node.Tag != preferred {
			continue
		}
		if _, err := e.urlTestNode(candidate.node); err == nil {
			return preferred, nil
		}
		e.UnreachableCount++
		break
	}
	for _, candidate := range candidates {
		if candidate.node.Tag == preferred {
			continue
		}
		if _, err := e.urlTestNode(candidate.node); err == nil {
			return candidate.node.Tag, nil
		}
		e.UnreachableCount++
	}
	return "", errors.New("URL Test: ни один ключ не открыл все обязательные сайты; старый выбор сохранён")
}
func (e *Engine) setVerified(tag string) error {
	if er := e.R.Override(tag); er != nil {
		return er
	}
	b, er := e.R.Balance()
	if er != nil {
		return er
	}
	if b.Override != tag {
		return errors.New("balancer override could not be verified")
	}
	return nil
}
func (e *Engine) commit(t *Transaction, reprobe bool) error {
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	if reprobe {
		n, _ := findNode(t.Next.Active, t.Next.Selected)
		if er = e.R.Probe(n); er != nil {
			return fmt.Errorf("pending selected node failed re-probe: %w", er)
		}
		if _, er = e.urlTestNode(n); er != nil {
			return fmt.Errorf("pending selected node failed URL Test: %w", er)
		}
	}
	for _, n := range t.Next.Active {
		if !tags[n.Tag] {
			if er = e.R.Add(n); er != nil {
				return errors.New("API add failed; transaction saved; old outbounds were not removed")
			}
			tags[n.Tag] = true
		}
	}
	actual, er := e.R.List()
	if er != nil {
		return er
	}
	for _, n := range t.Next.Active {
		if !actual[n.Tag] {
			return errors.New("API verification failed; pending transaction retained")
		}
	}
	if er = e.setVerified(t.Next.Selected); er != nil {
		return errors.New("selection switch could not be verified; pending transaction retained")
	}
	if er = atomicWrite(outputFile(e.C), configBytes(t.Next.Active, t.Next.Selected), 0600); er != nil {
		return errors.New("runtime selected new node, but disk write failed; run recover; do not restart Xray")
	}
	if er = atomicWrite(e.statePath(), encode(t.Next), 0600); er != nil {
		return errors.New("state write failed after runtime update; run recover")
	}
	if er = removeSync(e.journalPath()); er != nil {
		return er
	}
	e.event("applied", map[string]any{"selected": t.Next.Selected, "active_nodes": len(t.Next.Active), "retired_nodes": len(t.Next.Retired), "restart": false})
	return nil
}
func (e *Engine) Recover() error {
	if e.held() {
		return errors.New("hold is enabled; turn it off before recovering")
	}
	var t Transaction
	if er := mustJSON(e.journalPath(), &t); er != nil {
		return er
	}
	if er := validateTransaction(t); er != nil {
		return er
	}
	b, er := readLimited(outputFile(e.C), 8*1024*1024)
	if er != nil {
		return er
	}
	h := digest(b)
	if h != digest(t.PreviousFile) && h != t.Next.DiskHash {
		return errors.New("outbound file changed outside transaction; refusing recovery")
	}
	if er = e.R.Validate(t.Next.Active, t.Next.Selected); er != nil {
		return er
	}
	return e.commit(&t, true)
}
func validateTransaction(t Transaction) error {
	if t.Schema != 1 || len(t.Next.Active) == 0 || t.Next.Selected == "" || (t.Next.SelectionMode != "" && t.Next.SelectionMode != "manual") || t.Next.DiskHash != digest(configBytes(t.Next.Active, t.Next.Selected)) {
		return errors.New("invalid transaction journal")
	}
	if _, ok := findNode(t.Next.Active, t.Next.Selected); !ok {
		return errors.New("invalid transaction target")
	}
	for _, n := range t.Next.Active {
		if !strings.HasPrefix(n.Tag, TagPrefix) || n.Outbound["tag"] != n.Tag {
			return errors.New("invalid transaction node")
		}
	}
	return nil
}

// Abort restores old selection and disk contents but intentionally leaves staged
// handlers in memory: some connections may already hold them. No rmo is issued.
func (e *Engine) Abort() error {
	var t Transaction
	if er := mustJSON(e.journalPath(), &t); er != nil {
		return er
	}
	if er := validateTransaction(t); er != nil {
		return er
	}
	b, er := readLimited(outputFile(e.C), 8*1024*1024)
	if er != nil {
		return er
	}
	if h := digest(b); h != digest(t.PreviousFile) && h != t.Next.DiskHash {
		return errors.New("external file edit detected: refusing abort")
	}
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	if !tags[t.PreviousTarget] {
		if t.Previous == nil {
			return errors.New("original live target no longer exists; use offline migration rollback")
		}
		n, ok := findNode(t.Previous.Active, t.PreviousTarget)
		if !ok {
			return errors.New("previous target missing from state")
		}
		if er = e.R.Add(n); er != nil {
			return er
		}
	}
	if er = e.setVerified(t.PreviousTarget); er != nil {
		return er
	}
	if er = atomicWrite(outputFile(e.C), t.PreviousFile, 0600); er != nil {
		return er
	}
	if t.Previous != nil {
		er = atomicWrite(e.statePath(), encode(t.Previous), 0600)
	} else {
		er = removeSync(e.statePath())
	}
	if er != nil {
		return er
	}
	if er = removeSync(e.journalPath()); er != nil {
		return er
	}
	e.event("aborted", map[string]any{"staged_handlers_left_in_memory": true})
	return nil
}
func (e *Engine) Reconcile() error {
	if err := e.ensureSubscriptionMode(); err != nil {
		return err
	}
	if e.pending() {
		return errors.New("pending transaction requires recover or abort")
	}
	s, er := e.state()
	if er != nil {
		return er
	}
	if s == nil {
		return nil
	}
	if _, er = e.checkDisk(s); er != nil {
		return er
	}
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	return e.reconcile(s, tags)
}
func (e *Engine) reconcile(s *State, tags map[string]bool) error {
	for _, n := range s.Active {
		if !tags[n.Tag] {
			if er := e.R.Add(n); er != nil {
				return fmt.Errorf("runtime reconciliation failed: %w", er)
			}
			tags[n.Tag] = true
		}
	}
	b, er := e.R.Balance()
	if er != nil {
		return er
	}
	if b.Override != s.Selected {
		if er = e.setVerified(s.Selected); er != nil {
			return er
		}
		e.event("pin_restored", map[string]any{"selected": s.Selected})
	}
	return nil
}
func (e *Engine) GC() error {
	if err := e.ensureSubscriptionMode(); err != nil {
		return err
	}
	if e.held() {
		return errors.New("hold enabled: no retired handlers will be removed")
	}
	if e.pending() {
		return errors.New("pending transaction: gc refused")
	}
	s, er := e.state()
	if er != nil {
		return er
	}
	if s == nil {
		return errors.New("not adopted")
	}
	if _, er = e.checkDisk(s); er != nil {
		return er
	}
	return e.gc(s)
}
func (e *Engine) gc(s *State) error {
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	if er = e.reconcile(s, tags); er != nil {
		return er
	}
	keep := []Retired{}
	removed := 0
	for i, r := range s.Retired {
		if !strings.HasPrefix(r.Node.Tag, TagPrefix) || r.Node.Tag == s.Selected {
			return errors.New("gc ownership check failed")
		}
		if _, active := findNode(s.Active, r.Node.Tag); active {
			return errors.New("gc would remove an active node")
		}
		if e.Now().Before(r.After) {
			keep = append(keep, r)
			continue
		}
		if tags[r.Node.Tag] {
			if er = e.R.Remove(r.Node.Tag); er != nil {
				keep = append(keep, s.Retired[i:]...)
				s.Retired = keep
				_ = atomicWrite(e.statePath(), encode(s), 0600)
				return errors.New("partial gc: API removal failed; unremoved nodes remain tracked")
			}
		}
		removed++
	}
	if removed > 0 {
		s.Retired = keep
		if er = atomicWrite(e.statePath(), encode(s), 0600); er != nil {
			return er
		}
		e.event("gc", map[string]any{"removed": removed, "retired_nodes": len(keep)})
	}
	return nil
}
func (e *Engine) Status() (map[string]any, error) {
	mode, modeErr := e.staticMode()
	if modeErr != nil {
		return nil, modeErr
	}
	s, er := e.state()
	if er != nil {
		return nil, er
	}
	m := map[string]any{"version": Version, "adopted": s != nil, "hold": e.held(), "pending_transaction": e.pending(), "automatic_gc": e.C.AutoGC, "selection_policy": e.C.SelectionPolicy, "selection_mode": "auto", "key_switch_min_improvement_ms": e.C.KeySwitchMinImprovementMS, "key_switch_min_improvement_percent": e.C.KeySwitchMinImprovementPercent, "key_switch_cooldown_seconds": e.C.KeySwitchCooldownSeconds, "update_interval_seconds": e.C.IntervalSeconds, "hotwatcher_restarts_xray": false, "hard_sync_restarts_xray": true, "static_fallback_mode": mode != nil}
	if mode != nil {
		m["static_fallback_alias"] = staticAlias
	}
	if s != nil {
		if s.SelectionMode == "manual" {
			m["selection_mode"] = "manual"
		}
		m["selected"] = s.Selected
		m["active_nodes"] = len(s.Active)
		m["retired_nodes"] = len(s.Retired)
		m["last_applied_utc"] = s.UpdatedAt
		_, de := e.checkDisk(s)
		m["disk_matches_state"] = de == nil
	}
	tags, re := e.R.List()
	m["api_reachable"] = re == nil
	if re != nil {
		m["api_error"] = re.Error()
	}
	if re == nil {
		m["runtime_outbounds"] = len(tags)
		if s != nil {
			m["selected_present"] = tags[s.Selected]
		}
	}
	b, be := e.R.Balance()
	m["balancer_api_reachable"] = be == nil
	if be != nil {
		m["balancer_api_error"] = be.Error()
	}
	m["api_checked_at"] = e.Now().UTC()
	if be == nil {
		m["runtime_override"] = b.Override
		m["balancer_pin_matches"] = s != nil && s.Selected == b.Override
	}
	return m, nil
}
func (e *Engine) Hold(on bool) error {
	p := filepath.Join(e.C.StateDir, "hold")
	if on {
		if er := atomicWrite(p, []byte("Subscription updates and GC paused. Existing pin reconciliation remains enabled.\n"), 0600); er != nil {
			return er
		}
		e.event("hold_on", nil)
		return nil
	}
	if er := removeSync(p); er != nil {
		return er
	}
	e.event("hold_off", nil)
	return nil
}
func choose(nodes []Node, previous, identity, preferred string) string {
	if _, ok := findNode(nodes, previous); ok {
		return previous
	}
	if identity != "" {
		for _, n := range nodes {
			if n.Identity == identity {
				return n.Tag
			}
		}
	}
	if preferred != "" {
		for _, n := range nodes {
			if strings.Contains(strings.ToLower(n.Name), strings.ToLower(preferred)) {
				return n.Tag
			}
		}
	}
	return nodes[0].Tag
}
func legacyIdentity(b []byte, tag string) string {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	for _, o := range doc.Outbounds {
		if o["tag"] != tag || o["protocol"] != "vless" {
			continue
		}
		settings, _ := o["settings"].(map[string]any)
		server := settings
		if list, ok := settings["vnext"].([]any); ok && len(list) > 0 {
			server, _ = list[0].(map[string]any)
		}
		ss, _ := o["streamSettings"].(map[string]any)
		network, _ := ss["network"].(string)
		if network == "tcp" || network == "" {
			network = "raw"
		}
		security, _ := ss["security"].(string)
		sec, _ := ss[security+"Settings"].(map[string]any)
		sni, _ := sec["serverName"].(string)
		address, _ := server["address"].(string)
		path := ""
		service := ""
		if tr, ok := ss[network+"Settings"].(map[string]any); ok {
			path, _ = tr["path"].(string)
			service, _ = tr["serviceName"].(string)
		}
		return digest(encode([]any{strings.ToLower(address), server["port"], network, security, sni, path, service}))
	}
	return ""
}
func checkSelector(c Config) error {
	files, er := os.ReadDir(c.ConfigDir)
	if er != nil {
		return er
	}
	found := false
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		b, er := readLimited(filepath.Join(c.ConfigDir, f.Name()), 8*1024*1024)
		if er != nil {
			return er
		}
		var v struct {
			Routing struct {
				Balancers []struct {
					Tag      string   `json:"tag"`
					Selector []string `json:"selector"`
				} `json:"balancers"`
			} `json:"routing"`
		}
		if json.Unmarshal(b, &v) != nil {
			// Xray accepts JSONC/JSON5 in unrelated fragments (such as DNS).
			// Only routing fragments need strict parsing to verify the selector.
			if !strings.Contains(strings.ToLower(f.Name()), "routing") && !bytes.Contains(b, []byte(`"balancers"`)) {
				continue
			}
			return fmt.Errorf("routing fragment %s must be strict JSON to verify balancer selector", f.Name())
		}
		for _, bal := range v.Routing.Balancers {
			if bal.Tag != c.BalancerTag {
				continue
			}
			for _, s := range bal.Selector {
				if s != "" && strings.HasPrefix(TagPrefix, s) {
					found = true
				}
			}
		}
	}
	if !found {
		return errors.New("configured balancer is missing or its selector does not match main--VL--hw-; preserve selector main--VL")
	}
	return nil
}
func (e *Engine) Nodes() ([]map[string]any, error) {
	s, er := e.state()
	if er != nil {
		return nil, er
	}
	list := []map[string]any{}
	if s == nil {
		return list, nil
	}
	for _, n := range s.Active {
		list = append(list, map[string]any{"tag": n.Tag, "name": safeLabel(n.Name), "selected": n.Tag == s.Selected})
	}
	sort.Slice(list, func(i, j int) bool { return list[i]["tag"].(string) < list[j]["tag"].(string) })
	return list, nil
}

type KeyMeasurement struct {
	Name   string
	Tag    string
	Active bool
	PingMS *float64
}

type KeysReport struct {
	Keys             []KeyMeasurement
	LastCheckAgo     *time.Duration
	LastCheckSuccess *bool
	SelectedAgo      *time.Duration
	APIWarning       string
}

// Keys measures each owned outbound through a separate loopback-only Xray
// process. It reads the production pin but never changes it or the schedule.
// The CLI runs it without the subscription lock so a long daemon probe does
// not block inspection; a concurrent pin change may require a retry.
func (e *Engine) Keys() (KeysReport, error) {
	report := KeysReport{}
	if err := e.ensureSubscriptionMode(); err != nil {
		return report, err
	}
	s, err := e.state()
	if err != nil {
		return report, err
	}
	if s == nil {
		return report, errors.New("not adopted; run adopt before keys")
	}
	bal, err := e.R.Balance()
	if err != nil {
		report.APIWarning = "API балансировщика недоступен; активный ключ показан по сохранённому состоянию"
	} else if bal.Override != s.Selected {
		report.APIWarning = "выбор в Xray отличается от сохранённого; активный ключ показан по сохранённому состоянию"
	}
	node, ok := findNode(s.Active, s.Selected)
	if !ok {
		return report, errors.New("selected key is missing from active pool")
	}
	ordered := []Node{node}
	for _, n := range s.Active {
		if n.Tag != node.Tag {
			ordered = append(ordered, n)
		}
	}
	sort.Slice(ordered[1:], func(i, j int) bool {
		a, b := ordered[i+1], ordered[j+1]
		if a.Name == b.Name {
			return a.Tag < b.Tag
		}
		return a.Name < b.Name
	})
	for _, n := range ordered {
		m := KeyMeasurement{Name: safeLabel(n.Name), Tag: n.Tag, Active: n.Tag == s.Selected}
		if latency, probeErr := e.R.ProbeLatency(n); probeErr == nil {
			ms := float64(latency.Microseconds()) / 1000
			m.PingMS = &ms
		}
		report.Keys = append(report.Keys, m)
	}
	now := e.Now()
	if d, ok := elapsed(now, s.SelectedAt); ok {
		report.SelectedAgo = &d
	}
	b, err := readPrivateOptional(filepath.Join(e.C.StateDir, "last-check.json"))
	if err == nil {
		var check struct {
			Time    time.Time `json:"time"`
			Success bool      `json:"success"`
		}
		if json.Unmarshal(b, &check) == nil {
			if d, ok := elapsed(now, check.Time); ok {
				report.LastCheckAgo = &d
				report.LastCheckSuccess = &check.Success
			}
		}
	} else if !os.IsNotExist(err) {
		return report, errors.New("cannot read private last-check marker")
	}
	return report, nil
}

func elapsed(now, then time.Time) (time.Duration, bool) {
	if then.IsZero() || now.Before(then) {
		return 0, false
	}
	return now.Sub(then), true
}

// Select accepts either an owned tag or a unique, exact subscription name.
func (e *Engine) Select(identifier string) error { return e.selectNode(identifier, false) }
func (e *Engine) Pin(identifier string) error    { return e.selectNode(identifier, true) }

func (e *Engine) selectNode(identifier string, pin bool) error {
	if err := e.ensureSubscriptionMode(); err != nil {
		return err
	}
	if e.pending() {
		return errors.New("pending transaction: selection refused")
	}
	s, er := e.state()
	if er != nil {
		return er
	}
	if s == nil {
		return errors.New("not adopted")
	}
	tag := identifier
	node, ok := findNode(s.Active, tag)
	if !ok {
		for _, candidate := range s.Active {
			if candidate.Name != identifier {
				continue
			}
			if ok {
				return errors.New("node name is ambiguous; use the tag from keys")
			}
			node, tag, ok = candidate, candidate.Tag, true
		}
		if !ok {
			return errors.New("requested tag or exact name is not in the active owned pool")
		}
	}
	old, er := e.checkDisk(s)
	if er != nil {
		return er
	}
	tags, er := e.R.List()
	if er != nil {
		return er
	}
	if !tags[tag] {
		return errors.New("requested node is absent from the running Xray")
	}
	bal, er := e.R.Balance()
	if er != nil {
		return er
	}
	if bal.Override != s.Selected {
		return errors.New("live selection differs from saved state; run reconcile before select")
	}
	if !pin {
		if er = e.probe(node); er != nil {
			return er
		}
		if _, er = e.urlTestNode(node); er != nil {
			return er
		}
	}
	if tag == s.Selected && (!pin || s.SelectionMode == "manual") {
		return nil
	}
	next := *s
	next.Selected = tag
	if pin {
		next.SelectionMode = "manual"
	}
	next.UpdatedAt = e.Now()
	if tag != s.Selected {
		next.SelectedAt = next.UpdatedAt
	}
	next.DiskHash = digest(configBytes(next.Active, tag))
	t := Transaction{Schema: 1, Created: e.Now(), Previous: s, PreviousFile: old, PreviousTarget: s.Selected, Next: next}
	if len(encode(t)) > 16*1024*1024 {
		return errors.New("transaction exceeds 16 MiB limit; old configuration kept")
	}
	if er = atomicWrite(e.journalPath(), encode(t), 0600); er != nil {
		return er
	}
	return e.commit(&t, false)
}

// CheckKey verifies the selected key independently of subscription downloads.
// A failed selected key is replaced with the fastest freshly verified peer.
func (e *Engine) CheckKey() (string, error) {
	if err := e.ensureSubscriptionMode(); err != nil {
		return "", err
	}
	if e.held() {
		return "", errors.New("hold is enabled; key checking and switching paused")
	}
	if e.pending() {
		return "", errors.New("pending transaction requires recover or abort before checking keys")
	}
	s, err := e.state()
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", errors.New("not adopted")
	}
	if _, err = e.checkDisk(s); err != nil {
		return "", err
	}
	tags, err := e.R.List()
	if err != nil {
		return "", err
	}
	bal, err := e.R.Balance()
	if err != nil {
		return "", err
	}
	if bal.Override != s.Selected {
		return "", errors.New("live selection differs from saved state; run reconcile before checking keys")
	}
	active, _ := findNode(s.Active, s.Selected)
	if !tags[active.Tag] {
		return "", errors.New("selected key is absent from the running Xray; run reconcile")
	}
	if s.SelectionMode == "manual" {
		if _, probeErr := e.R.ProbeLatency(active); probeErr != nil {
			return s.Selected, errors.New("закреплённый ключ не отвечает; автоматическая смена выключена")
		}
		if _, urlErr := e.urlTestNode(active); urlErr != nil {
			return s.Selected, errors.New("закреплённый ключ не открыл обязательные сайты; автоматическая смена выключена")
		}
		return s.Selected, nil
	}
	if _, err = e.R.ProbeLatency(active); err == nil {
		if _, urlErr := e.urlTestNode(active); urlErr == nil {
			return s.Selected, nil
		}
	} else {
		// A single timeout should not dislodge a live game route.
		if _, err = e.R.ProbeLatency(active); err == nil {
			if _, urlErr := e.urlTestNode(active); urlErr == nil {
				return s.Selected, nil
			}
		}
	}
	type measuredCandidate struct {
		tag     string
		latency time.Duration
	}
	var peers []measuredCandidate
	for _, candidate := range s.Active {
		if candidate.Tag == s.Selected || !tags[candidate.Tag] {
			continue
		}
		latency, probeErr := e.R.ProbeLatency(candidate)
		if probeErr == nil {
			peers = append(peers, measuredCandidate{candidate.Tag, latency})
		}
	}
	if len(peers) == 0 {
		return "", errors.New("selected key failed HTTPS check; no verified replacement; old selection kept")
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].latency == peers[j].latency {
			return peers[i].tag < peers[j].tag
		}
		return peers[i].latency < peers[j].latency
	})
	for _, peer := range peers {
		if err = e.Select(peer.tag); err == nil {
			e.event("key_failover", map[string]any{"from": s.Selected, "to": peer.tag})
			return peer.tag, nil
		}
		if e.pending() {
			return "", err
		}
	}
	return "", fmt.Errorf("verified peers failed final switch; old selection kept: %w", err)
}
func (e *Engine) Doctor() (map[string]any, error) {
	result := map[string]any{"version": Version, "checks": map[string]bool{}, "secrets_printed": false}
	checks := result["checks"].(map[string]bool)
	_, err := e.C.URL()
	checks["private_subscription_url_file"] = err == nil
	info, err := os.Stat(e.C.XrayBinary)
	checks["xray_executable"] = err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
	err = checkSelector(e.C)
	checks["compatible_balancer_selector"] = err == nil
	_, err = e.R.List()
	checks["handler_service_list_outbounds"] = err == nil
	_, err = e.R.Balance()
	checks["routing_service_balancer"] = err == nil
	all := true
	for _, ok := range checks {
		all = all && ok
	}
	result["ready"] = all
	if !all {
		return result, errors.New("one or more doctor checks failed; see docs/TROUBLESHOOTING.md")
	}
	return result, nil
}
func WithLock(c Config, fn func() error) error {
	unlock, err := lock(c.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Lstat(filepath.Join("/opt/var/lib/hotwatcher-updater", "maintenance.json")); err == nil {
		return errors.New("software update maintenance in progress")
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join("/opt/var/lib/hotwatcher-updater", "pending-update.json")); err == nil {
		return errors.New("pending software update requires recovery")
	} else if !os.IsNotExist(err) {
		return err
	}
	return fn()
}
func WithLockWait(c Config, timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := WithLock(c, fn)
		if !errors.Is(err, ErrBusy) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Hot Watcher is still busy after %s: %w", timeout, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
func SafeLog(c Config, event string, fields map[string]any) { _ = logEvent(c.StateDir, event, fields) }
func WriteLastCheck(c Config, ok bool) {
	_ = atomicWrite(filepath.Join(c.StateDir, "last-check.json"), encode(map[string]any{"time": time.Now().UTC(), "success": ok}), 0600)
}
func NextSubscriptionCheck(c Config) time.Time {
	b, err := readPrivateOptional(filepath.Join(c.StateDir, "next-subscription-check.json"))
	if err != nil {
		return time.Time{}
	}
	var v struct {
		Next time.Time `json:"next"`
	}
	if json.Unmarshal(b, &v) != nil {
		return time.Time{}
	}
	return v.Next
}
func WriteNextSubscriptionCheck(c Config, next time.Time) {
	_ = atomicWrite(filepath.Join(c.StateDir, "next-subscription-check.json"), encode(map[string]any{"next": next}), 0600)
}
func readPrivateOptional(path string) ([]byte, error) { return readPrivate(path, 4096) }

func safeLabel(s string) string {
	if strings.Contains(s, "://") {
		return "[URL label redacted]"
	}
	return s
}
