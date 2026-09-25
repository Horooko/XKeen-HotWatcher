package hotwatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The alias matches the existing main--VL selector, while its outbound is
// copied from the administrator-owned 04_outbounds.json. The original file is
// never modified.
const staticAlias = "main--VL--hw-static-fallback"

type StaticMode struct {
	Schema           int    `json:"schema"`
	OriginalHash     string `json:"original_hash"`
	StaticHash       string `json:"static_hash"`
	SourceHash       string `json:"source_hash"`
	Restoring        *State `json:"restoring,omitempty"`
	AddedUpdatePause bool   `json:"added_update_pause,omitempty"`
}

var updaterPausePath = "/opt/var/lib/hotwatcher-updater/pause"

func (e *Engine) staticPath() string { return filepath.Join(e.C.StateDir, "static-mode.json") }

func (e *Engine) staticMode() (*StaticMode, error) {
	var m StaticMode
	if err := mustJSON(e.staticPath(), &m); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if m.Schema != 1 || len(m.OriginalHash) != 64 || len(m.StaticHash) != 64 || len(m.SourceHash) != 64 {
		return nil, errors.New("invalid static mode marker")
	}
	return &m, nil
}

func (e *Engine) staticNode() (Node, string, error) {
	path := filepath.Join(e.C.ConfigDir, "04_outbounds.json")
	b, err := readLimited(path, 8*1024*1024)
	if err != nil {
		return Node{}, "", errors.New("cannot read static 04_outbounds.json")
	}
	root, err := decodeObject(b)
	if err != nil {
		return Node{}, "", errors.New("static 04_outbounds.json must be strict JSON")
	}
	outs, ok := root["outbounds"].([]any)
	if !ok {
		return Node{}, "", errors.New("static 04_outbounds.json has no outbounds")
	}
	for _, entry := range outs {
		out, ok := entry.(map[string]any)
		if !ok || out["tag"] != e.C.StaticFallbackTag {
			continue
		}
		if out["protocol"] != "vless" {
			return Node{}, "", errors.New("static fallback must be a VLESS outbound")
		}
		cloned, _ := decodeObject(encode(out))
		cloned["tag"] = staticAlias
		return Node{Tag: staticAlias, Name: "static fallback", Outbound: cloned}, digest(b), nil
	}
	return Node{}, "", fmt.Errorf("static fallback outbound %s not found in 04_outbounds.json", e.C.StaticFallbackTag)
}

// StopToStatic is called only after the subscription daemon has been stopped.
// A durable marker is written before API or disk mutations, so StartFromStatic
// can finish an interrupted transition.
func (e *Engine) StopToStatic() error {
	if e.pending() {
		return errors.New("pending subscription transaction requires recover or abort")
	}
	if marker, err := e.staticMode(); err != nil {
		return err
	} else if marker != nil {
		b, readErr := readLimited(outputFile(e.C), 8*1024*1024)
		if readErr == nil && digest(b) == marker.StaticHash && marker.Restoring == nil {
			source, sourceErr := readLimited(filepath.Join(e.C.ConfigDir, "04_outbounds.json"), 8*1024*1024)
			if sourceErr != nil || digest(source) != marker.SourceHash {
				return errors.New("static 04_outbounds.json changed since stop; run start before selecting it again")
			}
			return nil // Already safely stopped; keep the boot-stable static route.
		}
		return errors.New("static transition already exists; run start to restore first")
	}
	s, err := e.state()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("not adopted; static mode requires an owned subscription file")
	}
	old, err := e.checkDisk(s)
	if err != nil {
		return err
	}
	node, sourceHash, err := e.staticNode()
	if err != nil {
		return err
	}
	staticFile := configBytes([]Node{node}, staticAlias)
	if err = e.R.Validate([]Node{node}, staticAlias); err != nil {
		return err
	}
	if err = e.R.Probe(node); err != nil {
		return errors.New("static VLESS fallback failed HTTPS probe; subscription kept")
	}
	if _, err = e.urlTestNode(node); err != nil {
		return errors.New("static VLESS fallback failed URL Test; subscription kept")
	}
	tags, err := e.R.List()
	if err != nil {
		return err
	}
	if tags[staticAlias] {
		return errors.New("static fallback alias already exists in Xray without a marker")
	}
	bal, err := e.R.Balance()
	if err != nil {
		return err
	}
	if bal.Override != s.Selected {
		return errors.New("live selection differs from saved state; run reconcile before stop")
	}
	_, pauseErr := os.Lstat(updaterPausePath)
	if pauseErr != nil && !os.IsNotExist(pauseErr) {
		return pauseErr
	}
	if pauseErr == nil {
		if err = regular(updaterPausePath); err != nil {
			return errors.New("unsafe updater pause marker")
		}
	}
	marker := StaticMode{Schema: 1, OriginalHash: digest(old), StaticHash: digest(staticFile), SourceHash: sourceHash, AddedUpdatePause: os.IsNotExist(pauseErr)}
	if err = atomicWrite(e.staticPath(), encode(marker), 0600); err != nil {
		return err
	}
	if marker.AddedUpdatePause {
		if err = atomicWrite(updaterPausePath, []byte("static fallback active\n"), 0600); err != nil {
			return errors.New("static transition saved but updater pause failed; run start to restore")
		}
	}
	if err = e.R.Add(node); err != nil {
		return errors.New("static transition saved but API add failed; run start to restore")
	}
	if err = e.setVerified(staticAlias); err != nil {
		return errors.New("static transition saved but API switch failed; run start to restore")
	}
	if err = atomicWrite(outputFile(e.C), staticFile, 0600); err != nil {
		return errors.New("static route live, disk update failed; run start to restore before Xray restart")
	}
	e.event("static_mode_on", map[string]any{"source": "04_outbounds.json", "restart": false})
	return nil
}

// StartFromStatic verifies every candidate before leaving the static route.
// It also finishes an interrupted stop/start when the marker remains present.
func (e *Engine) StartFromStatic() error {
	if e.pending() {
		return errors.New("pending subscription transaction requires recover or abort")
	}
	marker, err := e.staticMode()
	if err != nil {
		return err
	}
	s, err := e.state()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("not adopted")
	}
	if marker == nil {
		if _, err = e.checkDisk(s); err != nil {
			return err
		}
		return e.Reconcile()
	}
	file, err := readLimited(outputFile(e.C), 8*1024*1024)
	if err != nil {
		return err
	}
	hash := digest(file)
	allowed := hash == marker.OriginalHash || hash == marker.StaticHash || marker.Restoring != nil && hash == marker.Restoring.DiskHash
	if !allowed {
		return errors.New("managed outbound file changed outside static transition; refusing to overwrite")
	}
	tags, err := e.R.List()
	if err != nil {
		return err
	}
	for _, node := range s.Active {
		if !tags[node.Tag] {
			if err = e.R.Add(node); err != nil {
				return errors.New("could not restore subscription outbound in Xray; static mode retained")
			}
			tags[node.Tag] = true
		}
	}
	selected, err := e.fastest(s.Active, s.Selected, s.SelectedAt)
	if err != nil {
		return errors.New("no working subscription key; static route retained")
	}
	next := *s
	next.Selected = selected
	next.UpdatedAt = e.Now()
	if selected != s.Selected {
		next.SelectedAt = next.UpdatedAt
	}
	next.DiskHash = digest(configBytes(next.Active, selected))
	if err = e.R.Validate(next.Active, selected); err != nil {
		return errors.New("restored subscription configuration failed Xray validation; static route retained")
	}
	marker.Restoring = &next
	if len(encode(marker)) > 16*1024*1024 {
		return errors.New("static restore marker exceeds 16 MiB; static route retained")
	}
	if err = atomicWrite(e.staticPath(), encode(marker), 0600); err != nil {
		return err
	}
	if err = e.setVerified(selected); err != nil {
		return errors.New("subscription selection could not be verified; static marker retained")
	}
	if err = atomicWrite(outputFile(e.C), configBytes(next.Active, selected), 0600); err != nil {
		return errors.New("subscription live but disk restore failed; static marker retained")
	}
	if err = atomicWrite(e.statePath(), encode(next), 0600); err != nil {
		return errors.New("subscription disk restored but state write failed; static marker retained")
	}
	if tags[staticAlias] {
		if err = e.R.Remove(staticAlias); err != nil {
			return errors.New("subscription restored but static alias cleanup failed; retry start")
		}
	}
	if marker.AddedUpdatePause {
		if _, pauseErr := os.Lstat(updaterPausePath); pauseErr == nil {
			b, readErr := readPrivate(updaterPausePath, 1024)
			if readErr != nil || string(b) != "static fallback active\n" {
				return errors.New("updater pause was changed outside static mode; leave it and retry start after inspection")
			}
		} else if !os.IsNotExist(pauseErr) {
			return pauseErr
		}
		if err = removeSync(updaterPausePath); err != nil {
			return errors.New("subscription restored but updater pause cleanup failed")
		}
	}
	if err = removeSync(e.staticPath()); err != nil {
		return err
	}
	e.event("static_mode_off", map[string]any{"selected": selected, "restart": false})
	return nil
}

func (e *Engine) ensureSubscriptionMode() error {
	marker, err := e.staticMode()
	if err != nil {
		return err
	}
	if marker != nil {
		return errors.New("static fallback mode active; run hotwatcher start first")
	}
	return nil
}
