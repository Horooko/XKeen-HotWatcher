package hotwatcher

import (
	"errors"
	"strings"
	"time"
)

type EmergencyImportResult struct {
	Tag           string `json:"tag"`
	Name          string `json:"name"`
	URLTestPassed bool   `json:"url_test_passed"`
	Warning       string `json:"warning,omitempty"`
}

// Automatic releases the durable manual pin and evaluates saved keys now.
// An unavailable network leaves the current key selected while auto mode stays on.
func (e *Engine) Automatic() (string, error) {
	if err := e.ensureSubscriptionMode(); err != nil {
		return "", err
	}
	if e.pending() {
		return "", errors.New("сначала завершите или отмените незавершённое применение")
	}
	s, err := e.state()
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", errors.New("ключи ещё не подключены")
	}
	if _, err = e.checkDisk(s); err != nil {
		return "", err
	}
	if s.SelectionMode == "manual" {
		next := *s
		next.SelectionMode = ""
		if err = atomicWrite(e.statePath(), encode(next), 0600); err != nil {
			return "", err
		}
		e.event("automatic_selection_on", map[string]any{"selected": s.Selected})
	}
	best, err := e.fastest(s.Active, s.Selected, time.Time{})
	if err != nil {
		return s.Selected, err
	}
	if best != s.Selected {
		if err = e.Select(best); err != nil {
			return s.Selected, err
		}
	}
	return best, nil
}

// ImportEmergency accepts exactly one administrator-supplied VLESS URI. The
// original URI is never written to disk or events; only the parsed outbound is
// stored in the existing private state and managed Xray fragment. This explicit
// emergency action may apply a key despite a failed URL Test.
func (e *Engine) ImportEmergency(raw string) (EmergencyImportResult, error) {
	var result EmergencyImportResult
	if err := e.ensureSubscriptionMode(); err != nil {
		return result, err
	}
	if e.pending() {
		return result, errors.New("сначала завершите или отмените незавершённое применение")
	}
	raw = strings.TrimSpace(raw)
	if len(raw) > 4096 || strings.ContainsAny(raw, "\r\n") || !strings.HasPrefix(raw, "vless://") {
		return result, errors.New("вставьте один полный vless:// ключ без переносов строк")
	}
	parsed, err := Parse([]byte(raw), e.C)
	if err != nil || len(parsed.Nodes) != 1 {
		return result, errors.New("аварийный VLESS-ключ не прошёл проверку формата")
	}
	node := parsed.Nodes[0]
	node.Emergency = true
	node.Name = safeLabel(node.Name)
	if node.Name == "" {
		node.Name = "Аварийный ключ"
	}
	s, err := e.state()
	if err != nil {
		return result, err
	}
	if s == nil {
		return result, errors.New("сначала выполните hotwatcher adopt")
	}
	oldFile, err := e.checkDisk(s)
	if err != nil {
		return result, err
	}
	tags, err := e.R.List()
	if err != nil {
		return result, err
	}
	bal, err := e.R.Balance()
	if err != nil {
		return result, err
	}
	if bal.Override != s.Selected || !tags[s.Selected] {
		return result, errors.New("активный ключ расходится с сохранённым состоянием; выполните reconcile")
	}
	next := *s
	next.Active = make([]Node, 0, len(s.Active)+1)
	next.Retired = append([]Retired(nil), s.Retired...)
	for _, old := range s.Active {
		if old.Emergency && old.Tag != node.Tag {
			next.Retired = append(next.Retired, Retired{Node: old, After: e.Now().Add(time.Duration(e.C.GraceSeconds) * time.Second)})
			continue
		}
		if old.Tag == node.Tag {
			continue
		}
		next.Active = append(next.Active, old)
	}
	next.Active = append(next.Active, node)
	if len(next.Active) > e.C.MaxNodes || len(next.Retired) > e.C.MaxRetired {
		return result, errors.New("достигнут предел числа ключей; старый выбор сохранён")
	}
	next.Selected = node.Tag
	next.SelectionMode = "manual"
	next.UpdatedAt = e.Now()
	if s.Selected != node.Tag {
		next.SelectedAt = next.UpdatedAt
	}
	next.DiskHash = digest(configBytes(next.Active, node.Tag))
	if err = e.R.Validate(next.Active, node.Tag); err != nil {
		return result, errors.New("Xray отклонил конфигурацию аварийного ключа")
	}
	result.Tag, result.Name = node.Tag, node.Name
	if _, testErr := e.urlTestNode(node); testErr == nil {
		result.URLTestPassed = true
	} else {
		result.Warning = "URL Test не прошёл; ключ применён по аварийному запросу"
	}
	t := Transaction{Schema: 1, Created: e.Now(), Previous: s, PreviousFile: oldFile, PreviousTarget: s.Selected, Next: next}
	if len(encode(t)) > 16*1024*1024 {
		return EmergencyImportResult{}, errors.New("аварийное применение превышает размер журнала")
	}
	if err = atomicWrite(e.journalPath(), encode(t), 0600); err != nil {
		return EmergencyImportResult{}, err
	}
	if err = e.commit(&t, false); err != nil {
		return EmergencyImportResult{}, err
	}
	e.event("emergency_key_applied", map[string]any{"tag": node.Tag, "url_test_passed": result.URLTestPassed})
	return result, nil
}

func (e *Engine) EmergencyTag() (string, error) {
	s, err := e.state()
	if err != nil || s == nil {
		return "", err
	}
	for _, node := range s.Active {
		if node.Emergency {
			return node.Tag, nil
		}
	}
	return "", nil
}

// RemoveEmergency forgets the emergency designation. The currently selected
// key stays live; a later sync may retire it if it is absent from subscription.
func (e *Engine) RemoveEmergency() error {
	if err := e.ensureSubscriptionMode(); err != nil {
		return err
	}
	if e.pending() {
		return errors.New("сначала завершите или отмените незавершённое применение")
	}
	s, err := e.state()
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("ключи ещё не подключены")
	}
	if _, err = e.checkDisk(s); err != nil {
		return err
	}
	next := *s
	next.Active = append([]Node(nil), s.Active...)
	changed := false
	for i := range next.Active {
		if next.Active[i].Emergency {
			next.Active[i].Emergency = false
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err = atomicWrite(e.statePath(), encode(next), 0600); err == nil {
		e.event("emergency_key_forgotten", nil)
	}
	return err
}
