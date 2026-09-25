package updater

import (
	"errors"
	"os"
	"time"
)

// Overview contains only the fields needed by the authenticated local Web UI.
// It deliberately omits release URLs, file hashes and updater internals.
type Overview struct {
	Installed    string        `json:"installed"`
	Available    string        `json:"available,omitempty"`
	Verified     bool          `json:"verified"`
	LastCheck    time.Time     `json:"last_check,omitempty"`
	CheckFailed  bool          `json:"check_failed"`
	Enabled      bool          `json:"enabled"`
	Mode         string        `json:"mode"`
	Policy       string        `json:"policy"`
	PendingPhase string        `json:"pending_phase,omitempty"`
	LastResult   *UpdateResult `json:"last_result,omitempty"`
	StateInvalid bool          `json:"state_invalid"`
}

func GetOverview() (Overview, error) {
	c, err := loadConfig()
	if os.IsNotExist(err) {
		c = Defaults()
	} else if err != nil {
		return Overview{}, err
	}
	s := readState()
	result := Overview{Installed: installedVersion(s), Available: s.Available, Verified: s.Verified, LastCheck: s.LastCheck, CheckFailed: s.Deferred != "", Enabled: c.Enabled, Mode: c.Mode, Policy: c.Policy, LastResult: readResult(), StateInvalid: s.Invalid}
	if journal, journalErr := readJournal(); journalErr == nil {
		result.PendingPhase = journal.Phase
	} else if !os.IsNotExist(journalErr) {
		return Overview{}, errors.New("журнал установки обновления недоступен")
	}
	return result, nil
}

// SetPolicy keeps the existing notification/auto mode while choosing whether
// signed minor releases, such as 0.3.0 from 0.2.x, are eligible.
func SetPolicy(policy string) error {
	if policy != "patch" && policy != "minor" {
		return errors.New("политика обновлений должна быть patch или minor")
	}
	if err := ensureDir(Root); err != nil {
		return err
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	c, err := loadConfig()
	if os.IsNotExist(err) {
		c = Defaults()
	} else if err != nil {
		return err
	}
	c.Policy = policy
	return saveConfig(c)
}
