package hotwatcher

import (
	"errors"
	"os"
	"path/filepath"
)

type probeModeSettings struct {
	Schema        int  `json:"schema"`
	EconomyChecks bool `json:"economy_checks"`
}

func (c Config) probeModePath() string { return filepath.Join(c.StateDir, "probe-mode.json") }

// Economy checks use the running Xray. Existing installations default to on.
func (c Config) EconomyChecks() (bool, error) {
	var settings probeModeSettings
	if err := mustJSON(c.probeModePath(), &settings); os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, errors.New("не удалось прочитать режим проверки")
	}
	if settings.Schema != 1 {
		return false, errors.New("неподдерживаемый формат режима проверки")
	}
	return settings.EconomyChecks, nil
}

func (e *Engine) SetEconomyChecks(enabled bool) error {
	if err := privateDir(e.C.StateDir); err != nil {
		return err
	}
	return atomicWrite(e.C.probeModePath(), encode(probeModeSettings{Schema: 1, EconomyChecks: enabled}), 0600)
}
