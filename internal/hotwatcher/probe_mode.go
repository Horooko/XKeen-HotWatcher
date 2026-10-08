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

// Live checks use the running Xray and change its routing temporarily. Fresh
// and existing installations use isolated checks unless explicitly opted in.
func (c Config) EconomyChecks() (bool, error) {
	if c.ForceIsolatedChecks || !c.AllowLiveProbes {
		return false, nil
	}
	var settings probeModeSettings
	if err := mustJSON(c.probeModePath(), &settings); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, errors.New("не удалось прочитать режим проверки")
	}
	if settings.Schema != 1 {
		return false, errors.New("неподдерживаемый формат режима проверки")
	}
	return settings.EconomyChecks, nil
}

func (e *Engine) SetEconomyChecks(enabled bool) error {
	if enabled && !e.C.AllowLiveProbes {
		return errors.New("проверки через основной Xray отключены; для явного разрешения задайте allow_live_probes в локальной конфигурации")
	}
	if err := privateDir(e.C.StateDir); err != nil {
		return err
	}
	return atomicWrite(e.C.probeModePath(), encode(probeModeSettings{Schema: 1, EconomyChecks: enabled}), 0600)
}

// Diagnostic calls must never add temporary rules to the production Xray,
// even when the operator explicitly allows live probes for key operations.
func (e *Engine) isolatedChecks() *Engine {
	copy := *e
	copy.C.ForceIsolatedChecks = true
	switch runtime := e.R.(type) {
	case Xray:
		runtime.C = copy.C
		copy.R = runtime
	case *Xray:
		isolated := *runtime
		isolated.C = copy.C
		copy.R = &isolated
	}
	return &copy
}
