package hotwatcher

import (
	"context"
	"errors"
	"time"
)

// SelectedIsolatedHTTPSProbe checks only the saved selected outbound with a
// short-lived loopback Xray. It neither changes the running Xray nor installs
// routing rules, and deliberately ignores economy/live-probe mode.
func (e *Engine) SelectedIsolatedHTTPSProbe() (time.Duration, error) {
	return e.SelectedIsolatedHTTPSProbeContext(context.Background())
}

// SelectedIsolatedHTTPSProbeContext lets an HTTP report cancel the temporary
// Xray immediately when its collection budget or client connection ends.
func (e *Engine) SelectedIsolatedHTTPSProbeContext(ctx context.Context) (time.Duration, error) {
	s, err := e.state()
	if err != nil {
		return 0, err
	}
	if s == nil {
		return 0, errors.New("ключи не приняты Hot Watcher")
	}
	node, ok := findNode(s.Active, s.Selected)
	if !ok {
		return 0, errors.New("выбранный ключ отсутствует в сохранённом списке")
	}
	c := e.C
	if c.ProbeTimeoutSeconds < 1 || c.ProbeTimeoutSeconds > 4 {
		c.ProbeTimeoutSeconds = 4
	}
	if len(c.ProbeURLs) > 2 {
		c.ProbeURLs = c.ProbeURLs[:2]
	}
	return (Xray{C: c}).probeLatencyIsolatedContext(ctx, node)
}
