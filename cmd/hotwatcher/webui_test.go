package main

import (
	"bytes"
	"encoding/json"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebUIRequiresSessionAndCSRFToEditSites(t *testing.T) {
	c := hw.Defaults()
	root := t.TempDir()
	c.StateDir = filepath.Join(root, "state")
	c.AllowLiveProbes = true
	c.ConfigDir = filepath.Join(root, "configs")
	c.SubscriptionURLFile = filepath.Join(root, "subscription.url")
	if err := os.MkdirAll(c.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.APIURLPath(), []byte(`{"api":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := newWebUI(c, hw.New(c))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(c.StateDir, "webui-token")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("web token permissions: %v, %v", info, err)
	}
	handler := w.handler()
	call := func(method, path string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://"+c.WebUIListen+path, bytes.NewReader(body))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-HW-CSRF", csrf)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["example.com"]}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated edit accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/probe-mode", []byte(`{"economy_checks":false}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated probe mode edit accepted: %d", got.Code)
	}
	if got := call("POST", "/api/emergency", []byte(`{"uri":"vless://secret"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated emergency action accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/update/policy", []byte(`{"policy":"minor"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated updater edit accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/update/pin", []byte(`{"version":"0.3.4"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated updater pin accepted: %d", got.Code)
	}
	if got := call("GET", "/api/dns", nil, nil, ""); got.Code != 401 {
		t.Fatalf("unauthenticated DNS status accepted: %d", got.Code)
	}
	if got := call("GET", "/api/activity", nil, nil, ""); got.Code != 401 {
		t.Fatalf("unauthenticated activity status accepted: %d", got.Code)
	}
	if got := call("POST", "/api/activity/stop", nil, nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated background stop accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/subscription-url", []byte(`{"url":"https://example.com/sub"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated subscription edit accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/token", []byte(`{"current":"old","new":"new"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated token edit accepted: %d", got.Code)
	}
	if got := call("POST", "/api/login", []byte(`{"token":"wrong"}`), nil, ""); got.Code != 401 {
		t.Fatalf("bad token accepted: %d", got.Code)
	}
	login := call("POST", "/api/login", []byte(`{"token":"`+w.token+`"}`), nil, "")
	if login.Code != 200 || len(login.Result().Cookies()) != 1 {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil || session.CSRF == "" {
		t.Fatalf("missing CSRF token: %v", err)
	}
	cookie := login.Result().Cookies()[0]
	w.mu.Lock()
	w.job = webJob{ID: 7, Action: "startup-check", State: "running", Message: "private-progress-description", StartedAt: time.Now().Add(-65 * time.Second), Result: "private-result"}
	w.mu.Unlock()
	readActivity := func() (struct {
		Lock struct {
			Busy bool `json:"busy"`
		} `json:"lock"`
		Message string `json:"message"`
		WebJob  *struct {
			Action         string `json:"action"`
			ElapsedSeconds int64  `json:"elapsed_seconds"`
		} `json:"web_job"`
	}, string) {
		got := call("GET", "/api/activity", nil, cookie, "")
		if got.Code != 200 {
			t.Fatalf("activity request failed: %d %s", got.Code, got.Body.String())
		}
		var activity struct {
			Lock struct {
				Busy bool `json:"busy"`
			} `json:"lock"`
			Message string `json:"message"`
			WebJob  *struct {
				Action         string `json:"action"`
				ElapsedSeconds int64  `json:"elapsed_seconds"`
			} `json:"web_job"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &activity); err != nil {
			t.Fatal(err)
		}
		return activity, got.Body.String()
	}
	activity, body := readActivity()
	if activity.Lock.Busy || activity.WebJob == nil || activity.WebJob.Action != "startup-check" || activity.WebJob.ElapsedSeconds < 60 || strings.Contains(activity.Message, "нет") {
		t.Fatalf("unlocked web job reported idle: %s", body)
	}
	if strings.Contains(body, "private-progress-description") || strings.Contains(body, "private-result") {
		t.Fatalf("activity response leaked job details: %s", body)
	}
	if err := hw.WithLockNamed(c, "background sync", func() error {
		activity, body := readActivity()
		if !activity.Lock.Busy || activity.WebJob == nil {
			t.Fatalf("lock holder or waiting web job hidden: %s", body)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.job.State = "succeeded"
	w.mu.Unlock()
	activity, _ = readActivity()
	if activity.WebJob != nil {
		t.Fatal("completed web job still reported active")
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["example.com"]}`), cookie, ""); got.Code != 403 {
		t.Fatalf("edit without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/probe-mode", []byte(`{"economy_checks":false}`), cookie, ""); got.Code != 403 {
		t.Fatalf("probe mode edit without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/activity/stop", nil, cookie, ""); got.Code != 403 {
		t.Fatalf("background stop without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/activity/stop", nil, cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("background stop failed: %d %s", got.Code, got.Body.String())
	}
	if paused, err := hw.BackgroundPaused(c); err != nil || !paused {
		t.Fatalf("background pause not saved: %v %v", paused, err)
	}
	if got := call("POST", "/api/activity/resume", nil, cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("background resume failed: %d %s", got.Code, got.Body.String())
	}
	if got := call("PUT", "/api/probe-mode", []byte(`{"economy_checks":false}`), cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("probe mode setting failed: %d %s", got.Code, got.Body.String())
	}
	if enabled, err := c.EconomyChecks(); err != nil || enabled {
		t.Fatalf("probe mode setting not persisted: %v, %v", enabled, err)
	}
	if got := call("PUT", "/api/probe-mode", []byte(`{"economy_checks":true}`), cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("probe mode setting failed: %d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/emergency", []byte(`{"uri":"vless://secret"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("emergency without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/action", []byte(`{"action":"update-install"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("update install without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/action", []byte(`{"action":"dns-on"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("DNS change without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/update/pin", []byte(`{"version":"0.3.4"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("update pin without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/subscription-url", []byte(`{"url":"https://example.com/sub"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("subscription edit without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/token", []byte(`{"current":"old","new":"new"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("token edit without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["http://example.com"]}`), cookie, session.CSRF); got.Code != 400 {
		t.Fatalf("unsafe site accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["example.com","github.com"]}`), cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("valid site update failed: %d %s", got.Code, got.Body.String())
	}
	if got := call("GET", "/api/dns", nil, cookie, ""); got.Code != 200 || !strings.Contains(got.Body.String(), `"managed":false`) {
		t.Fatalf("DNS status failed: %d %s", got.Code, got.Body.String())
	}
	if got := call("PUT", "/api/subscription-url", []byte(`{"url":"http://example.com/sub"}`), cookie, session.CSRF); got.Code != 400 {
		t.Fatalf("insecure subscription URL accepted: %d", got.Code)
	}
	privateURL := "https://example.com/private-subscription-token"
	if got := call("PUT", "/api/subscription-url", []byte(`{"url":"`+privateURL+`"}`), cookie, session.CSRF); got.Code != 200 || strings.Contains(got.Body.String(), privateURL) {
		t.Fatalf("subscription URL save failed or leaked URL: %d %s", got.Code, got.Body.String())
	}
	if saved, err := c.URL(); err != nil || saved != privateURL {
		t.Fatalf("subscription URL not saved: %q, %v", saved, err)
	}
	sites, err := w.engine.URLTestSites()
	if err != nil || len(sites) != 2 || sites[0] != "https://example.com/" {
		t.Fatalf("Web UI did not apply site list: %v, %v", sites, err)
	}
	lanRequest := httptest.NewRequest("POST", "http://"+c.WebUILANListen+"/api/login", strings.NewReader(`{"token":"`+w.token+`"}`))
	lanRequest.Header.Set("Content-Type", "application/json")
	lanLogin := httptest.NewRecorder()
	handler.ServeHTTP(lanLogin, lanRequest)
	if lanLogin.Code != 200 {
		t.Fatalf("LAN host rejected: %d %s", lanLogin.Code, lanLogin.Body.String())
	}
	var lanSession struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(lanLogin.Body.Bytes(), &lanSession); err != nil || lanSession.CSRF == "" {
		t.Fatalf("LAN login missing CSRF: %v", err)
	}
	lanEdit := httptest.NewRequest("PUT", "http://"+c.WebUILANListen+"/api/sites", strings.NewReader(`{"sites":["http://example.com"]}`))
	lanEdit.Header.Set("Content-Type", "application/json")
	lanEdit.Header.Set("Origin", "http://"+c.WebUILANListen)
	lanEdit.Header.Set("X-HW-CSRF", lanSession.CSRF)
	lanEdit.AddCookie(lanLogin.Result().Cookies()[0])
	lanEditResponse := httptest.NewRecorder()
	handler.ServeHTTP(lanEditResponse, lanEdit)
	if lanEditResponse.Code != 400 {
		t.Fatalf("LAN CSRF validation failed: %d %s", lanEditResponse.Code, lanEditResponse.Body.String())
	}
	oldToken := w.token
	newToken := "new-private-panel-token-2026"
	if err := setWebToken(c, "short"); err == nil {
		t.Fatal("short token accepted")
	}
	if got := call("PUT", "/api/token", []byte(`{"current":"wrong","new":"`+newToken+`"}`), cookie, session.CSRF); got.Code != 403 {
		t.Fatalf("wrong current token accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/token", []byte(`{"current":"`+oldToken+`","new":"`+newToken+`"}`), cookie, session.CSRF); got.Code != 200 || strings.Contains(got.Body.String(), newToken) {
		t.Fatalf("token change failed or leaked token: %d %s", got.Code, got.Body.String())
	}
	if got := call("GET", "/api/session", nil, cookie, ""); got.Code != 200 || !strings.Contains(got.Body.String(), `"authenticated":false`) {
		t.Fatalf("old session stayed valid after token change: %d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/login", []byte(`{"token":"`+oldToken+`"}`), nil, ""); got.Code != 401 {
		t.Fatalf("old token stayed valid: %d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/login", []byte(`{"token":"`+newToken+`"}`), nil, ""); got.Code != 200 {
		t.Fatalf("new token login failed: %d %s", got.Code, got.Body.String())
	}
}

func TestBusyOperationErrorNamesCurrentTask(t *testing.T) {
	c := hw.Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
	w := &webUI{config: c}
	if err := hw.WithLockNamed(c, "background sync", func() error {
		message := w.busyOperationError().Error()
		if !strings.Contains(message, "background sync") || !strings.Contains(message, "PID") {
			t.Fatalf("busy error omitted active task: %s", message)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWebUIActionAllowlist(t *testing.T) {
	for _, action := range []string{"dns-test", "dns-verify", "dns-on", "dns-off", "doctor", "doctor-network", "plan", "keys-check", "adopt", "reconcile", "gc", "recover", "abort", "hold-on", "hold-off", "url-migrate", "update-auto", "update-disable", "update-pause-on", "update-pause-off", "update-download", "update-retry"} {
		if !webActionAllowed(action) {
			t.Fatalf("missing WebUI action: %s", action)
		}
	}
	for _, action := range []string{"hard-sync", "start", "stop", "update-rollback", "", "dns-restart"} {
		if webActionAllowed(action) {
			t.Fatalf("unexpected WebUI action: %s", action)
		}
	}
}
