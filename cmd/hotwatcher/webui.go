package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"local/xkeen-hot-watcher/internal/updater"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed ui/*
var webAssets embed.FS

type webSession struct {
	CSRF    string
	Expires time.Time
	Token   string
}

type webJob struct {
	ID        uint64                    `json:"id"`
	Action    string                    `json:"action"`
	State     string                    `json:"state"`
	Message   string                    `json:"message"`
	StartedAt time.Time                 `json:"started_at"`
	EndedAt   *time.Time                `json:"ended_at,omitempty"`
	Report    *hw.URLTestReport         `json:"report,omitempty"`
	Emergency *hw.EmergencyImportResult `json:"emergency,omitempty"`
	Result    any                       `json:"result,omitempty"`
}

var updaterHelperPath = "/opt/sbin/hotwatcher-updater"

type webUI struct {
	config   hw.Config
	engine   *hw.Engine
	token    string
	hosts    map[string]bool
	mu       sync.Mutex
	reportMu sync.Mutex
	sessions map[string]webSession
	job      webJob
	health   *dashboardHealth
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validWebToken(value string) bool {
	if len(value) < 16 || len(value) > 128 || utf8.RuneCountInString(value) < 16 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func webToken(c hw.Config) (string, error) {
	info, dirErr := os.Lstat(c.StateDir)
	if os.IsNotExist(dirErr) {
		if err := os.MkdirAll(c.StateDir, 0700); err != nil {
			return "", err
		}
		info, dirErr = os.Lstat(c.StateDir)
	}
	if dirErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("небезопасный каталог состояния Web UI")
	}
	path := filepath.Join(c.StateDir, "webui-token")
	read := func() (string, error) {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", errors.New("небезопасный файл токена Web UI")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(string(b))
		if !validWebToken(value) {
			return "", errors.New("повреждён токен Web UI")
		}
		return value, nil
	}
	if _, err := os.Lstat(path); err == nil {
		return read()
	} else if !os.IsNotExist(err) {
		return "", err
	}
	value, err := randomHex(32)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		return read()
	}
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(f, value+"\n")
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return "", writeErr
	}
	return value, nil
}

func setWebToken(c hw.Config, value string) error {
	if !validWebToken(value) {
		return errors.New("токен должен содержать 16–128 печатных символов без пробелов по краям")
	}
	if _, err := webToken(c); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.StateDir, ".webui-token-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = io.WriteString(f, value+"\n")
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(c.StateDir, "webui-token"))
}

func newWebUI(c hw.Config, e *hw.Engine) (*webUI, error) {
	token, err := webToken(c)
	if err != nil {
		return nil, err
	}
	hosts := map[string]bool{c.WebUIListen: true}
	if c.WebUILANListen != "" {
		hosts[c.WebUILANListen] = true
	}
	return &webUI{config: c, engine: e, token: token, hosts: hosts, sessions: map[string]webSession{}, health: newDashboardHealth(c, e)}, nil
}

func (w *webUI) syncToken() bool {
	token, err := webToken(w.config)
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.token != token {
		w.token = token
		w.sessions = map[string]webSession{}
	}
	return true
}

func (w *webUI) session(r *http.Request) (webSession, bool) {
	if !w.syncToken() {
		return webSession{}, false
	}
	cookie, err := r.Cookie("hw_session")
	if err != nil || len(cookie.Value) != 64 {
		return webSession{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sessions[cookie.Value]
	if !ok || s.Token != w.token || time.Now().After(s.Expires) {
		delete(w.sessions, cookie.Value)
		return webSession{}, false
	}
	return s, true
}

func (w *webUI) csrfOK(r *http.Request, session webSession) bool {
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
		return false
	}
	value := r.Header.Get("X-HW-CSRF")
	return len(value) == len(session.CSRF) && subtle.ConstantTimeCompare([]byte(value), []byte(session.CSRF)) == 1
}

func jsonResponse(out http.ResponseWriter, status int, value any) {
	out.Header().Set("Content-Type", "application/json; charset=utf-8")
	out.WriteHeader(status)
	_ = json.NewEncoder(out).Encode(value)
}

func apiError(out http.ResponseWriter, status int, message string) {
	jsonResponse(out, status, map[string]string{"error": message})
}

func decodeRequest(r *http.Request, target any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("ожидается JSON")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("неверный JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("лишние данные в запросе")
	}
	return nil
}

func (w *webUI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(out http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(out, r)
			return
		}
		b, _ := webAssets.ReadFile("ui/index.html")
		out.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = out.Write(b)
	})
	for _, file := range []struct{ path, name, mime string }{
		{"/assets/app.css", "ui/app.css", "text/css; charset=utf-8"},
		{"/assets/app.js", "ui/app.js", "text/javascript; charset=utf-8"},
	} {
		asset := file
		mux.HandleFunc("GET "+asset.path, func(out http.ResponseWriter, r *http.Request) {
			b, _ := webAssets.ReadFile(asset.name)
			out.Header().Set("Content-Type", asset.mime)
			_, _ = out.Write(b)
		})
	}
	mux.HandleFunc("POST /api/login", func(out http.ResponseWriter, r *http.Request) {
		if !w.syncToken() {
			apiError(out, 500, "токен Web UI недоступен")
			return
		}
		var input struct {
			Token string `json:"token"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, http.StatusUnauthorized, "неверный токен")
			return
		}
		id, err := randomHex(32)
		if err != nil {
			apiError(out, 500, "не удалось создать сессию")
			return
		}
		csrf, err := randomHex(32)
		if err != nil {
			apiError(out, 500, "не удалось создать сессию")
			return
		}
		w.mu.Lock()
		if len(input.Token) != len(w.token) || subtle.ConstantTimeCompare([]byte(input.Token), []byte(w.token)) != 1 {
			w.mu.Unlock()
			apiError(out, http.StatusUnauthorized, "неверный токен")
			return
		}
		w.sessions[id] = webSession{CSRF: csrf, Expires: time.Now().Add(12 * time.Hour), Token: w.token}
		w.mu.Unlock()
		http.SetCookie(out, &http.Cookie{Name: "hw_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 12 * 3600})
		jsonResponse(out, 200, map[string]any{"authenticated": true, "csrf": csrf})
	})
	mux.HandleFunc("GET /api/session", func(out http.ResponseWriter, r *http.Request) {
		if session, ok := w.session(r); ok {
			jsonResponse(out, 200, map[string]any{"authenticated": true, "csrf": session.CSRF})
		} else {
			jsonResponse(out, 200, map[string]any{"authenticated": false})
		}
	})
	mux.HandleFunc("POST /api/logout", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		if cookie, err := r.Cookie("hw_session"); err == nil {
			w.mu.Lock()
			delete(w.sessions, cookie.Value)
			w.mu.Unlock()
		}
		http.SetCookie(out, &http.Cookie{Name: "hw_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
		jsonResponse(out, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/overview", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		status, statusErr, system := w.health.snapshot()
		keys, keysErr := w.engine.KeysSnapshot()
		sites, sitesErr := w.engine.URLTestSites()
		economy, modeErr := w.config.EconomyChecks()
		last, lastErr := w.engine.LastURLTest()
		recovery, recoveryErr := w.engine.RecoveryStatus()
		warnings := []string{}
		for _, err := range []error{statusErr, keysErr, sitesErr, modeErr, lastErr, recoveryErr} {
			if err != nil {
				warnings = append(warnings, err.Error())
			}
		}
		jsonResponse(out, 200, map[string]any{"version": hw.Version, "status": status, "system": system, "keys": keys, "sites": sites, "economy_checks": economy, "live_probes_allowed": w.config.AllowLiveProbes, "last_test": last, "recovery": recovery, "warnings": warnings})
	})
	mux.HandleFunc("GET /api/job", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		w.mu.Lock()
		job := w.job
		w.mu.Unlock()
		jsonResponse(out, 200, job)
	})
	mux.HandleFunc("GET /api/activity", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		activity, err := hw.ActivityStatus(w.config)
		if err != nil {
			apiError(out, 500, "не удалось прочитать состояние операции")
			return
		}
		type jobSummary struct {
			ID             uint64 `json:"id"`
			Action         string `json:"action"`
			State          string `json:"state"`
			ElapsedSeconds int64  `json:"elapsed_seconds"`
		}
		var running *jobSummary
		w.mu.Lock()
		job := w.job
		w.mu.Unlock()
		if job.State == "running" {
			elapsed := int64(0)
			if !job.StartedAt.IsZero() {
				elapsed = max(0, int64(time.Since(job.StartedAt).Seconds()))
			}
			running = &jobSummary{ID: job.ID, Action: job.Action, State: job.State, ElapsedSeconds: elapsed}
			if !activity.Lock.Busy {
				activity.Message = "Задача панели выполняется или ожидает блокировки"
			}
		}
		jsonResponse(out, 200, struct {
			hw.Activity
			WebJob *jobSummary `json:"web_job,omitempty"`
		}{activity, running})
	})
	for _, route := range []struct {
		path string
		stop bool
	}{{"POST /api/activity/stop", true}, {"POST /api/activity/resume", false}} {
		mux.HandleFunc(route.path, func(out http.ResponseWriter, r *http.Request) {
			session, ok := w.session(r)
			if !ok || !w.csrfOK(r, session) {
				apiError(out, 403, "доступ запрещён")
				return
			}
			var err error
			if route.stop {
				err = hw.StopBackground(w.config)
			} else {
				err = hw.ResumeBackground(w.config)
			}
			if err != nil {
				apiError(out, 500, "не удалось изменить состояние фоновых задач")
				return
			}
			activity, err := hw.ActivityStatus(w.config)
			if err != nil {
				apiError(out, 500, "не удалось прочитать состояние операции")
				return
			}
			jsonResponse(out, 200, activity)
		})
	}
	mux.HandleFunc("GET /api/system", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		_, _, system := w.health.snapshot()
		lan := readLANInterception(r.Context(), w.config.ConfigDir)
		system.LAN = &lan
		jsonResponse(out, 200, system)
	})
	mux.HandleFunc("GET /api/diagnostics/report", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		out.Header().Set("Cache-Control", "no-store")
		if !w.reportMu.TryLock() {
			apiError(out, 409, "диагностический отчёт уже собирается")
			return
		}
		defer w.reportMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
		defer cancel()
		jsonResponse(out, 200, w.generateStatusReport(ctx))
	})
	mux.HandleFunc("GET /api/update", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		state, err := updater.GetOverview()
		if err != nil {
			apiError(out, 500, "не удалось прочитать состояние обновлений")
			return
		}
		jsonResponse(out, 200, state)
	})
	mux.HandleFunc("GET /api/dns", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		status, err := w.engine.DNSStatus()
		if err != nil {
			apiError(out, 500, err.Error())
			return
		}
		jsonResponse(out, 200, status)
	})
	mux.HandleFunc("PUT /api/update/policy", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			Policy string `json:"policy"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		if err := updater.SetPolicy(input.Policy); err != nil {
			apiError(out, 400, "не удалось сохранить политику обновлений")
			return
		}
		jsonResponse(out, 200, map[string]string{"policy": input.Policy})
	})
	mux.HandleFunc("PUT /api/update/pin", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			Version string `json:"version"`
		}
		if err := decodeRequest(r, &input); err != nil || len(input.Version) > 64 {
			apiError(out, 400, "неверная версия")
			return
		}
		command := []string{"unpin"}
		if input.Version != "" {
			command = []string{"pin", input.Version}
		}
		if err := updater.Command(command); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		jsonResponse(out, 200, map[string]string{"pinned_version": input.Version})
	})
	mux.HandleFunc("PUT /api/sites", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			Sites []string `json:"sites"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		var sites []string
		err := hw.WithLock(w.config, func() (err error) {
			sites, err = w.engine.SaveURLTestSites(input.Sites)
			return err
		})
		if err != nil {
			apiError(out, 400, err.Error())
			return
		}
		jsonResponse(out, 200, map[string]any{"sites": sites})
	})
	mux.HandleFunc("PUT /api/probe-mode", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			EconomyChecks *bool `json:"economy_checks"`
		}
		if err := decodeRequest(r, &input); err != nil || input.EconomyChecks == nil {
			apiError(out, 400, "укажите режим проверки")
			return
		}
		if err := hw.WithLock(w.config, func() error { return w.engine.SetEconomyChecks(*input.EconomyChecks) }); err != nil {
			apiError(out, 409, err.Error())
			return
		}
		jsonResponse(out, 200, map[string]bool{"economy_checks": *input.EconomyChecks})
	})
	mux.HandleFunc("PUT /api/subscription-url", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			URL string `json:"url"`
		}
		if err := decodeRequest(r, &input); err != nil || len(input.URL) > 8192 {
			apiError(out, 400, "неверный адрес подписки")
			return
		}
		if err := hw.WithLockWait(w.config, 30*time.Second, func() error { return w.config.SetSubscriptionURL(input.URL) }); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		jsonResponse(out, 200, map[string]bool{"saved": true})
	})
	mux.HandleFunc("PUT /api/token", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		w.mu.Lock()
		valid := len(input.Current) == len(w.token) && subtle.ConstantTimeCompare([]byte(input.Current), []byte(w.token)) == 1
		w.mu.Unlock()
		if !valid {
			apiError(out, 403, "текущий токен неверен")
			return
		}
		if err := setWebToken(w.config, input.New); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		w.syncToken()
		jsonResponse(out, 200, map[string]bool{"changed": true})
	})
	mux.HandleFunc("POST /api/emergency", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			URI string `json:"uri"`
		}
		if err := decodeRequest(r, &input); err != nil || len(input.URI) > 4096 || !strings.HasPrefix(strings.TrimSpace(input.URI), "vless://") {
			apiError(out, 400, "вставьте один полный vless:// ключ")
			return
		}
		w.mu.Lock()
		if w.job.State == "running" {
			w.mu.Unlock()
			apiError(out, 409, "операция уже выполняется")
			return
		}
		w.job = webJob{ID: w.job.ID + 1, Action: "emergency", State: "running", Message: "Проверяю и применяю аварийный ключ…", StartedAt: time.Now().UTC()}
		job := w.job
		w.mu.Unlock()
		go w.runEmergency(job.ID, input.URI)
		jsonResponse(out, 202, job)
	})
	mux.HandleFunc("POST /api/action", func(out http.ResponseWriter, r *http.Request) {
		session, ok := w.session(r)
		if !ok || !w.csrfOK(r, session) {
			apiError(out, 403, "доступ запрещён")
			return
		}
		var input struct {
			Action     string   `json:"action"`
			Tag        string   `json:"tag"`
			Providers  []string `json:"providers"`
			AutoSelect *bool    `json:"auto_select"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		if !webActionAllowed(input.Action) {
			apiError(out, 400, "неизвестная команда")
			return
		}
		if (input.Action == "url-test" || input.Action == "select" || input.Action == "pin") && (len(input.Tag) > 128 || strings.ContainsAny(input.Tag, "\r\n")) {
			apiError(out, 400, "неверный тег")
			return
		}
		w.mu.Lock()
		if w.job.State == "running" {
			w.mu.Unlock()
			apiError(out, 409, "операция уже выполняется")
			return
		}
		w.job = webJob{ID: w.job.ID + 1, Action: input.Action, State: "running", Message: "Выполняется…", StartedAt: time.Now().UTC()}
		job := w.job
		w.mu.Unlock()
		autoSelect := true
		if input.AutoSelect != nil {
			autoSelect = *input.AutoSelect
		}
		go w.runAction(job.ID, input.Action, input.Tag, input.Providers, autoSelect)
		jsonResponse(out, 202, job)
	})
	return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Cache-Control", "no-store")
		out.Header().Set("X-Content-Type-Options", "nosniff")
		out.Header().Set("X-Frame-Options", "DENY")
		out.Header().Set("Referrer-Policy", "no-referrer")
		out.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if !w.hosts[r.Host] {
			http.Error(out, "invalid host", 421)
			return
		}
		mux.ServeHTTP(out, r)
	})
}

func webActionAllowed(action string) bool {
	switch action {
	case "sync", "check-key", "url-test", "select", "pin", "auto", "forget-emergency",
		"startup-check",
		"update-enable", "update-check", "update-install", "update-auto", "update-disable",
		"update-pause-on", "update-pause-off", "update-download", "update-retry",
		"dns-test", "dns-verify", "dns-on", "dns-off",
		"doctor", "doctor-network", "plan", "keys-check", "adopt", "reconcile", "gc", "url-migrate",
		"recover", "abort", "hold-on", "hold-off", "lan-repair":
		return true
	}
	return false
}

func (w *webUI) runAction(id uint64, action, tag string, providers []string, autoSelect bool) {
	defer w.health.refresh()
	var report *hw.URLTestReport
	var result any
	var err error
	if action == "update-enable" {
		err = updater.Command([]string{"enable", "--notify"})
	} else if action == "update-check" {
		err = updater.Command([]string{"check"})
	} else if action == "update-auto" {
		err = updater.Command([]string{"enable"})
	} else if action == "update-disable" {
		err = updater.Command([]string{"disable"})
	} else if action == "update-pause-on" {
		err = updater.Command([]string{"pause", "on"})
	} else if action == "update-pause-off" {
		err = updater.Command([]string{"pause", "off"})
	} else if action == "update-download" {
		err = updater.Command([]string{"download"})
	} else if action == "update-retry" {
		err = updater.Command([]string{"retry"})
	} else if action == "update-install" {
		var cmd *exec.Cmd
		cmd, err = startUpdateHelper()
		if err == nil {
			err = cmd.Wait()
		}
	} else if action == "dns-test" {
		if providers != nil {
			err = w.engine.SaveDNSProviderSelection(providers, autoSelect)
		}
		if err == nil {
			result, err = w.engine.DNSTest()
		}
	} else if action == "dns-verify" {
		verification, verifyErr := w.engine.DNSVerify()
		result, err = verification, verifyErr
		if err == nil && !verification.Direct.Success && !verification.SelectedVLESS.Success {
			err = errors.New("DNS не ответил ни через прямой, ни через выбранный VLESS-маршрут")
		}
	} else if action == "doctor-network" {
		var network hw.NetworkDoctorReport
		err = hw.WithLockWaitNamed(w.config, "web doctor-network", 30*time.Second, func() error {
			network = w.engine.DoctorNetworkWithProgress(func(check hw.NetworkCheck) {
				w.mu.Lock()
				if w.job.ID == id {
					w.job.Message = "Диагностика: " + check.Detail
				}
				w.mu.Unlock()
			})
			return nil
		})
		result = network
		if err == nil && !network.Healthy {
			err = errors.New("часть сетевых проверок не прошла; изучите отчёт")
		}
	} else if action == "doctor" {
		result, err = w.engine.Doctor()
	} else if action == "startup-check" {
		check := checkXKeenStartup(context.Background(), w.config.OutboundMark)
		result, err = check, startupCheckError(check)
	} else if action == "plan" {
		result, err = w.engine.Plan()
	} else if action == "keys-check" {
		err = hw.WithLockWaitNamed(w.config, "web keys-check", 30*time.Second, func() error {
			var checkErr error
			result, checkErr = w.engine.Keys()
			return checkErr
		})
	} else {
		err = hw.WithLockWaitNamed(w.config, "web "+action, 30*time.Second, func() error {
			switch action {
			case "lan-repair":
				var repair lanRepairResult
				repair, err = w.repairLAN(context.Background())
				result = repair
				return err
			case "dns-on":
				if providers != nil {
					if err := w.engine.SaveDNSProviderSelection(providers, autoSelect); err != nil {
						return err
					}
				}
				if _, err := os.Lstat(filepath.Join(w.config.StateDir, "pending.json")); err == nil {
					return errors.New("сначала завершите операцию с ключами: recover или abort")
				} else if !os.IsNotExist(err) {
					return err
				}
				var change hw.DNSChange
				change, err = w.engine.DNSAutoOn()
				result = change
				return err
			case "dns-off":
				return w.engine.DNSAutoOff()
			case "adopt":
				return w.engine.Sync(true)
			case "reconcile":
				return w.engine.Reconcile()
			case "gc":
				return w.engine.GC()
			case "recover":
				return w.engine.Recover()
			case "abort":
				return w.engine.Abort()
			case "hold-on":
				return w.engine.Hold(true)
			case "hold-off":
				return w.engine.Hold(false)
			case "url-migrate":
				return w.config.MigrateSubscriptionURL()
			case "sync":
				before, _ := w.engine.KeysSnapshot()
				err := w.engine.Sync(false)
				hw.WriteLastCheck(w.config, err == nil)
				if err == nil {
					after, snapshotErr := w.engine.KeysSnapshot()
					if snapshotErr == nil {
						previousNames := make(map[string]string, len(before.Keys))
						for _, key := range before.Keys {
							previousNames[key.Tag] = key.Name
						}
						fetched, applied, emergency, renamed := 0, 0, 0, 0
						for _, key := range after.Keys {
							if key.Latest {
								fetched++
							}
							if key.Applied {
								applied++
							}
							if key.Emergency {
								emergency++
							}
							if previous, ok := previousNames[key.Tag]; ok && previous != key.Name {
								renamed++
							}
						}
						result = map[string]any{"fetched_nodes": fetched, "applied_nodes": applied, "emergency_nodes": emergency, "renamed_nodes": renamed, "fetched_at": after.FetchedAt}
					}
				}
				return err
			case "check-key":
				_, err := w.engine.CheckKey()
				return err
			case "select":
				return w.engine.Select(tag)
			case "pin":
				return w.engine.Pin(tag)
			case "auto":
				_, err := w.engine.Automatic()
				return err
			case "forget-emergency":
				return w.engine.RemoveEmergency()
			case "url-test":
				r, err := w.engine.URLTestKeyWithProgress(tag, func(snapshot hw.URLTestReport) {
					w.mu.Lock()
					if w.job.ID == id {
						w.job.Report = &snapshot
						completed := 0
						for _, item := range snapshot.Results {
							if item.Completed {
								completed++
							}
						}
						w.job.Message = fmt.Sprintf("URL Test: проверено %d из %d сайтов", completed, len(snapshot.Results))
					}
					w.mu.Unlock()
				})
				report = &r
				return err
			}
			return errors.New("неизвестная команда")
		})
	}
	ended := time.Now().UTC()
	if errors.Is(err, hw.ErrBusy) {
		err = w.busyOperationError()
	}
	w.mu.Lock()
	if w.job.ID == id {
		w.job.EndedAt, w.job.Report, w.job.Result = &ended, report, result
		if err != nil {
			w.job.State, w.job.Message = "failed", err.Error()
		} else {
			w.job.State, w.job.Message = "succeeded", "Готово"
			if action == "update-install" {
				w.job.Message = "Установка завершена; проверьте новую версию панели"
			} else if action == "dns-on" || action == "dns-off" {
				w.job.Message = "DNS-файл изменён. Проверьте xkeen -xtest и вне игры выполните xkeen -restart."
			}
		}
	}
	w.mu.Unlock()
}

func (w *webUI) runEmergency(id uint64, uri string) {
	defer w.health.refresh()
	var result hw.EmergencyImportResult
	err := hw.WithLockWaitNamed(w.config, "web emergency", 30*time.Second, func() error {
		var importErr error
		result, importErr = w.engine.ImportEmergency(uri)
		return importErr
	})
	if errors.Is(err, hw.ErrBusy) {
		err = w.busyOperationError()
	}
	ended := time.Now().UTC()
	w.mu.Lock()
	if w.job.ID == id {
		w.job.EndedAt = &ended
		if err != nil {
			w.job.State, w.job.Message = "failed", err.Error()
		} else {
			w.job.State, w.job.Message = "succeeded", "Аварийный ключ применён и закреплён"
			w.job.Emergency = &result
			if result.Warning != "" {
				w.job.Message += ". " + result.Warning
			}
		}
	}
	w.mu.Unlock()
}

func (w *webUI) busyOperationError() error {
	activity, err := hw.ActivityStatus(w.config)
	if err != nil || !activity.Lock.Busy {
		return errors.New("другая операция Hot Watcher ещё выполняется; состояние видно в разделе «Система»")
	}
	return fmt.Errorf("занято: %s (PID %d, %d сек); состояние видно в разделе «Система»", activity.Lock.Operation, activity.Lock.PID, activity.ElapsedSeconds)
}

// A separate session lets the signed updater stop and restart the Web UI
// service without killing its own installation process.
func startUpdateHelper() (*exec.Cmd, error) {
	info, err := os.Lstat(updaterHelperPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("исполняемый файл обновлятора не найден")
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer null.Close()
	cmd := exec.Command(updaterHelperPath, "apply")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return nil, errors.New("не удалось запустить обновлятор")
	}
	return cmd, nil
}

func serveWebUI(ctx context.Context, c hw.Config, e *hw.Engine) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w, err := newWebUI(c, e)
	if err != nil {
		return err
	}
	addresses := []string{c.WebUIListen}
	if c.WebUILANListen != "" && c.WebUILANListen != c.WebUIListen {
		addresses = append(addresses, c.WebUILANListen)
	}
	listeners := make([]net.Listener, 0, len(addresses))
	var bindError error
	for _, address := range addresses {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			bindError = listenErr
			hw.SafeLog(c, "webui_bind_failed", map[string]any{"address": address})
			continue
		}
		listeners = append(listeners, listener)
		fmt.Println("Web UI:", "http://"+address)
	}
	if len(listeners) == 0 {
		return bindError
	}
	w.health.start(ctx, 30*time.Second)
	servers := make([]*http.Server, 0, len(listeners))
	finished := make(chan error, len(listeners))
	for _, listener := range listeners {
		server := &http.Server{Handler: w.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 8192}
		servers = append(servers, server)
		go func() {
			serveErr := server.Serve(listener)
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = nil
			}
			finished <- serveErr
		}()
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(shutdown)
		}
	}()
	var serveError error
	for range servers {
		serveErr := <-finished
		if serveErr != nil {
			serveError = serveErr
		}
	}
	return serveError
}
