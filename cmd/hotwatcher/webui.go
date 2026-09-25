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
)

//go:embed ui/*
var webAssets embed.FS

type webSession struct {
	CSRF    string
	Expires time.Time
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
}

var updaterHelperPath = "/opt/sbin/hotwatcher-updater"

type webUI struct {
	config   hw.Config
	engine   *hw.Engine
	token    string
	mu       sync.Mutex
	sessions map[string]webSession
	job      webJob
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
		if len(value) != 64 {
			return "", errors.New("повреждён токен Web UI")
		}
		if _, err := hex.DecodeString(value); err != nil {
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

func newWebUI(c hw.Config, e *hw.Engine) (*webUI, error) {
	token, err := webToken(c)
	if err != nil {
		return nil, err
	}
	return &webUI{config: c, engine: e, token: token, sessions: map[string]webSession{}}, nil
}

func (w *webUI) session(r *http.Request) (webSession, bool) {
	cookie, err := r.Cookie("hw_session")
	if err != nil || len(cookie.Value) != 64 {
		return webSession{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sessions[cookie.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(w.sessions, cookie.Value)
		return webSession{}, false
	}
	return s, true
}

func (w *webUI) csrfOK(r *http.Request, session webSession) bool {
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+w.config.WebUIListen {
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
		var input struct {
			Token string `json:"token"`
		}
		if err := decodeRequest(r, &input); err != nil || len(input.Token) != len(w.token) || subtle.ConstantTimeCompare([]byte(input.Token), []byte(w.token)) != 1 {
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
		w.sessions[id] = webSession{CSRF: csrf, Expires: time.Now().Add(12 * time.Hour)}
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
		status, statusErr := w.engine.Status()
		keys, keysErr := w.engine.KeysSnapshot()
		sites, sitesErr := w.engine.URLTestSites()
		last, lastErr := w.engine.LastURLTest()
		recovery, recoveryErr := w.engine.RecoveryStatus()
		warnings := []string{}
		for _, err := range []error{statusErr, keysErr, sitesErr, lastErr, recoveryErr} {
			if err != nil {
				warnings = append(warnings, err.Error())
			}
		}
		jsonResponse(out, 200, map[string]any{"version": hw.Version, "status": status, "keys": keys, "sites": sites, "last_test": last, "recovery": recovery, "warnings": warnings})
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
	mux.HandleFunc("GET /api/system", func(out http.ResponseWriter, r *http.Request) {
		if _, ok := w.session(r); !ok {
			apiError(out, 401, "требуется вход")
			return
		}
		jsonResponse(out, 200, readXKeenStatus())
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
			Action string `json:"action"`
			Tag    string `json:"tag"`
		}
		if err := decodeRequest(r, &input); err != nil {
			apiError(out, 400, err.Error())
			return
		}
		if input.Action != "sync" && input.Action != "check-key" && input.Action != "url-test" && input.Action != "select" && input.Action != "pin" && input.Action != "auto" && input.Action != "forget-emergency" && input.Action != "update-enable" && input.Action != "update-check" && input.Action != "update-install" {
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
		go w.runAction(job.ID, input.Action, input.Tag)
		jsonResponse(out, 202, job)
	})
	return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Cache-Control", "no-store")
		out.Header().Set("X-Content-Type-Options", "nosniff")
		out.Header().Set("X-Frame-Options", "DENY")
		out.Header().Set("Referrer-Policy", "no-referrer")
		out.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.Host != w.config.WebUIListen {
			http.Error(out, "invalid host", 421)
			return
		}
		mux.ServeHTTP(out, r)
	})
}

func (w *webUI) runAction(id uint64, action, tag string) {
	var report *hw.URLTestReport
	var err error
	if action == "update-enable" {
		err = updater.Command([]string{"enable", "--notify"})
	} else if action == "update-check" {
		err = updater.Command([]string{"check"})
	} else if action == "update-install" {
		var cmd *exec.Cmd
		cmd, err = startUpdateHelper()
		if err == nil {
			err = cmd.Wait()
		}
	} else {
		err = hw.WithLockWait(w.config, 30*time.Second, func() error {
			switch action {
			case "sync":
				err := w.engine.Sync(false)
				hw.WriteLastCheck(w.config, err == nil)
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
				r, err := w.engine.URLTestKey(tag)
				report = &r
				return err
			}
			return errors.New("неизвестная команда")
		})
	}
	ended := time.Now().UTC()
	if errors.Is(err, hw.ErrBusy) {
		err = errors.New("другая операция Hot Watcher ещё выполняется; повторите позже")
	}
	w.mu.Lock()
	if w.job.ID == id {
		w.job.EndedAt, w.job.Report = &ended, report
		if err != nil {
			w.job.State, w.job.Message = "failed", err.Error()
		} else {
			w.job.State, w.job.Message = "succeeded", "Готово"
			if action == "update-install" {
				w.job.Message = "Установка завершена; проверьте новую версию панели"
			}
		}
	}
	w.mu.Unlock()
}

func (w *webUI) runEmergency(id uint64, uri string) {
	var result hw.EmergencyImportResult
	err := hw.WithLockWait(w.config, 30*time.Second, func() error {
		var importErr error
		result, importErr = w.engine.ImportEmergency(uri)
		return importErr
	})
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
	w, err := newWebUI(c, e)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", c.WebUIListen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: w.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("Web UI:", "http://"+c.WebUIListen)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
