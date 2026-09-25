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
)

func TestWebUIRequiresSessionAndCSRFToEditSites(t *testing.T) {
	c := hw.Defaults()
	c.StateDir = filepath.Join(t.TempDir(), "state")
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
	if got := call("POST", "/api/emergency", []byte(`{"uri":"vless://secret"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated emergency action accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/update/policy", []byte(`{"policy":"minor"}`), nil, ""); got.Code != 403 {
		t.Fatalf("unauthenticated updater edit accepted: %d", got.Code)
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
	if got := call("PUT", "/api/sites", []byte(`{"sites":["example.com"]}`), cookie, ""); got.Code != 403 {
		t.Fatalf("edit without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/emergency", []byte(`{"uri":"vless://secret"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("emergency without CSRF accepted: %d", got.Code)
	}
	if got := call("POST", "/api/action", []byte(`{"action":"update-install"}`), cookie, ""); got.Code != 403 {
		t.Fatalf("update install without CSRF accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["http://example.com"]}`), cookie, session.CSRF); got.Code != 400 {
		t.Fatalf("unsafe site accepted: %d", got.Code)
	}
	if got := call("PUT", "/api/sites", []byte(`{"sites":["example.com","github.com"]}`), cookie, session.CSRF); got.Code != 200 {
		t.Fatalf("valid site update failed: %d %s", got.Code, got.Body.String())
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
	if err := setWebToken(c, newToken); err != nil {
		t.Fatal(err)
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
