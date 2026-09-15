package hotwatcher

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "00000000-0000-4000-8000-000000000001"
const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func uri(id, name string) string {
	return "vless://" + id + "@node.example.invalid:443?encryption=none&security=reality&type=tcp&sni=example.invalid&fp=firefox&pbk=" + testKey + "&sid=abcd&flow=xtls-rprx-vision#" + name
}
func TestParseMixed(t *testing.T) {
	c := Defaults()
	raw := uri(testUUID, "FIN") + "\ntrojan://placeholder@host:443\nvmess://placeholder\n"
	p, e := Parse([]byte(raw), c)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Nodes) != 1 || p.Skipped != 2 {
		t.Fatalf("%+v", p)
	}
	n := p.Nodes[0]
	if !strings.HasPrefix(n.Tag, TagPrefix) || n.Name != "FIN" {
		t.Fatal(n.Tag)
	}
	ss := n.Outbound["streamSettings"].(map[string]any)
	if ss["network"] != "raw" {
		t.Fatal(ss)
	}
}
func TestBase64Formats(t *testing.T) {
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		p, err := Parse([]byte(e.EncodeToString([]byte(uri(testUUID, "FI")))), Defaults())
		if err != nil || len(p.Nodes) != 1 {
			t.Fatal(err)
		}
	}
}
func TestStableTagIgnoresNamesOrderAndDuplicates(t *testing.T) {
	a, e := Parse([]byte(uri(testUUID, "one")), Defaults())
	if e != nil {
		t.Fatal(e)
	}
	b, e := Parse([]byte(uri(testUUID, "two")+"\n"+uri(testUUID, "three")), Defaults())
	if e != nil {
		t.Fatal(e)
	}
	if !sameNodes(a.Nodes, b.Nodes) || len(b.Nodes) != 1 {
		t.Fatal("rename changed identity")
	}
	newID := "00000000-0000-4000-8000-000000000002"
	n, _ := Parse([]byte(uri(newID, "two")), Defaults())
	if sameNodes(a.Nodes, n.Nodes) || a.Nodes[0].Identity != n.Nodes[0].Identity {
		t.Fatal("credential rotation identity broken")
	}
}
func TestParseRejectsUnsafeOrUnsupported(t *testing.T) {
	good := uri(testUUID, "FI")
	cases := map[string]string{"empty": "", "html": "<html>Error</html>", "no-vless": "trojan://somewhere", "json": `{"outbounds":[]}`, "unknown-field": strings.Replace(good, "&sid=abcd", "&sid=abcd&evil=1", 1), "insecure": strings.Replace(good, "&sid=abcd", "&sid=abcd&allowInsecure=1", 1), "duplicate": strings.Replace(good, "&sid=abcd", "&sid=abcd&sid=12", 1), "bad-uuid": strings.Replace(good, testUUID, "wrong", 1), "bad-key": strings.Replace(good, testKey, "short", 1), "bad-sid": strings.Replace(good, "sid=abcd", "sid=xyz", 1), "none": strings.Replace(good, "security=reality", "security=none", 1), "bad-type": strings.Replace(good, "type=tcp", "type=kcp", 1), "ws-vision": strings.Replace(good, "type=tcp", "type=ws", 1), "encryption": strings.Replace(good, "encryption=none", "encryption=new-encryption", 1), "bad-tls-field": strings.Replace(good, "&sid=abcd", "&sid=abcd&alpn=h2", 1)}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := Parse([]byte(s), Defaults()); e == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
func TestOneBadVLESSRejectsWholeUpdate(t *testing.T) {
	if _, e := Parse([]byte(uri(testUUID, "FI")+"\nvless://broken"), Defaults()); e == nil {
		t.Fatal("partial subscription applied")
	}
}
func TestEncodedPathDecodedOnlyOnce(t *testing.T) {
	s := "vless://" + testUUID + "@example.invalid:443?encryption=none&security=tls&type=ws&sni=example.invalid&path=%2Fa%252Fb&host=example.invalid#WS"
	c := Defaults()
	c.AllowTLS = true
	p, e := Parse([]byte(s), c)
	if e != nil {
		t.Fatal(e)
	}
	ss := p.Nodes[0].Outbound["streamSettings"].(map[string]any)
	ws := ss["wsSettings"].(map[string]any)
	if ws["path"] != "/a%2Fb" {
		t.Fatal(ws)
	}
}
func TestLoopbackOnlyTestHTTP(t *testing.T) {
	for _, s := range []string{"http://example.com", "http://localhost/x", "https://user:pass@example.com", "https://example.com/#fragment"} {
		if allowedURL(s, true) {
			t.Fatal(s)
		}
	}
	if !allowedURL("http://127.0.0.1:1234/test", true) || allowedURL("http://127.0.0.1/test", false) {
		t.Fatal("loopback policy")
	}
}
func TestFetchRedactsURLAndRejectsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private-token" {
			w.WriteHeader(403)
		} else {
			http.Redirect(w, r, "http://127.0.0.1:1/private-token", 302)
		}
	}))
	defer srv.Close()
	c := Defaults()
	c.AllowLoopbackHTTP = true
	c.SubscriptionURLFile = filepath.Join(t.TempDir(), "url")
	for _, path := range []string{"/private-token", "/redirect"} {
		os.WriteFile(c.SubscriptionURLFile, []byte(srv.URL+path), 0600)
		_, e := Fetch(c)
		if e == nil || strings.Contains(e.Error(), "private-token") || strings.Contains(e.Error(), srv.URL) {
			t.Fatalf("unsafe error: %v", e)
		}
	}
}
func TestFetchOKAndSizeLimit(t *testing.T) {
	body := uri(testUUID, "FI")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	c := Defaults()
	c.AllowLoopbackHTTP = true
	c.SubscriptionURLFile = filepath.Join(t.TempDir(), "url")
	os.WriteFile(c.SubscriptionURLFile, []byte(srv.URL), 0600)
	b, e := Fetch(c)
	if e != nil || string(b) != body {
		t.Fatal(e)
	}
	body = strings.Repeat("x", 2*1024*1024+1)
	if _, e = Fetch(c); e == nil {
		t.Fatal("oversize accepted")
	}
}
func TestConfigStrictPermissionsAndUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, encode(Defaults()), 0644)
	if _, e := LoadConfig(p); e == nil {
		t.Fatal("public config accepted")
	}
	os.Chmod(p, 0600)
	if _, e := LoadConfig(p); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte(`{"mystery":true}`), 0600)
	if _, e := LoadConfig(p); e == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestMetadataNameURLNotPrinted(t *testing.T) {
	if safeLabel("https://somewhere/private-token") != "[URL label redacted]" {
		t.Fatal("URL label exposed")
	}
}
func TestGeneratedFileCannotOverwriteRoutingOrStaticOutbounds(t *testing.T) {
	for _, name := range []string{"05_routing.json", "03_inbounds.json", "04_outbounds.json", "../04_outbounds.main.json"} {
		c := Defaults()
		c.GeneratedFile = name
		if e := c.Validate(); e == nil {
			t.Fatal("unsafe generated file accepted", name)
		}
	}
	c := Defaults()
	c.SubscriptionURLFile = filepath.Join(c.ConfigDir, "secret.txt")
	if e := c.Validate(); e == nil {
		t.Fatal("secret in confdir accepted")
	}
}
func TestTooLongLineRejected(t *testing.T) {
	s := uri(testUUID, strings.Repeat("x", 33000))
	if _, e := Parse([]byte(s), Defaults()); e == nil {
		t.Fatal("oversize line accepted")
	}
}
