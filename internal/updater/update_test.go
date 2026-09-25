package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedManifest(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	old := PublicKeyB64
	PublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	defer func() { PublicKeyB64 = old }()
	m := Manifest{SchemaVersion: 1, Application: app, Repository: repo, RepositoryID: 1371012653, Version: "0.2.1", Tag: "v0.2.1", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseSequence: 2001, Channel: "stable", PublishedAt: time.Now().UTC(), MinimumUpdaterProtocol: 1, ConfigSchema: 1, StateSchema: 1, Assets: []Asset{{Name: "hotwatcher_v0.2.1_linux_arm64", OS: "linux", Arch: "arm64", Size: 100, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "hotwatcher"}}}
	b, _ := json.Marshal(m)
	signed := ed25519.Sign(priv, append([]byte(signingContext), b...))
	sig, _ := json.Marshal(Signature{Algorithm: "Ed25519", KeyID: "bootstrap-v1", Signature: base64.StdEncoding.EncodeToString(signed)})
	if _, e = verifyManifest(b, sig); e != nil {
		t.Fatal(e)
	}
	altered := append([]byte{}, b...)
	altered[len(altered)-2] = 'x'
	if _, e = verifyManifest(altered, sig); e == nil {
		t.Fatal("tampered manifest accepted")
	}
	m.RepositoryID++
	b, _ = json.Marshal(m)
	signed = ed25519.Sign(priv, append([]byte(signingContext), b...))
	sig, _ = json.Marshal(Signature{Algorithm: "Ed25519", KeyID: "bootstrap-v1", Signature: base64.StdEncoding.EncodeToString(signed)})
	if _, e = verifyManifest(b, sig); e == nil {
		t.Fatal("wrong repository accepted")
	}
}
func TestVersionPolicy(t *testing.T) {
	for _, tc := range []struct {
		cur, next, policy string
		want              bool
	}{{"0.2.0", "0.2.1", "patch", true}, {"0.2.9", "0.2.10", "patch", true}, {"0.2.0", "0.3.0", "patch", false}, {"0.2.0", "0.3.0", "minor", true}, {"0.2.0", "1.0.0", "minor", false}, {"0.2.0", "0.2.1-rc.1", "patch", false}, {"0.2.0", "0.2.0", "patch", false}} {
		if got := eligible(tc.cur, tc.next, tc.policy); got != tc.want {
			t.Errorf("%s -> %s: %v", tc.cur, tc.next, got)
		}
	}
}
func TestStrictJSONRejectsDuplicate(t *testing.T) {
	var v map[string]any
	if e := strictJSON([]byte(`{"a":1,"a":2}`), &v); e == nil {
		t.Fatal("duplicate keys accepted")
	}
}

func TestGitHubReleasesDecoderAllowsExtraFieldsButRejectsUnsafeJSON(t *testing.T) {
	b := []byte(`[{"url":"https://api.github.com/repos/Horooko/XKeen-HotWatcher/releases/1","id":1,"tag_name":"v0.2.5","draft":false,"prerelease":false,"author":{"login":"Horooko","url":"https://api.github.com/users/Horooko"},"assets":[{"id":2,"name":"release-manifest.json","url":"https://api.github.com/repos/Horooko/XKeen-HotWatcher/releases/assets/2","browser_download_url":"https://github.com/Horooko/XKeen-HotWatcher/releases/download/v0.2.5/release-manifest.json"}]}]`)
	releases, err := decodeReleases(b)
	if err != nil || len(releases) != 1 || releases[0].TagName != "v0.2.5" {
		t.Fatal("realistic GitHub response rejected", err)
	}
	if _, err = releaseAsset(releases[0], "release-manifest.json"); err != nil {
		t.Fatal("asset URL not read from browser_download_url", err)
	}
	for _, bad := range [][]byte{[]byte(`[{"id":1,"id":2}]`), append(append([]byte{}, b...), []byte(` true`)...)} {
		if _, err = decodeReleases(bad); err == nil {
			t.Fatal("unsafe GitHub JSON accepted")
		}
	}
	var strict []Release
	if err = strictJSON(b, &strict); err == nil {
		t.Fatal("signed data decoder unexpectedly became permissive")
	}
}

func TestOfflineRepairRecordsBinaryAndPreservesHighWater(t *testing.T) {
	oldRoot, oldBinary, oldConfig := Root, Binary, ConfigPath
	Root = t.TempDir()
	if err := os.Chmod(Root, 0700); err != nil {
		t.Fatal(err)
	}
	Binary = filepath.Join(Root, "hotwatcher")
	ConfigPath = filepath.Join(Root, "updates.json")
	defer func() { Root, Binary, ConfigPath = oldRoot, oldBinary, oldConfig }()
	if err := os.WriteFile(Binary, []byte("candidate-v0.2.11"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := save(ConfigPath, Defaults()); err != nil {
		t.Fatal(err)
	}
	if err := save(statePath(), State{Installed: "0.2.4", InstalledHash: "old", HighWater: 2004, Verified: true}); err != nil {
		t.Fatal(err)
	}
	if err := RepairOfflineBootstrap("0.2.11"); err != nil {
		t.Fatal(err)
	}
	s := readState()
	hash, _ := hashFile(Binary)
	if s.Invalid || s.Installed != "0.2.11" || s.Previous != "0.2.4" || s.InstalledHash != hash || s.HighWater != 2011 || s.Verified {
		t.Fatal("offline repair state incorrect", s)
	}
	if err := save(statePath(), State{Installed: "0.2.12", HighWater: 2012}); err != nil {
		t.Fatal(err)
	}
	if err := RepairOfflineBootstrap("0.2.11"); err == nil || readState().HighWater != 2012 {
		t.Fatal("offline repair lowered high-water mark")
	}
}

func TestUpdateResultDoesNotChangeStrictUpdaterState(t *testing.T) {
	oldRoot := Root
	Root = t.TempDir()
	defer func() { Root = oldRoot }()
	if err := os.Chmod(Root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := save(statePath(), State{Installed: "0.2.9", HighWater: 2009}); err != nil {
		t.Fatal(err)
	}
	recordResult("installed", "0.2.9", "0.2.10")
	result := readResult()
	if result == nil || result.Outcome != "installed" || result.Target != "0.2.10" || readState().Invalid {
		t.Fatalf("update result broke state compatibility: %+v", result)
	}
}

func TestUpdateOverviewShowsVersionAndRollbackWithoutRawState(t *testing.T) {
	oldRoot := Root
	Root = t.TempDir()
	defer func() { Root = oldRoot }()
	if err := os.Chmod(Root, 0700); err != nil {
		t.Fatal(err)
	}
	recordResult("rolled_back", "0.2.10", "0.2.9")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = writer
	printUpdateOverview(Defaults(), State{Installed: "0.2.9", Available: "0.2.10", Verified: true})
	writer.Close()
	os.Stdout = oldStdout
	output, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Contains(output, []byte("0.2.10")) || !bytes.Contains(output, []byte("откат")) || bytes.Contains(output, []byte(`"configuration"`)) {
		t.Fatalf("update overview is incomplete or raw: %s, %v", output, err)
	}
}
func TestReleaseAssetExactURL(t *testing.T) {
	var r Release
	r.TagName = "v0.2.1"
	r.Assets = append(r.Assets, struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}{1, "release-manifest.json", "https://evil.example/release-manifest.json"})
	if _, e := releaseAsset(r, "release-manifest.json"); e == nil {
		t.Fatal("foreign asset URL accepted")
	}
}
func TestBootRecoveryRestoresPreviousBinary(t *testing.T) {
	oldRoot, oldBinary := Root, Binary
	Root = t.TempDir()
	if e := os.Chmod(Root, 0700); e != nil {
		t.Fatal(e)
	}
	Binary = filepath.Join(Root, "hotwatcher")
	defer func() { Root, Binary = oldRoot, oldBinary }()
	old := filepath.Join(Root, "old")
	if e := os.WriteFile(old, []byte("known good"), 0700); e != nil {
		t.Fatal(e)
	}
	h, e := hashFile(old)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(Binary, []byte("broken candidate"), 0700); e != nil {
		t.Fatal(e)
	}
	j := Journal{ID: "0123456789abcdef0123456789abcdef", Phase: "installed", Version: "0.2.1", Hash: "blocked", PreviousHash: h, PreviousPath: old}
	if e = save(journalPath(), j); e != nil {
		t.Fatal(e)
	}
	if e = save(maintenancePath(), map[string]string{"id": j.ID}); e != nil {
		t.Fatal(e)
	}
	if e = Recover(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(Binary)
	if e != nil || string(b) != "known good" {
		t.Fatal("previous binary not restored")
	}
	s := readState()
	if s.BlockedHash != "blocked" {
		t.Fatal("failed asset not blocked")
	}
	if _, e = os.Lstat(maintenancePath()); !os.IsNotExist(e) {
		t.Fatal("maintenance guard left after rollback")
	}
}
