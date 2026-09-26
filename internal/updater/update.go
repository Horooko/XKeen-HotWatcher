package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Root = "/opt/var/lib/hotwatcher-updater"
var Binary = "/opt/sbin/hotwatcher"
var ConfigPath = "/opt/etc/hotwatcher/updates.json"

const app = "xkeen-hotwatcher"
const repo = "Horooko/XKeen-HotWatcher"
const protocol = 1
const signingContext = "XKeen-HotWatcher release manifest v1\x00"

var ErrNoUpdate = errors.New("no compatible signed release")

// Injected only when building a trusted bootstrap updater. An unset key fails closed.
var PublicKeyB64 = "HAEyxEhNmL1QwZ4OppQZ8F5xsvDw6v3PGFinMhhnzeU="
var Commit = "unknown"
var BuildTime = "unknown"
var Dirty = "true"

func BuildInfo() map[string]any {
	return map[string]any{"version": hw.Version, "commit": Commit, "build_time_utc": BuildTime, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "dirty": Dirty == "true", "updater_protocol": protocol, "config_schema": 1, "state_schema": 1}
}

type Config struct {
	SchemaVersion           int             `json:"schema_version"`
	Enabled                 bool            `json:"enabled"`
	Mode                    string          `json:"mode"`
	Repository              string          `json:"repository"`
	Channel                 string          `json:"channel"`
	Policy                  string          `json:"policy"`
	CheckIntervalSeconds    int             `json:"check_interval_seconds"`
	JitterSeconds           int             `json:"jitter_seconds"`
	RespectHold             bool            `json:"respect_hold"`
	PinnedVersion           string          `json:"pinned_version"`
	ApplyWindow             json.RawMessage `json:"apply_window"`
	RetainVersions          int             `json:"retain_versions"`
	ReadinessTimeoutSeconds int             `json:"readiness_timeout_seconds"`
	ShutdownTimeoutSeconds  int             `json:"shutdown_timeout_seconds"`
	MaxDownloadBytes        int64           `json:"max_download_bytes"`
}

func Defaults() Config {
	return Config{SchemaVersion: 1, Enabled: true, Mode: "notify", Repository: repo, Channel: "stable", Policy: "patch", CheckIntervalSeconds: 21600, JitterSeconds: 900, RespectHold: true, RetainVersions: 2, ReadinessTimeoutSeconds: 90, ShutdownTimeoutSeconds: 300, MaxDownloadBytes: 33554432}
}
func (c Config) Validate() error {
	if c.SchemaVersion != 1 || c.Repository != repo || c.Channel != "stable" || (c.Mode != "notify" && c.Mode != "auto") || (c.Policy != "patch" && c.Policy != "minor") {
		return errors.New("unsupported update configuration")
	}
	if c.CheckIntervalSeconds < 3600 || c.JitterSeconds < 0 || c.JitterSeconds > 3600 || c.ReadinessTimeoutSeconds < 10 || c.ReadinessTimeoutSeconds > 300 || c.ShutdownTimeoutSeconds < 30 || c.ShutdownTimeoutSeconds > 600 || c.MaxDownloadBytes < 1024 || c.MaxDownloadBytes > 33554432 {
		return errors.New("update limits out of range")
	}
	if c.RetainVersions < 2 || c.RetainVersions > 4 {
		return errors.New("retain_versions must be 2..4")
	}
	if !c.RespectHold {
		return errors.New("hold guard cannot be disabled")
	}
	if len(c.ApplyWindow) > 0 && string(c.ApplyWindow) != "null" {
		return errors.New("apply_window scheduling is not supported in protocol v1")
	}
	return nil
}
func loadConfig() (Config, error) {
	c := Defaults()
	b, e := privateRead(ConfigPath, 1<<20)
	if e != nil {
		return c, e
	}
	e = strictJSON(b, &c)
	if e != nil {
		return c, fmt.Errorf("invalid updater settings %s: %w", ConfigPath, e)
	}
	return c, c.Validate()
}

type Asset struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}
type Manifest struct {
	SchemaVersion           int       `json:"schema_version"`
	Application             string    `json:"application"`
	Repository              string    `json:"repository"`
	RepositoryID            int64     `json:"repository_id"`
	Version                 string    `json:"version"`
	Tag                     string    `json:"tag"`
	Commit                  string    `json:"commit"`
	ReleaseSequence         uint64    `json:"release_sequence"`
	Channel                 string    `json:"channel"`
	PublishedAt             time.Time `json:"published_at"`
	MinimumUpdaterProtocol  int       `json:"minimum_updater_protocol"`
	ConfigSchema            int       `json:"config_schema"`
	StateSchema             int       `json:"state_schema"`
	RequiresXrayRestart     bool      `json:"requires_xray_restart"`
	RequiresManualMigration bool      `json:"requires_manual_migration"`
	Assets                  []Asset   `json:"assets"`
}
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type Release struct {
	ID         int64  `json:"id"`
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}
type State struct {
	LastCheck     time.Time `json:"last_check"`
	NextCheck     time.Time `json:"next_check"`
	Available     string    `json:"available"`
	Verified      bool      `json:"verified"`
	Installed     string    `json:"installed"`
	InstalledHash string    `json:"installed_hash"`
	HighWater     uint64    `json:"high_water"`
	Previous      string    `json:"previous"`
	BlockedHash   string    `json:"blocked_hash"`
	Deferred      string    `json:"deferred"`
	ETag          string    `json:"etag"`
	Failures      int       `json:"failures"`
	Invalid       bool      `json:"-"`
}

type UpdateResult struct {
	Schema   int       `json:"schema"`
	Time     time.Time `json:"time"`
	Outcome  string    `json:"outcome"`
	Previous string    `json:"previous,omitempty"`
	Target   string    `json:"target,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

func resultPath() string { return filepath.Join(Root, "last-result.json") }

func recordResult(outcome, previous, target string) {
	_ = save(resultPath(), UpdateResult{Schema: 1, Time: time.Now().UTC(), Outcome: outcome, Previous: previous, Target: target})
}

func recordDeferred(previous, target string, reason error) {
	_ = save(resultPath(), UpdateResult{Schema: 1, Time: time.Now().UTC(), Outcome: "deferred", Previous: previous, Target: target, Reason: reason.Error()})
}

func readResult() *UpdateResult {
	b, err := privateRead(resultPath(), 4096)
	if err != nil {
		return nil
	}
	var result UpdateResult
	if strictJSON(b, &result) != nil || result.Schema != 1 || result.Time.IsZero() || (result.Outcome != "installed" && result.Outcome != "rolled_back" && result.Outcome != "deferred") {
		return nil
	}
	return &result
}

type Journal struct {
	ID            string `json:"id"`
	Phase         string `json:"phase"`
	Version       string `json:"version"`
	Hash          string `json:"hash"`
	PreviousHash  string `json:"previous_hash"`
	PreviousPath  string `json:"previous_path"`
	Enabled       bool   `json:"enabled"`
	PreviousState State  `json:"previous_state"`
}
type ProcessIdentity struct {
	PID             int    `json:"pid"`
	StartTime       string `json:"start_time"`
	Executable      string `json:"executable"`
	ArgumentsSHA256 string `json:"arguments_sha256"`
}
type heartbeat struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	PID     int    `json:"pid"`
	Ready   bool   `json:"ready"`
}

func readHeartbeat(path, id, version string, pid int) bool {
	b, e := privateRead(path, 4096)
	if e != nil {
		return false
	}
	var h heartbeat
	if strictJSON(b, &h) != nil {
		return false
	}
	return h.Ready && h.ID == id && h.Version == version && h.PID > 0 && (pid == 0 || h.PID == pid)
}

func xrayIdentities() ([]ProcessIdentity, error) {
	c, err := hw.LoadConfig("/opt/etc/hotwatcher/config.json")
	if err != nil {
		return nil, err
	}
	return scanXrayIdentities("/proc", c.XrayBinary, c.StateDir)
}

func scanXrayIdentities(procDir, binary, stateDir string) ([]ProcessIdentity, error) {
	found := []ProcessIdentity{}
	entries, e := os.ReadDir(procDir)
	if e != nil {
		return found, e
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		base := filepath.Join(procDir, entry.Name())
		exe, e := os.Readlink(filepath.Join(base, "exe"))
		if e != nil {
			continue
		}
		if exe != binary && exe != binary+" (deleted)" {
			continue
		}
		args, e := os.ReadFile(filepath.Join(base, "cmdline"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return found, e
		}
		if !hw.IsXrayServerCommand(strings.Split(strings.TrimRight(string(args), "\x00"), "\x00"), binary, stateDir) {
			continue
		}
		stat, e := os.ReadFile(filepath.Join(base, "stat"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return found, e
		}
		end := bytes.LastIndexByte(stat, ')')
		if end < 0 {
			return found, errors.New("invalid Xray proc stat")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 20 {
			return found, errors.New("invalid Xray proc fields")
		}
		h := sha256.Sum256(args)
		found = append(found, ProcessIdentity{PID: pid, StartTime: fields[19], Executable: exe, ArgumentsSHA256: hex.EncodeToString(h[:])})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].PID < found[j].PID })
	return found, nil
}
func protectedHashes() (map[string]string, error) {
	c, e := hw.LoadConfig("/opt/etc/hotwatcher/config.json")
	if e != nil {
		return nil, e
	}
	files := []string{"/opt/etc/hotwatcher/config.json", c.SubscriptionURLFile, c.APIURLPath(), filepath.Join(c.StateDir, "state.json"), filepath.Join(c.ConfigDir, c.GeneratedFile)}
	out := map[string]string{}
	for i, p := range files {
		h, e := hashFile(p)
		if os.IsNotExist(e) && i >= 2 {
			out[p] = "<absent>"
			continue
		}
		if e != nil {
			return nil, e
		}
		out[p] = h
	}
	return out, nil
}

type runtimeSnapshot struct {
	Adopted              bool
	APIReachable         bool
	BalancerAPIReachable bool
	BalancerPinMatches   bool
	Selected             string
	RuntimeOverride      string
}

func selectedRuntime() (runtimeSnapshot, error) {
	c, e := hw.LoadConfig("/opt/etc/hotwatcher/config.json")
	if e != nil {
		return runtimeSnapshot{}, e
	}
	v, e := hw.New(c).Status()
	if e != nil {
		return runtimeSnapshot{}, e
	}
	return runtimeSnapshotFromStatus(v), nil
}

func runtimeSnapshotFromStatus(v map[string]any) runtimeSnapshot {
	selected, _ := v["selected"].(string)
	override, _ := v["runtime_override"].(string)
	return runtimeSnapshot{
		Adopted:              v["adopted"] == true,
		APIReachable:         v["api_reachable"] == true,
		BalancerAPIReachable: v["balancer_api_reachable"] == true,
		BalancerPinMatches:   v["balancer_pin_matches"] == true,
		Selected:             selected,
		RuntimeOverride:      override,
	}
}

func strictJSON(b []byte, v any) error {
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// GitHub's public release response contains many fields outside our small
// projection. Keep duplicate-key and trailing-data checks, then decode only
// the fields needed to locate assets. Signed manifests remain strictJSON.
func decodeReleases(b []byte) ([]Release, error) {
	var releases []Release
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&releases); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing GitHub releases JSON")
	}
	return releases, nil
}
func rejectDuplicateKeys(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	return walkJSON(d, t)
}
func walkJSON(d *json.Decoder, t json.Token) error {
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := k.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[name] = true
			v, e := d.Token()
			if e != nil {
				return e
			}
			if e = walkJSON(d, v); e != nil {
				return e
			}
		}
	} else if delim == '[' {
		for d.More() {
			v, e := d.Token()
			if e != nil {
				return e
			}
			if e = walkJSON(d, v); e != nil {
				return e
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, e := d.Token()
	return e
}
func privateRead(p string, max int64) ([]byte, error) {
	s, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe private file")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, e
}
func ensureDir(p string) error {
	s, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return os.MkdirAll(p, 0700)
	}
	if e != nil {
		return e
	}
	if !s.IsDir() || s.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe updater directory")
	}
	return nil
}
func atomic(p string, b []byte, mode os.FileMode) error {
	if s, e := os.Lstat(p); e == nil && !s.Mode().IsRegular() {
		return errors.New("unsafe replacement path")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".update-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), p); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func save(p string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomic(p, append(b, '\n'), 0600)
}
func statePath() string       { return filepath.Join(Root, "state.json") }
func journalPath() string     { return filepath.Join(Root, "pending-update.json") }
func maintenancePath() string { return filepath.Join(Root, "maintenance.json") }
func readState() State {
	var s State
	b, e := privateRead(statePath(), 1<<20)
	if os.IsNotExist(e) {
		if _, markerErr := os.Lstat(ConfigPath); markerErr == nil {
			s.Invalid = true
		}
		return s
	}
	if e != nil || strictJSON(b, &s) != nil {
		s.Invalid = true
	}
	return s
}
func readJournal() (Journal, error) {
	var j Journal
	b, e := privateRead(journalPath(), 1<<20)
	if e != nil {
		return j, e
	}
	e = strictJSON(b, &j)
	return j, e
}
func hashFile(p string) (string, error) {
	s, e := os.Lstat(p)
	if e != nil {
		return "", e
	}
	if !s.Mode().IsRegular() {
		return "", errors.New("unsafe binary path")
	}
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}
func lock() (func(), error) {
	if e := ensureDir(Root); e != nil {
		return nil, e
	}
	p := filepath.Join(Root, "update.lock")
	if s, e := os.Lstat(p); e == nil && !s.Mode().IsRegular() {
		return nil, errors.New("unsafe update lock")
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another updater is active")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func semver(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	if strings.ContainsAny(s, "-+") {
		return v, false
	}
	a := strings.Split(s, ".")
	if len(a) != 3 {
		return v, false
	}
	for i, x := range a {
		if x == "" || (len(x) > 1 && x[0] == '0') {
			return v, false
		}
		n, e := strconv.Atoi(x)
		if e != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}
func eligible(current, candidate, policy string) bool {
	a, ok := semver(current)
	b, yes := semver(candidate)
	if !ok || !yes {
		return false
	}
	if a[0] != b[0] || b[1] < a[1] || b[0] > 0 && b[1] != a[1] {
		return false
	}
	if policy == "patch" && b[1] != a[1] {
		return false
	}
	return b[1] > a[1] || b[1] == a[1] && b[2] > a[2]
}

// RepairOfflineBootstrap records an administrator-installed release after the
// v0.2.4 updater could not parse GitHub's public release response. It cannot
// lower the rollback high-water mark or accept a version other than this binary.
func RepairOfflineBootstrap(expected string) error {
	if expected != hw.Version {
		return errors.New("offline package version differs from installed Hot Watcher")
	}
	v, ok := semver(expected)
	if !ok || v[1] > 999 || v[2] > 999 {
		return errors.New("invalid offline package version")
	}
	sequence := uint64(v[0])*1000000 + uint64(v[1])*1000 + uint64(v[2])
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = loadConfig(); err != nil {
		return err
	}
	if _, err = os.Lstat(journalPath()); err == nil {
		return errors.New("pending software update exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	s := readState()
	if s.Invalid || s.HighWater > sequence {
		return errors.New("offline repair would overwrite invalid or newer updater state")
	}
	hash, err := hashFile(Binary)
	if err != nil {
		return err
	}
	if s.Installed != expected {
		s.Previous = s.Installed
	}
	s.Installed, s.InstalledHash, s.HighWater = expected, hash, sequence
	s.Verified = false // The one-time archive repair did not use signed manifest verification.
	s.Available, s.Deferred, s.BlockedHash, s.ETag = "", "", "", ""
	s.Failures = 0
	s.NextCheck = time.Now().UTC()
	return save(statePath(), s)
}
func verifyManifest(b, sigBytes []byte) (Manifest, error) {
	var m Manifest
	key, e := base64.StdEncoding.DecodeString(PublicKeyB64)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return m, errors.New("trusted signing key is not installed")
	}
	var sig Signature
	if e = strictJSON(sigBytes, &sig); e != nil {
		return m, e
	}
	if sig.Algorithm != "Ed25519" || sig.KeyID != "bootstrap-v1" {
		return m, errors.New("unsupported release signature")
	}
	raw, e := base64.StdEncoding.DecodeString(sig.Signature)
	if e != nil || !ed25519.Verify(key, append([]byte(signingContext), b...), raw) {
		return m, errors.New("release signature invalid")
	}
	if e = strictJSON(b, &m); e != nil {
		return m, e
	}
	if m.SchemaVersion != 1 || m.Application != app || m.Repository != repo || m.RepositoryID != 1371012653 || m.Tag != "v"+m.Version || m.ReleaseSequence == 0 || m.Channel != "stable" || m.MinimumUpdaterProtocol < 1 || m.MinimumUpdaterProtocol > protocol || m.ConfigSchema != 1 || m.StateSchema != 1 || m.RequiresXrayRestart || m.RequiresManualMigration || len(m.Assets) == 0 || m.PublishedAt.IsZero() {
		return m, errors.New("release manifest incompatible")
	}
	if _, ok := semver(m.Version); !ok {
		return m, errors.New("invalid release version")
	}
	if len(m.Commit) != 40 {
		return m, errors.New("invalid release commit")
	}
	if _, e := hex.DecodeString(m.Commit); e != nil {
		return m, errors.New("invalid release commit")
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if a.Name == "" || seen[a.Name] || a.Size <= 0 || len(a.SHA256) != 64 {
			return m, errors.New("invalid or duplicate release asset")
		}
		seen[a.Name] = true
		if _, e := hex.DecodeString(a.SHA256); e != nil {
			return m, errors.New("invalid asset hash")
		}
	}
	return m, nil
}
func VerifyReleaseFiles(manifestPath, signaturePath string) error {
	b, e := os.ReadFile(manifestPath)
	if e != nil {
		return e
	}
	sig, e := os.ReadFile(signaturePath)
	if e != nil {
		return e
	}
	_, e = verifyManifest(b, sig)
	return e
}
func assetFor(m Manifest) (Asset, error) {
	want := fmt.Sprintf("hotwatcher_%s_linux_%s", m.Tag, runtime.GOARCH)
	for _, a := range m.Assets {
		if a.Name == want && a.OS == "linux" && a.Arch == runtime.GOARCH && a.Kind == "hotwatcher" && a.Size > 0 && a.Size <= 33554432 && len(a.SHA256) == 64 {
			if _, e := hex.DecodeString(a.SHA256); e == nil {
				return a, nil
			}
		}
	}
	return Asset{}, errors.New("exact architecture asset unavailable")
}
func client() *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil || !allowedHost(req.URL.Hostname()) {
			return errors.New("unsafe release redirect")
		}
		return nil
	}}
}
func allowedHost(h string) bool {
	return h == "api.github.com" || h == "github.com" || h == "release-assets.githubusercontent.com" || h == "objects.githubusercontent.com"
}
func fetch(ctx context.Context, u string, max int64) ([]byte, error) {
	parsed, e := url.Parse(u)
	if e != nil || parsed.Scheme != "https" || parsed.User != nil || !allowedHost(parsed.Hostname()) {
		return nil, errors.New("unsafe release URL")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "XKeen-Hot-Watcher-Updater/1")
	r, e := client().Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("release HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("release metadata too large")
	}
	return b, e
}
func fetchReleases(ctx context.Context, u, etag string) ([]byte, string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return nil, "", e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "XKeen-Hot-Watcher-Updater/1")
	if len(etag) > 0 && len(etag) < 256 {
		req.Header.Set("If-None-Match", etag)
	}
	r, e := client().Do(req)
	if e != nil {
		return nil, "", e
	}
	defer r.Body.Close()
	if r.StatusCode == 304 {
		b, e := privateRead(filepath.Join(Root, "releases-cache.json"), 1<<20)
		return b, etag, e
	}
	if r.StatusCode == 404 {
		return []byte("[]"), "", nil
	}
	if r.StatusCode != 200 {
		return nil, "", fmt.Errorf("release HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil {
		return nil, "", e
	}
	if len(b) > 1<<20 {
		return nil, "", errors.New("release list too large")
	}
	newTag := r.Header.Get("ETag")
	if len(newTag) > 256 {
		newTag = ""
	}
	if newTag != "" {
		_ = atomic(filepath.Join(Root, "releases-cache.json"), b, 0600)
	}
	return b, newTag, nil
}
func releaseAsset(r Release, name string) (string, error) {
	for _, a := range r.Assets {
		if a.Name == name && a.ID > 0 {
			parsed, e := url.Parse(a.URL)
			if e != nil || parsed.Scheme != "https" || parsed.Hostname() != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/"+repo+"/releases/download/"+r.TagName+"/"+name {
				return "", errors.New("release asset URL mismatch")
			}
			return a.URL, nil
		}
	}
	return "", errors.New("release asset missing")
}
func check(ctx context.Context, c Config, s *State) (Manifest, Release, Asset, error) {
	var best Manifest
	var chosen Release
	var ba Asset
	if s.Invalid {
		return best, chosen, ba, errors.New("updater state is unsafe or invalid")
	}
	if s.InstalledHash != "" {
		h, e := hashFile(Binary)
		if e != nil || h != s.InstalledHash {
			return best, chosen, ba, errors.New("installed binary hash differs from updater state")
		}
	}
	current := hw.Version
	if s.Installed != "" {
		current = s.Installed
	}
	for page := 1; page <= 3; page++ {
		u := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=30&page=%d", repo, page)
		var b []byte
		var e error
		if page == 1 {
			var newTag string
			b, newTag, e = fetchReleases(ctx, u, s.ETag)
			if e == nil {
				s.ETag = newTag
			}
		} else {
			b, e = fetch(ctx, u, 1<<20)
		}
		if e != nil {
			return best, chosen, ba, e
		}
		releases, parseErr := decodeReleases(b)
		if parseErr != nil {
			return best, chosen, ba, fmt.Errorf("invalid GitHub Releases response: %w", parseErr)
		}
		if len(releases) == 0 {
			break
		}
		for _, r := range releases {
			if r.ID <= 0 || r.Draft || r.Prerelease {
				continue
			}
			v, ok := semver(r.TagName)
			if !ok || !eligible(current, r.TagName, c.Policy) {
				continue
			}
			if c.PinnedVersion != "" && strings.TrimPrefix(r.TagName, "v") != c.PinnedVersion {
				continue
			}
			if old, yes := semver(best.Version); yes && (v[0] < old[0] || v[0] == old[0] && v[1] < old[1] || v[0] == old[0] && v[1] == old[1] && v[2] <= old[2]) {
				continue
			}
			mu, e := releaseAsset(r, "release-manifest.json")
			if e != nil {
				continue
			}
			su, e := releaseAsset(r, "release-manifest.sig")
			if e != nil {
				continue
			}
			mb, e := fetch(ctx, mu, 1<<20)
			if e != nil {
				continue
			}
			sb, e := fetch(ctx, su, 8<<10)
			if e != nil {
				continue
			}
			m, e := verifyManifest(mb, sb)
			if e != nil || m.Tag != r.TagName || m.ReleaseSequence <= s.HighWater {
				continue
			}
			a, e := assetFor(m)
			if e != nil || a.Size > c.MaxDownloadBytes || a.SHA256 == s.BlockedHash {
				continue
			}
			if _, e = releaseAsset(r, a.Name); e != nil {
				continue
			}
			best, chosen, ba = m, r, a
		}
		if len(releases) < 30 {
			break
		}
	}
	if best.Version == "" {
		return best, chosen, ba, ErrNoUpdate
	}
	return best, chosen, ba, nil
}
func download(ctx context.Context, r Release, a Asset, c Config) (string, error) {
	u, e := releaseAsset(r, a.Name)
	if e != nil {
		return "", e
	}
	if e = ensureDir(filepath.Join(Root, "cache")); e != nil {
		return "", e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("User-Agent", "XKeen-Hot-Watcher-Updater/1")
	resp, e := client().Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("asset HTTP %d", resp.StatusCode)
	}
	f, e := os.CreateTemp(filepath.Join(Root, "cache"), ".asset-")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, c.MaxDownloadBytes+1))
	if e == nil && n != a.Size {
		e = errors.New("asset size mismatch")
	}
	if e == nil && hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		e = errors.New("asset hash mismatch")
	}
	if e == nil {
		e = f.Chmod(0700)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return "", e
	}
	p := filepath.Join(Root, "cache", a.SHA256)
	if e = os.Rename(f.Name(), p); e != nil {
		return "", e
	}
	return p, nil
}
func guarded(c Config) error {
	if !c.Enabled {
		return errors.New("updates disabled")
	}
	hotConfig, e := hw.LoadConfig("/opt/etc/hotwatcher/config.json")
	if e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(hotConfig.StateDir, "pending.json")); e == nil {
		return errors.New("subscription transaction pending")
	} else if !os.IsNotExist(e) {
		return e
	}
	if c.RespectHold {
		if _, e := os.Lstat(filepath.Join(hotConfig.StateDir, "hold")); e == nil {
			return errors.New("subscription hold active")
		}
	}
	if _, e := os.Lstat(filepath.Join(Root, "pause")); e == nil {
		return errors.New("software updates paused")
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}

func apply(ctx context.Context, c Config, m Manifest, a Asset, source string, s *State) error {
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	if _, e = os.Lstat(journalPath()); e == nil {
		return errors.New("recover pending update first")
	}
	latestConfig, e := loadConfig()
	if e != nil {
		return e
	}
	if c.Mode == "auto" && latestConfig.Mode != "auto" {
		return errors.New("automatic installation was disabled during download")
	}
	c = latestConfig
	latestState := readState()
	if latestState.Invalid {
		return errors.New("updater state invalid")
	}
	current := hw.Version
	if latestState.Installed != "" {
		current = latestState.Installed
	}
	if !eligible(current, m.Version, c.Policy) || m.ReleaseSequence <= latestState.HighWater || latestState.BlockedHash == a.SHA256 {
		return errors.New("candidate no longer eligible")
	}
	*s = latestState
	if e = guarded(c); e != nil {
		return e
	}
	if h, e := hashFile(source); e != nil || h != a.SHA256 {
		return errors.New("verified staging asset changed")
	}
	infoBytes, e := exec.CommandContext(ctx, source, "version", "--json").Output()
	if e != nil {
		return fmt.Errorf("candidate build info unavailable: %w", e)
	}
	var info struct {
		Version         string `json:"version"`
		Commit          string `json:"commit"`
		OS              string `json:"os"`
		Arch            string `json:"arch"`
		Dirty           bool   `json:"dirty"`
		UpdaterProtocol int    `json:"updater_protocol"`
		BuildTime       string `json:"build_time_utc"`
		GoVersion       string `json:"go_version"`
		ConfigSchema    int    `json:"config_schema"`
		StateSchema     int    `json:"state_schema"`
	}
	if e = strictJSON(infoBytes, &info); e != nil {
		return e
	}
	if info.Version != m.Version || info.Commit != m.Commit || info.OS != "linux" || info.Arch != runtime.GOARCH || info.Dirty || info.UpdaterProtocol < protocol {
		return errors.New("candidate build info does not match signed manifest")
	}
	if _, e := exec.CommandContext(ctx, Binary, "update-preflight").CombinedOutput(); e != nil {
		return fmt.Errorf("current preflight: %w", e)
	}
	if _, e := exec.CommandContext(ctx, source, "update-preflight").CombinedOutput(); e != nil {
		return fmt.Errorf("candidate preflight: %w", e)
	}
	xrayBefore, e := xrayIdentities()
	if e != nil {
		return e
	}
	protectedBefore, e := protectedHashes()
	if e != nil {
		return e
	}
	pinBefore, e := selectedRuntime()
	if e != nil {
		return e
	}
	oldHash, e := hashFile(Binary)
	if e != nil {
		return e
	}
	if e = ensureDir(filepath.Join(Root, "versions")); e != nil {
		return e
	}
	prev := filepath.Join(Root, "versions", oldHash)
	if e = copyAtomic(Binary, prev, 0700); e != nil {
		return e
	}
	idBytes := make([]byte, 16)
	if _, e = rand.Read(idBytes); e != nil {
		return e
	}
	j := Journal{ID: hex.EncodeToString(idBytes), Phase: "staged", Version: m.Version, Hash: a.SHA256, PreviousHash: oldHash, PreviousPath: prev, PreviousState: *s}
	_, e = os.Lstat("/opt/etc/hotwatcher/enabled")
	j.Enabled = e == nil
	if e = save(journalPath(), j); e != nil {
		return e
	}
	if e = save(maintenancePath(), map[string]string{"id": j.ID}); e != nil {
		return e
	}
	if j.Enabled {
		j.Phase = "quiescing"
		_ = save(journalPath(), j)
		stop := exec.CommandContext(ctx, "/opt/etc/init.d/S99hotwatcher", "stop")
		stop.Env = append(os.Environ(), fmt.Sprintf("HOTWATCHER_SHUTDOWN_TIMEOUT_SECONDS=%d", c.ShutdownTimeoutSeconds))
		if out, e := stop.CombinedOutput(); e != nil {
			return rollback(j, s, fmt.Errorf("watcher stop deferred: %s: %w", string(out), e))
		}
	}
	if e = guarded(c); e != nil {
		return rollback(j, s, e)
	}
	j.Phase = "stopped"
	if e = save(journalPath(), j); e != nil {
		return rollback(j, s, e)
	}
	if e = copyAtomic(source, Binary, 0700); e != nil {
		return rollback(j, s, e)
	}
	j.Phase = "installed"
	if e = save(journalPath(), j); e != nil {
		return rollback(j, s, e)
	}
	if j.Enabled {
		j.Phase = "validating"
		_ = save(journalPath(), j)
		vctx, cancel := context.WithTimeout(ctx, time.Duration(c.ReadinessTimeoutSeconds)*time.Second)
		defer cancel()
		proc := exec.CommandContext(vctx, Binary, "update-validation", j.ID)
		if e = proc.Start(); e != nil {
			return rollback(j, s, e)
		}
		ready := false
		for !ready {
			select {
			case <-vctx.Done():
				_ = proc.Process.Signal(syscall.SIGTERM)
				_ = proc.Wait()
				return rollback(j, s, errors.New("validation timeout"))
			case <-time.After(200 * time.Millisecond):
				ready = readHeartbeat(filepath.Join(Root, "heartbeat-"+j.ID+".json"), j.ID, m.Version, proc.Process.Pid)
			}
		}
		_ = proc.Process.Signal(syscall.SIGTERM)
		if e = proc.Wait(); e != nil {
			return rollback(j, s, fmt.Errorf("candidate validation exited early: %w", e))
		}
	}
	xrayAfter, e := xrayIdentities()
	if e != nil || !slices.Equal(xrayBefore, xrayAfter) {
		return rollback(j, s, errors.New("external Xray process changed during software update"))
	}
	protectedAfter, e := protectedHashes()
	if e != nil {
		return rollback(j, s, e)
	}
	for p, old := range protectedBefore {
		if protectedAfter[p] != old {
			return rollback(j, s, errors.New("protected configuration or subscription state changed during software update"))
		}
	}
	pinAfter, e := selectedRuntime()
	if e != nil || pinAfter != pinBefore {
		return rollback(j, s, errors.New("selected Xray runtime pin changed during software update"))
	}
	if j.Enabled {
		j.Phase = "restarting"
		if e = save(journalPath(), j); e != nil {
			return rollback(j, s, e)
		}
		start := exec.Command("/opt/etc/init.d/S99hotwatcher", "start")
		start.Env = append(os.Environ(), "HOTWATCHER_UPDATE_ID="+j.ID)
		if out, er := start.CombinedOutput(); er != nil {
			return rollback(j, s, fmt.Errorf("daemon start failed: %s: %w", string(out), er))
		}
		pidBytes, er := privateRead("/opt/var/run/hotwatcher.pid", 64)
		if er != nil {
			return rollback(j, s, errors.New("daemon PID file unavailable"))
		}
		daemonPID, er := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if er != nil || daemonPID < 1 {
			return rollback(j, s, errors.New("invalid daemon PID file"))
		}
		deadline := time.Now().Add(time.Duration(c.ReadinessTimeoutSeconds) * time.Second)
		for {
			if readHeartbeat(filepath.Join(Root, "daemon-ready-"+j.ID+".json"), j.ID, m.Version, daemonPID) {
				break
			}
			if time.Now().After(deadline) {
				return rollback(j, s, errors.New("normal daemon readiness timeout"))
			}
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(2 * time.Second)
		status, er := exec.Command("/opt/etc/init.d/S99hotwatcher", "status").CombinedOutput()
		if er != nil || !bytes.Contains(status, []byte("Hot Watcher PID:")) {
			return rollback(j, s, errors.New("normal daemon exited after readiness"))
		}
	}
	xrayFinal, e := xrayIdentities()
	if e != nil || !slices.Equal(xrayFinal, xrayBefore) {
		return rollback(j, s, errors.New("external Xray process changed before commit"))
	}
	protectedFinal, e := protectedHashes()
	if e != nil {
		return rollback(j, s, e)
	}
	for p, old := range protectedBefore {
		if protectedFinal[p] != old {
			return rollback(j, s, errors.New("protected files changed before commit"))
		}
	}
	pinFinal, e := selectedRuntime()
	if e != nil || pinFinal != pinBefore {
		return rollback(j, s, errors.New("selected Xray runtime pin changed before commit"))
	}
	nextState := *s
	nextState.Previous = s.Installed
	nextState.Installed = m.Version
	nextState.InstalledHash = a.SHA256
	nextState.HighWater = m.ReleaseSequence
	nextState.BlockedHash = ""
	nextState.Verified = true
	if e = save(statePath(), &nextState); e != nil {
		return rollback(j, s, e)
	}
	committed := j
	committed.Phase = "committed"
	if e = save(journalPath(), committed); e != nil {
		return rollback(j, s, e)
	}
	*s = nextState
	recordResult("installed", nextState.Previous, nextState.Installed)
	_ = os.Remove(maintenancePath())
	_ = os.Remove(journalPath())
	_ = os.Remove(source)
	_ = cleanupVersions(prev, c.RetainVersions)
	return nil
}
func cleanupVersions(latest string, retain int) error {
	dir := filepath.Join(Root, "versions")
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	type item struct {
		path     string
		modified time.Time
	}
	all := []item{}
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		if _, e := hex.DecodeString(entry.Name()); e != nil {
			continue
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() {
			continue
		}
		all = append(all, item{filepath.Join(dir, entry.Name()), info.ModTime()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].modified.After(all[j].modified) })
	kept := 1
	for _, it := range all {
		if it.path == latest {
			continue
		}
		if kept < retain-1 {
			kept++
			continue
		}
		if e := os.Remove(it.path); e != nil {
			return e
		}
	}
	return nil
}
func copyAtomic(src, dst string, mode os.FileMode) error {
	s, e := os.Lstat(src)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return errors.New("unsafe source binary")
	}
	f, e := os.Open(src)
	if e != nil {
		return e
	}
	defer f.Close()
	tmp, e := os.CreateTemp(filepath.Dir(dst), ".binary-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if e = tmp.Chmod(mode); e == nil {
		_, e = io.Copy(tmp, f)
	}
	if e == nil {
		e = tmp.Sync()
	}
	ce := tmp.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if s, e := os.Lstat(dst); e == nil && !s.Mode().IsRegular() {
		return errors.New("unsafe destination binary")
	}
	if e = os.Rename(tmp.Name(), dst); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(dst))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func rollback(j Journal, s *State, reason error) error {
	if j.Phase == "restarting" {
		_ = save(maintenancePath(), map[string]string{"id": j.ID})
		if out, e := exec.Command("/opt/etc/init.d/S99hotwatcher", "stop").CombinedOutput(); e != nil {
			return fmt.Errorf("new daemon could not stop safely: %s: %w", string(out), reason)
		}
	}
	j.Phase = "rolling_back"
	_ = save(journalPath(), j)
	if j.PreviousPath != "" {
		if h, e := hashFile(j.PreviousPath); e != nil || h != j.PreviousHash {
			return fmt.Errorf("rollback copy invalid; manual intervention: %w", reason)
		}
		if e := copyAtomic(j.PreviousPath, Binary, 0700); e != nil {
			return fmt.Errorf("rollback failed: %w", e)
		}
	}
	s.BlockedHash = j.Hash
	s.Deferred = reason.Error()
	_ = save(statePath(), s)
	recordResult("rolled_back", j.Version, s.Installed)
	_ = os.Remove(maintenancePath())
	if j.Enabled {
		_, _ = exec.Command("/opt/etc/init.d/S99hotwatcher", "start").CombinedOutput()
	}
	j.Phase = "rolled_back"
	_ = save(journalPath(), j)
	_ = os.Remove(journalPath())
	return reason
}
func Recover() error {
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := readJournal()
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	s := readState()
	if s.Invalid {
		return errors.New("updater state invalid; manual intervention required before recovery")
	}
	if j.Phase == "committed" {
		_ = os.Remove(maintenancePath())
		_ = os.Remove(journalPath())
		return nil
	}
	if j.Phase != "committed" {
		s = j.PreviousState
	}
	e = rollback(j, &s, errors.New("interrupted software update"))
	if _, statErr := os.Lstat(journalPath()); os.IsNotExist(statErr) {
		return nil
	}
	return e
}
func ValidationHeartbeat(id string) error {
	if len(id) != 32 {
		return errors.New("invalid transaction ID")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return e
	}
	b, e := privateRead(maintenancePath(), 4096)
	if e != nil || !bytes.Contains(b, []byte(id)) {
		return errors.New("maintenance transaction mismatch")
	}
	p := filepath.Join(Root, "heartbeat-"+id+".json")
	if e = save(p, map[string]any{"id": id, "version": hw.Version, "pid": os.Getpid(), "ready": true}); e != nil {
		return e
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(ch)
	<-ch
	return nil
}
func DaemonReady(id string) error {
	if len(id) != 32 {
		return errors.New("invalid update ID")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return e
	}
	return save(filepath.Join(Root, "daemon-ready-"+id+".json"), map[string]any{"id": id, "pid": os.Getpid(), "ready": true, "version": hw.Version})
}
