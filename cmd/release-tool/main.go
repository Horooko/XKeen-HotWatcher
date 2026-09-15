package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	u "local/xkeen-hot-watcher/internal/updater"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func die(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func main() {
	if len(os.Args) < 2 {
		die(fmt.Errorf("use keygen|manifest|sign"))
	}
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 4 {
			die(fmt.Errorf("keygen PRIVATE_SEED_PATH PUBLIC_KEY_PATH"))
		}
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		die(e)
		die(os.WriteFile(os.Args[2], []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0600))
		die(os.WriteFile(os.Args[3], []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644))
	case "manifest":
		if len(os.Args) != 7 {
			die(fmt.Errorf("manifest TAG COMMIT SEQUENCE ARM64 AMD64"))
		}
		tag := os.Args[2]
		seq, e := strconv.ParseUint(os.Args[4], 10, 64)
		die(e)
		if !strings.HasPrefix(tag, "v") {
			die(fmt.Errorf("tag needs v prefix"))
		}
		m := u.Manifest{SchemaVersion: 1, Application: "xkeen-hotwatcher", Repository: "Horooko/XKeen-HotWatcher", RepositoryID: 1371012653, Version: strings.TrimPrefix(tag, "v"), Tag: tag, Commit: os.Args[3], ReleaseSequence: seq, Channel: "stable", PublishedAt: time.Now().UTC(), MinimumUpdaterProtocol: 1, ConfigSchema: 1, StateSchema: 1}
		for i, p := range os.Args[5:] {
			arch := []string{"arm64", "amd64"}[i]
			a, e := asset(p, arch)
			die(e)
			m.Assets = append(m.Assets, a)
		}
		b, e := json.MarshalIndent(m, "", "  ")
		die(e)
		die(os.WriteFile("release-manifest.json", append(b, '\n'), 0644))
	case "sign":
		if len(os.Args) != 5 {
			die(fmt.Errorf("sign SEED MANIFEST SIGNATURE"))
		}
		seed, e := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Args[2]))
		die(e)
		if len(seed) != ed25519.SeedSize {
			die(fmt.Errorf("invalid seed"))
		}
		b, e := os.ReadFile(os.Args[3])
		die(e)
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte("XKeen-HotWatcher release manifest v1\x00"), b...))
		v := u.Signature{Algorithm: "Ed25519", KeyID: "bootstrap-v1", Signature: base64.StdEncoding.EncodeToString(sig)}
		out, e := json.MarshalIndent(v, "", "  ")
		die(e)
		die(os.WriteFile(os.Args[4], append(out, '\n'), 0644))
	case "sign-env":
		if len(os.Args) != 4 {
			die(fmt.Errorf("sign-env MANIFEST SIGNATURE"))
		}
		seed, e := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("UPDATE_SIGNING_SEED")))
		die(e)
		if len(seed) != ed25519.SeedSize {
			die(fmt.Errorf("invalid signing environment"))
		}
		b, e := os.ReadFile(os.Args[2])
		die(e)
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte("XKeen-HotWatcher release manifest v1\x00"), b...))
		v := u.Signature{Algorithm: "Ed25519", KeyID: "bootstrap-v1", Signature: base64.StdEncoding.EncodeToString(sig)}
		out, e := json.MarshalIndent(v, "", "  ")
		die(e)
		die(os.WriteFile(os.Args[3], append(out, '\n'), 0644))
	case "verify":
		if len(os.Args) != 4 {
			die(fmt.Errorf("verify MANIFEST SIGNATURE"))
		}
		die(u.VerifyReleaseFiles(os.Args[2], os.Args[3]))
	default:
		die(fmt.Errorf("unknown release tool command"))
	}
}
func asset(p, arch string) (u.Asset, error) {
	f, e := os.Open(p)
	if e != nil {
		return u.Asset{}, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil {
		return u.Asset{}, e
	}
	return u.Asset{Name: filepath.Base(p), OS: runtime.GOOS, Arch: arch, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Kind: "hotwatcher"}, nil
}
