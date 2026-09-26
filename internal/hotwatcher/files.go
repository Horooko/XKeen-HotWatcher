package hotwatcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ErrBusy = errors.New("another Hot Watcher operation is in progress")

type LockInfo struct {
	Busy      bool      `json:"busy"`
	PID       int       `json:"pid,omitempty"`
	Operation string    `json:"operation,omitempty"`
	Since     time.Time `json:"since,omitempty"`
}

func lockOperation() string {
	allowed := map[string]bool{"sync": true, "hard-sync": true, "adopt": true, "check-key": true, "select": true, "recover": true, "abort": true, "recovery": true, "dns": true, "daemon": true, "stop": true, "start": true}
	for _, arg := range os.Args[1:] {
		if allowed[arg] {
			return arg
		}
	}
	return "hotwatcher"
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func encode(v any) []byte    { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
func regular(path string) error {
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return errors.New("not a regular file (symlinks are refused)")
	}
	return nil
}
func readPrivate(path string, limit int64) ([]byte, error) {
	if e := regular(path); e != nil {
		return nil, e
	}
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if s.Mode().Perm()&0077 != 0 {
		return nil, errors.New("file permissions must be 0600 or 0400")
	}
	return readLimited(path, limit)
}
func readLimited(path string, limit int64) ([]byte, error) {
	if e := regular(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file size limit exceeded")
	}
	return b, nil
}
func privateDir(path string) error {
	if s, e := os.Lstat(path); e == nil {
		if !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("state directory is not a real directory")
		}
		if s.Mode().Perm()&0077 != 0 {
			return errors.New("state directory permissions must be 0700")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	return os.MkdirAll(path, 0700)
}

// Atomic file replacement on the same filesystem. A directory fsync follows rename.
// JSON backups/journals belong outside Xray's config directory.
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if s, e := os.Lstat(path); e == nil && !s.Mode().IsRegular() {
		return errors.New("refusing to replace non-regular file")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".hw-tmp-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
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
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func removeSync(path string) error {
	e := os.Remove(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	f, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func lock(dir string) (func(), error) {
	if e := privateDir(dir); e != nil {
		return nil, e
	}
	p := filepath.Join(dir, "lock")
	if s, e := os.Lstat(p); e == nil && !s.Mode().IsRegular() {
		return nil, errors.New("unsafe lock path")
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		if errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("Hot Watcher lock failed: %w", e)
	}
	info := LockInfo{Busy: true, PID: os.Getpid(), Operation: lockOperation(), Since: time.Now().UTC()}
	if e = f.Truncate(0); e == nil {
		_, e = f.Seek(0, io.SeekStart)
	}
	if e == nil {
		e = json.NewEncoder(f).Encode(info)
	}
	if e == nil {
		e = f.Sync()
	}
	if e != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, e
	}
	return func() {
		_ = f.Truncate(0)
		_, _ = f.Seek(0, io.SeekStart)
		_ = f.Sync()
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// LockDaemon is held for the entire daemon lifetime. The operation lock above
// is intentionally short lived and cannot prevent two background daemons.
func LockDaemon(dir string) (func(), error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "daemon.lock")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("unsafe daemon lock path")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another Hot Watcher daemon is already running")
		}
		return nil, fmt.Errorf("Hot Watcher daemon lock failed: %w", err)
	}
	other, err := otherDaemonPIDs()
	if err != nil || len(other) > 0 {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("another Hot Watcher daemon is already running (PID %d)", other[0])
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// Older releases did not hold daemon.lock. Detect their orphaned processes
// before the new daemon can start and leave their old Web UI on port 8787.
func otherDaemonPIDs() ([]int, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		exe, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil || (exe != self && exe != self+" (deleted)") {
			continue
		}
		args, err := os.ReadFile(filepath.Join(base, "cmdline"))
		if err != nil {
			continue // The process may have exited during the scan.
		}
		for _, arg := range strings.Split(string(args), "\x00") {
			if arg == "daemon" {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids, nil
}

// CurrentLock reports whether a process really holds the kernel lock. A
// leftover lock file after a crash is never treated as a busy operation.
func CurrentLock(c Config) (LockInfo, error) {
	p := filepath.Join(c.StateDir, "lock")
	if err := regular(p); os.IsNotExist(err) {
		return LockInfo{}, nil
	} else if err != nil {
		return LockInfo{}, err
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return LockInfo{}, err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return LockInfo{}, nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		return LockInfo{}, err
	}
	var info LockInfo
	if decodeErr := json.NewDecoder(io.LimitReader(f, 4096)).Decode(&info); decodeErr != nil {
		return LockInfo{Busy: true}, nil
	}
	info.Busy = true
	return info, nil
}
func logEvent(dir, event string, fields map[string]any) error {
	p := filepath.Join(dir, "events.jsonl")
	if s, e := os.Lstat(p); e == nil {
		if !s.Mode().IsRegular() {
			return errors.New("unsafe log path")
		}
		if s.Size() > 1024*1024 {
			if e = os.Rename(p, p+".1"); e != nil {
				return e
			}
		}
	}
	m := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "event": event}
	// Callers use only fixed event names, counts, content hashes and owned tags.
	for k, v := range fields {
		m[k] = v
	}
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(b, '\n'))
	return e
}
func outputFile(c Config) string { return filepath.Join(c.ConfigDir, c.GeneratedFile) }
func mustJSON(path string, v any) error {
	b, e := readPrivate(path, 16*1024*1024)
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, v); e != nil {
		return fmt.Errorf("invalid local JSON in %s", filepath.Base(path))
	}
	return nil
}
