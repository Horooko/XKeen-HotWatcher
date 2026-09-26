package hotwatcher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A second Xray has exhausted memory on 1 GiB routers. Keep enough memory
// available for the production process and the router before starting one.
const (
	auxStartAvailable = 384 << 20
	auxStopAvailable  = 128 << 20
	auxMaxRSS         = 192 << 20
)

var errAuxiliaryMemory = errors.New("временный Xray остановлен из-за нехватки памяти; основной Xray не перезапускался")

func procKilobytes(data []byte, key string) (int64, error) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) == 3 && fields[0] == key && fields[2] == "kB" {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && value >= 0 {
				return value * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("%s unavailable in procfs", key)
}

func availableMemory() (int64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	return procKilobytes(data, "MemAvailable:")
}

func processRSS(pid int) (int64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	return procKilobytes(data, "VmRSS:")
}

type auxiliaryXray struct {
	cmd       *exec.Cmd
	done      chan struct{}
	budgetErr chan error
	waitErr   error
}

func startAuxiliaryXray(cmd *exec.Cmd) (*auxiliaryXray, error) {
	available, err := availableMemory()
	if err != nil {
		return nil, errors.New("не удалось проверить свободную память для временного Xray")
	}
	if available < auxStartAvailable {
		return nil, fmt.Errorf("%w: доступно менее 384 МиБ", errAuxiliaryMemory)
	}
	// GOMEMLIMIT is a soft Go-runtime limit, so the process is monitored as well.
	cmd.Env = append(cmd.Env, "GOMEMLIMIT=128MiB", "GOGC=50")
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &auxiliaryXray{cmd: cmd, done: make(chan struct{}), budgetErr: make(chan error, 1)}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	go p.watchMemory()
	return p, nil
}

func (p *auxiliaryXray) watchMemory() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			available, availableErr := availableMemory()
			rss, rssErr := processRSS(p.cmd.Process.Pid)
			if os.IsNotExist(rssErr) {
				return // The process exited while procfs was read.
			}
			if availableErr != nil || rssErr != nil || available < auxStopAvailable || rss > auxMaxRSS {
				p.budgetErr <- errAuxiliaryMemory
				_ = p.cmd.Process.Kill()
				return
			}
		}
	}
}

func (p *auxiliaryXray) result(fallback string) error {
	<-p.done
	select {
	case err := <-p.budgetErr:
		return err
	default:
	}
	if p.waitErr != nil {
		return errors.New(fallback)
	}
	return nil
}

func (p *auxiliaryXray) unexpectedExit(fallback string) error {
	if err := p.result(fallback); err != nil {
		return err
	}
	return errors.New(fallback)
}

func (p *auxiliaryXray) stop() {
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}
