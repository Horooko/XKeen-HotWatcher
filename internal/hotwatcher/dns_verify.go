package hotwatcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type DNSRouteProbe struct {
	Checked   bool     `json:"checked"`
	Success   bool     `json:"success"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type DNSVerification struct {
	ConfigFile    string        `json:"config_file"`
	Managed       bool          `json:"managed"`
	ProductionAPI bool          `json:"production_api_reachable"`
	Direct        DNSRouteProbe `json:"direct"`
	SelectedVLESS DNSRouteProbe `json:"selected_vless"`
	SelectedTag   string        `json:"selected_tag,omitempty"`
	Scope         string        `json:"scope"`
}

func dnsProbeConfig(dns map[string]json.RawMessage, outbound map[string]any, port int) ([]byte, error) {
	var tag string
	if raw := dns["tag"]; len(raw) != 0 && json.Unmarshal(raw, &tag) != nil {
		return nil, errors.New("неверный tag в DNS-конфигурации")
	}
	egress, ok := outbound["tag"].(string)
	if !ok || egress == "" || egress == "hw-dns-out" || egress == "hw-dns-in" {
		return nil, errors.New("неверный тег исходящего маршрута DNS-пробы")
	}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"hw-dns-in"}, "outboundTag": "hw-dns-out"}}
	if tag != "" {
		if tag == "hw-dns-in" {
			return nil, errors.New("DNS tag конфликтует с диагностическим входом")
		}
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tag}, "outboundTag": egress})
	}
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"dns":       dns,
		"inbounds":  []any{map[string]any{"tag": "hw-dns-in", "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door", "settings": map[string]any{"address": "1.1.1.1", "port": 53, "network": "udp"}}},
		"outbounds": []any{outbound, map[string]any{"tag": "hw-dns-out", "protocol": "dns", "settings": map[string]any{}}},
		"routing":   map[string]any{"rules": rules},
	}
	return encode(config), nil
}

func (e *Engine) probeDNSRoute(dns map[string]json.RawMessage, outbound map[string]any) (time.Duration, error) {
	if err := privateDir(e.C.StateDir); err != nil {
		return 0, err
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return 0, errors.New("не удалось выделить локальный порт для DNS-пробы")
	}
	port := packet.LocalAddr().(*net.UDPAddr).Port
	packet.Close()
	config, err := dnsProbeConfig(dns, outbound, port)
	if err != nil {
		return 0, err
	}
	dir, err := os.MkdirTemp(e.C.StateDir, "dns-probe-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		return 0, err
	}
	if _, err := (Xray{C: e.C}).run(nil, "run", "-test", "-config", path); err != nil {
		return 0, errors.New("установленный Xray отклонил изолированную DNS-пробу")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.C.ProbeTimeoutSeconds+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.C.XrayBinary, "run", "-config", path)
	cmd.Env = append(isolatedEnv(), "XRAY_LOCATION_ASSET="+e.C.AssetDir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return 0, errors.New("не удалось запустить изолированный Xray для DNS-пробы")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	query, id, err := dnsQuestion()
	if err != nil {
		return 0, err
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	started := time.Now()
	for ctx.Err() == nil {
		select {
		case <-done:
			return 0, errors.New("изолированный Xray завершился до ответа DNS")
		default:
		}
		conn, err := net.DialTimeout("udp4", address, time.Second)
		if err != nil {
			return 0, errors.New("не удалось отправить локальный DNS-запрос")
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, writeErr := conn.Write(query)
		answer := make([]byte, 4096)
		n, readErr := conn.Read(answer)
		conn.Close()
		if writeErr == nil && readErr == nil && validDNSAnswer(answer[:n], id) {
			return time.Since(started), nil
		}
	}
	return 0, errors.New("Xray не вернул DNS-ответ через этот маршрут")
}

func (e *Engine) DNSVerify() (DNSVerification, error) {
	result := DNSVerification{Scope: "изолированная копия DNS-настройки; API подтверждает работу основного Xray, но не его загруженную DNS-версию"}
	src, err := findDNSSource(e.C)
	if err != nil {
		return result, err
	}
	if src.created {
		return result, errors.New("DNS-фрагмент Xray отсутствует")
	}
	result.ConfigFile = src.path
	status, err := e.DNSStatus()
	if err != nil {
		return result, err
	}
	result.Managed = status.Managed
	_, apiErr := e.R.List()
	result.ProductionAPI = apiErr == nil
	result.Direct.Checked = true
	direct := map[string]any{"tag": "hw-dns-direct", "protocol": "freedom", "settings": map[string]any{}}
	if latency, err := e.probeDNSRoute(src.dns, direct); err == nil {
		ms := float64(latency.Microseconds()) / 1000
		result.Direct.Success, result.Direct.LatencyMS = true, &ms
	} else {
		result.Direct.Reason = err.Error()
	}
	s, err := e.state()
	if err != nil {
		return result, err
	}
	if s == nil {
		result.SelectedVLESS.Reason = "ключи ещё не приняты Hot Watcher"
		return result, nil
	}
	node, ok := findNode(s.Active, s.Selected)
	if !ok {
		result.SelectedVLESS.Reason = "выбранный ключ отсутствует в сохранённом списке"
		return result, nil
	}
	result.SelectedTag = node.Tag
	result.SelectedVLESS.Checked = true
	if latency, err := e.probeDNSRoute(src.dns, node.Outbound); err == nil {
		ms := float64(latency.Microseconds()) / 1000
		result.SelectedVLESS.Success, result.SelectedVLESS.LatencyMS = true, &ms
	} else {
		result.SelectedVLESS.Reason = err.Error()
	}
	return result, nil
}
