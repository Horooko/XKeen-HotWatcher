package hotwatcher

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// withLiveProbe creates a loopback-only, authenticated HTTP inbound in the
// running Xray. Its appended routing rule targets this key, never the balancer.
// A candidate not yet installed gets a temporary outbound whose tag cannot
// match Hot Watcher's production balancer selector.
func (x Xray) withLiveProbe(n Node, use func(*url.URL, *url.URL) error) (resultErr error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	inboundTag := "hw-live-in-" + id
	controlInboundTag := "hw-live-control-in-" + id
	ruleTag := "hw-live-rule-" + id
	controlRuleTag := "hw-live-control-rule-" + id
	outboundTag := "hw-live-out-" + id
	controlOutboundTag := "hw-live-block-" + id
	apiArgs := func(command string, extra ...string) []string {
		args := []string{"api", command, "--server=" + x.C.APIAddress, fmt.Sprintf("--timeout=%d", x.C.APITimeoutSeconds)}
		return append(args, extra...)
	}
	tags, err := x.List()
	if err != nil {
		return fmt.Errorf("основной Xray недоступен: %w", err)
	}
	target := n.Tag
	addedOutbound := false
	addedRule := false
	addedInbound := false
	defer func() {
		var cleanupErr error
		cleanup := func(command, label string, tags ...string) {
			for _, tag := range tags {
				if _, err := x.api(command, tag); err != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%s %s: %w", label, tag, err))
				}
			}
		}
		if addedInbound {
			cleanup("rmi", "удаление проверочного входа", inboundTag, controlInboundTag)
		}
		if addedRule {
			cleanup("rmrules", "удаление проверочного маршрута", ruleTag, controlRuleTag)
		}
		if addedOutbound {
			cleanup("rmo", "удаление проверочного выхода", controlOutboundTag)
			if target == outboundTag {
				cleanup("rmo", "удаление проверочного выхода", outboundTag)
			}
		}
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	outbounds := []any{map[string]any{"tag": controlOutboundTag, "protocol": "blackhole"}}
	if !tags[n.Tag] {
		// JSON round-trip copies nested outbound settings before changing its tag.
		var outbound map[string]any
		if err := json.Unmarshal(encode(n.Outbound), &outbound); err != nil || outbound == nil {
			return errors.New("неверная конфигурация проверяемого ключа")
		}
		outbound["tag"] = outboundTag
		outbounds = append(outbounds, outbound)
		target = outboundTag
	}
	addedOutbound = true
	if _, err := x.run(encode(map[string]any{"outbounds": outbounds}), apiArgs("ado", "stdin:")...); err != nil {
		return fmt.Errorf("не удалось добавить проверочный выход в основной Xray: %w", err)
	}
	// -append is mandatory: omitting it replaces every production routing rule.
	rule := map[string]any{"type": "field", "ruleTag": ruleTag, "inboundTag": []string{inboundTag}, "outboundTag": target}
	controlRule := map[string]any{"type": "field", "ruleTag": controlRuleTag, "inboundTag": []string{controlInboundTag}, "outboundTag": controlOutboundTag}
	addedRule = true
	if _, err := x.run(encode(map[string]any{"routing": map[string]any{"rules": []any{rule, controlRule}}}), apiArgs("adrules", "-append", "stdin:")...); err != nil {
		return fmt.Errorf("не удалось добавить проверочный маршрут: %w", err)
	}
	port, err := freeLiveProbePort()
	if err != nil {
		return errors.New("нет свободного локального порта для проверки")
	}
	controlPort, err := freeLiveProbePort()
	if err != nil || controlPort == port {
		return errors.New("нет второго локального порта для проверки маршрута")
	}
	username, password := "hw-"+id[:16], hex.EncodeToString(secret[:])
	inbound := map[string]any{"tag": inboundTag, "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{"accounts": []any{map[string]string{"user": username, "pass": password}}}}
	controlInbound := map[string]any{"tag": controlInboundTag, "listen": "127.0.0.1", "port": controlPort, "protocol": "http", "settings": map[string]any{"accounts": []any{map[string]string{"user": username, "pass": password}}}}
	addedInbound = true
	if _, err := x.run(encode(map[string]any{"inbounds": []any{inbound, controlInbound}}), apiArgs("adi", "stdin:")...); err != nil {
		return fmt.Errorf("не удалось добавить проверочный вход: %w", err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	controlAddress := fmt.Sprintf("127.0.0.1:%d", controlPort)
	if !waitLiveProbePort(address) || !waitLiveProbePort(controlAddress) {
		return errors.New("проверочные входы основного Xray не открыли локальные порты")
	}
	return use(&url.URL{Scheme: "http", Host: address, User: url.UserPassword(username, password)}, &url.URL{Scheme: "http", Host: controlAddress, User: url.UserPassword(username, password)})
}

func freeLiveProbePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

func waitLiveProbePort(address string) bool {
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// A successful response through a deliberately blocked route means an earlier
// production rule intercepted the probe. Never count that as a key success.
func controlRouteOpens(client *http.Client, request *http.Request) bool {
	response, err := client.Do(request.Clone(request.Context()))
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode >= 200 && response.StatusCode < 300
}
