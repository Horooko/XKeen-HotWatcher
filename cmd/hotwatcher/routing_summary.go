package main

import (
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"path/filepath"
)

// routingSummary reports destinations for transparent LAN inbounds without
// exporting domain lists, server addresses or subscription credentials.
func routingSummary(configDir string) []string {
	path := filepath.Join(configDir, "05_routing.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return []string{"Правила 05_routing.json недоступны"}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return []string{"Правила 05_routing.json не читаются"}
	}
	var config struct {
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				BalancerTag string   `json:"balancerTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if hw.DecodeXrayJSONC(b, &config) != nil || len(config.Routing.Rules) > 2048 {
		return []string{"Правила 05_routing.json не удалось разобрать"}
	}
	balancer, static, direct, other := 0, 0, 0, 0
	for _, rule := range config.Routing.Rules {
		lan := len(rule.InboundTag) == 0
		for _, tag := range rule.InboundTag {
			if tag == "redirect" || tag == "tproxy" {
				lan = true
			}
		}
		if !lan {
			continue
		}
		switch {
		case rule.BalancerTag == "proxy":
			balancer++
		case rule.OutboundTag == "vless-reality":
			static++
		case rule.OutboundTag == "direct" || rule.OutboundTag == "block":
			direct++
		default:
			other++
		}
	}
	return []string{fmt.Sprintf("Правила для redirect/tproxy: balancer proxy=%d; статический vless-reality=%d; direct/block=%d; другие=%d", balancer, static, direct, other), "Статический outbound не следует за выбором ключа в Hot Watcher."}
}
