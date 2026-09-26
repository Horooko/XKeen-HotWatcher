package main

import (
	"errors"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"os"
	"path/filepath"
)

func dnsCommand(c hw.Config, engine *hw.Engine, args []string) error {
	if len(args) == 1 && args[0] == "status" {
		status, err := engine.DNSStatus()
		if err == nil {
			printJSON(status)
		}
		return err
	}
	if len(args) == 1 && args[0] == "test" {
		fmt.Println("Проверяю доверенные DoH-серверы с маршрута самого роутера…")
		results, err := engine.DNSTest()
		if err == nil {
			printJSON(results)
		}
		return err
	}
	if len(args) == 1 && args[0] == "verify" {
		fmt.Println("Проверяю DNS через временный Xray с учётом режима маршрутизации…")
		result, err := engine.DNSVerify()
		if result.ConfigFile != "" {
			printJSON(result)
		}
		if err == nil && !result.Direct.Success && !result.SelectedVLESS.Success {
			return errors.New("DNS не ответил ни через прямой, ни через выбранный VLESS-маршрут")
		}
		return err
	}
	if len(args) == 2 && args[0] == "auto" && (args[1] == "on" || args[1] == "off") {
		return hw.WithLock(c, func() error {
			if args[1] == "off" {
				if err := engine.DNSAutoOff(); err != nil {
					return err
				}
				fmt.Println("Исходная DNS-конфигурация восстановлена. Проверьте xkeen -xtest и вне игры выполните xkeen -restart.")
				return nil
			}
			if _, err := os.Lstat(filepath.Join(c.StateDir, "pending.json")); err == nil {
				return errors.New("сначала завершите операцию с ключами: hotwatcher recover или abort")
			} else if !os.IsNotExist(err) {
				return err
			}
			fmt.Println("Проверяю доступность DNS и подготавливаю конфигурацию Xray…")
			change, err := engine.DNSAutoOn()
			if err != nil {
				if len(change.Probes) != 0 {
					printJSON(change.Probes)
				}
				return err
			}
			printJSON(change)
			fmt.Println("DNS auto записан на диск. Для включения в работающем Xray:", change.Restart)
			return nil
		})
	}
	return errors.New("использование: hotwatcher dns status|test|verify|auto on|auto off")
}
