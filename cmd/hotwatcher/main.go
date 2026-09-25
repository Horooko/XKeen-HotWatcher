package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"local/xkeen-hot-watcher/internal/updater"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func printJSON(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func usage() {
	fmt.Print(`XKeen Hot Watcher ` + hw.Version + `
Использование: hotwatcher [--config ПУТЬ] КОМАНДА

Основные команды:
  keys           Сразу показать все ключи последней загрузки и сохранённые ключи
  keys --check   Заново измерить доступность применённых ключей (может быть долго)
  dns status     Показать DNS-настройку Xray и состояние автоматического выбора
  dns test       Проверить задержку доверенных DNS-серверов с роутера
  dns auto on    Включить автоматический выбор нескольких DNS в Xray
  dns auto off   Восстановить прежнюю DNS-настройку Xray
  sync           Обновить ключи подписки при работающем VPN
  hard-sync      Остановить XKeen, скачать подписку напрямую, запустить XKeen и применить ключи
  check-key      Проверить активный ключ и при сбое выбрать рабочий
  select ИМЯ    Выбрать ключ по точному имени или тегу из keys
  status         Показать состояние службы и выбранный ключ
  stop           Перейти на статический ключ и остановить службу подписки
  start          Вернуться к ключам подписки и запустить службу
  update         Проверить и установить доступное обновление программы

Подробности: hotwatcher help advanced
`)
}
func advancedUsage() {
	fmt.Print(`Дополнительные команды Hot Watcher:
  doctor             Проверить настройки и доступность API без изменений
  plan               Скачать подписку и показать план без применения
  adopt              Первое подключение: сохранить старый файл и применить подписку
  nodes              Показать теги управляемых узлов
  hold on|off        Приостановить или возобновить автообновление
  reconcile          Восстановить сохранённые узлы и выбор через API
  gc                 Удалить старые узлы после периода ожидания
  recover|abort      Завершить или откатить прерванное применение
  url set|migrate    Сохранить URL (set читает его из стандартного ввода)
  update КОМАНДА     Дополнительно: check|status|download|apply|rollback
  config-example     Показать пример конфигурации без секретов
  version [--json]   Показать версию
  daemon             Запустить службу на переднем плане

hard-sync временно прерывает VPN-соединения и перезапускает XKeen.
При ошибке загрузки XKeen запускается обратно, старые ключи сохраняются.
Команды stop/start переключают статический ключ, но не выключают XKeen.
`)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Hot Watcher:", err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("hotwatcher", flag.ContinueOnError)
	path := flags.String("config", "/opt/etc/hotwatcher/config.json", "configuration path")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	args := flags.Args()
	if len(args) == 0 {
		usage()
		return nil
	}
	command := args[0]
	if command == "version" {
		if len(args) > 1 && args[1] == "--json" {
			printJSON(updater.BuildInfo())
			return nil
		}
		fmt.Println(hw.Version)
		return nil
	}
	if command == "update" {
		return updater.Command(args[1:])
	}
	if command == "update-preflight" {
		c, err := hw.LoadConfig(*path)
		if err != nil {
			return err
		}
		if _, err = os.Lstat(c.StateDir + "/pending.json"); err == nil {
			return errors.New("subscription transaction pending")
		} else if !os.IsNotExist(err) {
			return err
		}
		_, err = hw.New(c).Status()
		return err
	}
	if command == "update-validation" {
		if len(args) != 2 {
			return errors.New("update-validation requires transaction ID")
		}
		c, err := hw.LoadConfig(*path)
		if err != nil {
			return err
		}
		if _, err = hw.New(c).Status(); err != nil {
			return err
		}
		return updater.ValidationHeartbeat(args[1])
	}
	if command == "config-example" {
		printJSON(hw.Defaults())
		return nil
	}
	if command == "help" {
		if len(args) == 1 {
			usage()
			return nil
		}
		if len(args) == 2 && args[1] == "advanced" {
			advancedUsage()
			return nil
		}
		return errors.New("использование: hotwatcher help [advanced]")
	}
	c, err := hw.LoadConfig(*path)
	if err != nil {
		return err
	}
	engine := hw.New(c)
	if command == "dns" {
		return dnsCommand(c, engine, args[1:])
	}
	if command == "hard-sync" {
		if len(args) != 1 {
			return errors.New("hard-sync не принимает аргументы")
		}
		return hardSync(c, engine)
	}
	if command == "stop" || command == "start" {
		if len(args) != 1 {
			return errors.New("start and stop take no arguments")
		}
		return serviceMode(c, engine, command)
	}
	if command == "daemon" {
		return daemon(c, engine)
	}
	if command == "status" || command == "doctor" || command == "nodes" || command == "keys" {
		var v any
		var er error
		switch command {
		case "status":
			v, er = engine.Status()
		case "doctor":
			v, er = engine.Doctor()
		case "nodes":
			v, er = engine.Nodes()
		case "keys":
			if len(args) == 1 {
				var inventory hw.KeyInventory
				inventory, er = engine.KeysSnapshot()
				if er == nil {
					printKeyInventory(inventory)
				}
				return er
			}
			if len(args) != 2 || args[1] != "--check" {
				return errors.New("использование: hotwatcher keys [--check]")
			}
			fmt.Println("Проверяю применённые ключи; проверка может занять несколько минут…")
			var keys hw.KeysReport
			keys, er = engine.Keys()
			if er == nil {
				printKeys(keys)
			}
			return er
		}
		if v != nil {
			printJSON(v)
		}
		return er
	}
	err = hw.WithLock(c, func() error {
		switch command {
		case "url":
			if len(args) != 2 {
				return errors.New("url requires set or migrate")
			}
			switch args[1] {
			case "migrate":
				return c.MigrateSubscriptionURL()
			case "set":
				b, er := io.ReadAll(io.LimitReader(os.Stdin, 8193))
				if er != nil || len(b) > 8192 {
					return errors.New("cannot read subscription URL from standard input")
				}
				return c.SetSubscriptionURL(string(b))
			default:
				return errors.New("url requires set or migrate")
			}
		case "doctor":
			v, er := engine.Doctor()
			printJSON(v)
			return er
		case "plan":
			v, er := engine.Plan()
			if er == nil {
				printJSON(v)
			}
			return er
		case "status":
			v, er := engine.Status()
			if er == nil {
				printJSON(v)
			}
			return er
		case "nodes":
			v, er := engine.Nodes()
			if er == nil {
				printJSON(v)
			}
			return er
		case "adopt":
			return engine.Sync(true)
		case "sync":
			er := engine.Sync(false)
			hw.WriteLastCheck(c, er == nil)
			if er == nil && engine.UnreachableCount > 0 {
				fmt.Printf("Недоступных ключей в подписке: %d. Они сохранены в списке, выбран проверенный ключ.\n", engine.UnreachableCount)
			}
			return er
		case "reconcile":
			return engine.Reconcile()
		case "select":
			if len(args) < 2 {
				return errors.New("select requires a tag or exact name from keys")
			}
			return engine.Select(strings.Join(args[1:], " "))
		case "check-key":
			if len(args) != 1 {
				return errors.New("check-key takes no arguments")
			}
			selected, er := engine.CheckKey()
			if er == nil {
				fmt.Println("Verified selected key:", selected)
			}
			return er
		case "gc":
			return engine.GC()
		case "recover":
			return engine.Recover()
		case "abort":
			return engine.Abort()
		case "hold":
			if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
				return errors.New("use hold on or hold off")
			}
			return engine.Hold(args[1] == "on")
		default:
			usage()
			return errors.New("unknown command")
		}
	})
	if err != nil {
		hw.SafeLog(c, "command_failed", map[string]any{"command": command, "message": err.Error()})
	} else if command != "doctor" && command != "status" && command != "plan" && command != "nodes" && command != "keys" {
		fmt.Println("OK (production Xray was not restarted)")
	}
	return err
}

func enabledMarker() (bool, error) {
	s, err := os.Lstat("/opt/etc/hotwatcher/enabled")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !s.Mode().IsRegular() {
		return false, errors.New("unsafe service enabled marker")
	}
	return true, nil
}

func setEnabled(on bool) error {
	if !on {
		err := os.Remove("/opt/etc/hotwatcher/enabled")
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if exists, err := enabledMarker(); err != nil || exists {
		return err
	}
	return os.WriteFile("/opt/etc/hotwatcher/enabled", []byte("enabled\n"), 0600)
}

func initService(action string) error {
	out, err := exec.Command("/opt/etc/init.d/S99hotwatcher", action).CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	if err != nil {
		return fmt.Errorf("Hot Watcher service %s failed: %w", action, err)
	}
	return nil
}

func serviceMode(c hw.Config, engine *hw.Engine, action string) error {
	if action == "start" {
		if err := hw.WithLock(c, engine.StartFromStatic); err != nil {
			return err
		}
		if err := setEnabled(true); err != nil {
			return err
		}
		if err := initService("start"); err != nil {
			return err
		}
		time.Sleep(time.Second)
		status, err := exec.Command("/opt/etc/init.d/S99hotwatcher", "status").CombinedOutput()
		if err != nil || !strings.Contains(string(status), "Hot Watcher PID:") {
			return errors.New("subscription route restored, but Hot Watcher service did not remain running")
		}
		fmt.Println("Subscription service active. Xray was not restarted.")
		return nil
	}
	wasEnabled, err := enabledMarker()
	if err != nil {
		return err
	}
	if err = setEnabled(false); err != nil {
		return err
	}
	if err = initService("stop"); err != nil {
		if wasEnabled {
			_ = setEnabled(true)
		}
		return err
	}
	if err = hw.WithLock(c, engine.StopToStatic); err != nil {
		if _, markerErr := os.Lstat(c.StateDir + "/static-mode.json"); os.IsNotExist(markerErr) && wasEnabled {
			_ = setEnabled(true)
			_ = initService("start")
		}
		return err
	}
	fmt.Println("Static fallback active from 04_outbounds.json. Xray was not restarted.")
	return nil
}

func printKeys(v hw.KeysReport) {
	if v.APIWarning != "" {
		fmt.Println("Внимание:", v.APIWarning)
	}
	if len(v.Keys) == 0 {
		fmt.Println("Ключей нет")
		return
	}
	active := v.Keys[0]
	fmt.Printf("Активный ключ: %s [%s] — %s\n", active.Name, active.Tag, pingText(active.PingMS))
	if v.LastCheckAgo == nil {
		fmt.Println("С последней проверки подписки: нет данных")
	} else {
		result := "ошибка"
		if v.LastCheckSuccess != nil && *v.LastCheckSuccess {
			result = "успешно"
		}
		fmt.Printf("С последней проверки подписки: %s (%s)\n", ageText(*v.LastCheckAgo), result)
	}
	if v.SelectedAgo == nil {
		fmt.Println("С последней смены ключа: нет данных")
	} else {
		fmt.Printf("С последней смены ключа: %s\n", ageText(*v.SelectedAgo))
	}
	if len(v.Keys) > 1 {
		fmt.Println("Остальные ключи:")
		for _, key := range v.Keys[1:] {
			fmt.Printf("- %s [%s] — %s\n", key.Name, key.Tag, pingText(key.PingMS))
		}
	}
}

func printKeyInventory(v hw.KeyInventory) {
	fmt.Println("Ключи по сохранённому состоянию (без обращения к Xray API):")
	if v.LastCheckAgo != nil {
		result := "ошибка"
		if v.LastCheckSuccess != nil && *v.LastCheckSuccess {
			result = "успешно"
		}
		fmt.Printf("С последней проверки подписки: %s (%s)\n", ageText(*v.LastCheckAgo), result)
	}
	if v.SelectedAgo != nil {
		fmt.Printf("С последней смены ключа: %s\n", ageText(*v.SelectedAgo))
	}
	if v.FetchedAt != nil {
		fmt.Printf("Последняя загрузка: %s\n", v.FetchedAt.Local().Format("2006-01-02 15:04:05"))
	}
	if v.Note != "" {
		fmt.Println(v.Note)
	}
	for _, key := range v.Keys {
		parts := []string{}
		if key.Selected {
			parts = append(parts, "выбран по сохранённому состоянию")
		}
		if key.Applied {
			parts = append(parts, "применён")
		} else {
			parts = append(parts, "не применён")
		}
		if key.Latest {
			if key.Checked {
				if key.Verified {
					parts = append(parts, "проверен без VPN: "+pingText(key.LatencyMS))
				} else {
					parts = append(parts, "не прошёл проверку без VPN")
				}
			} else {
				parts = append(parts, "из последней подписки")
			}
		} else if v.FetchedAt != nil {
			parts = append(parts, "отсутствует в последней подписке")
		}
		fmt.Printf("- %s [%s] — %s\n", key.Name, key.Tag, strings.Join(parts, ", "))
	}
	fmt.Println("Для новой проверки применённых ключей: hotwatcher keys --check")
}

func pingText(ms *float64) string {
	if ms == nil {
		return "недоступен"
	}
	return fmt.Sprintf("%.1f мс", *ms)
}

func ageText(d time.Duration) string {
	seconds := int64(d / time.Second)
	days, hours, minutes := seconds/86400, (seconds%86400)/3600, (seconds%3600)/60
	if days > 0 {
		return fmt.Sprintf("%d д %d ч %d мин", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%d ч %d мин", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d мин %d сек", minutes, seconds%60)
	}
	return fmt.Sprintf("%d сек", seconds)
}
func daemon(c hw.Config, e *hw.Engine) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	hw.SafeLog(c, "daemon_started", map[string]any{"interval_seconds": c.IntervalSeconds})
	next := hw.NextSubscriptionCheck(c)
	nextKeyCheck := time.Time{} // Check the saved pin once on service startup.
	if id := os.Getenv("HOTWATCHER_UPDATE_ID"); id != "" {
		if _, err := e.Status(); err != nil {
			return err
		}
		if err := updater.DaemonReady(id); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(c.ReconcileSeconds) * time.Second):
		}
	}
	for {
		select {
		case <-ctx.Done():
			hw.SafeLog(c, "daemon_stopped", nil)
			return nil
		default:
		}
		err := hw.WithLock(c, func() error {
			if er := e.Reconcile(); er != nil {
				return er
			}
			if time.Now().After(next) {
				next = time.Now().Add(time.Duration(c.IntervalSeconds) * time.Second)
				hw.WriteNextSubscriptionCheck(c, next)
				er := e.Sync(false)
				hw.WriteLastCheck(c, er == nil)
				if er != nil {
					// Subscription download/validation may fail while the saved
					// selected node is already dead. Check the saved pool anyway.
					if _, keyErr := e.CheckKey(); keyErr != nil {
						hw.SafeLog(c, "key_check_failed", map[string]any{"message": keyErr.Error()})
					}
				}
				return er
			}
			if time.Now().After(nextKeyCheck) {
				nextKeyCheck = time.Now().Add(time.Duration(c.KeyCheckSeconds) * time.Second)
				_, keyErr := e.CheckKey()
				return keyErr
			}
			return nil
		})
		if err != nil {
			hw.SafeLog(c, "daemon_check_failed", map[string]any{"message": err.Error()})
		}
		timer := time.NewTimer(time.Duration(c.ReconcileSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			hw.SafeLog(c, "daemon_stopped", nil)
			return nil
		case <-timer.C:
		}
	}
}
