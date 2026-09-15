package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	hw "local/xkeen-hot-watcher/internal/hotwatcher"
	"local/xkeen-hot-watcher/internal/updater"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func printJSON(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func usage() {
	fmt.Print(`XKeen Hot Watcher ` + hw.Version + `
Usage: hotwatcher [--config /opt/etc/hotwatcher/config.json] COMMAND

config-example   Print default configuration (no secrets)
version [--json] Print version and release build info
update COMMAND   Signed software update: check|status|download|apply|enable|disable|pause|pin|unpin|retry
doctor           Read-only local/API capability checks
plan             Download/parse subscription, report diff; no API/disk changes
adopt            First migration: backup existing subscription file and hot-apply
sync             Fetch/validate/probe/apply subscription without production restart
status           Redacted state and API status
nodes            Owned node tags (no credentials)
select TAG       Explicitly pin one active node, after a candidate probe
reconcile        Restore saved active pool and pin via API, without downloading
hold on|off      Pause downloads/application/GC, but keep restoring saved pin
gc               Remove only owned retired handlers after the grace period
recover          Complete a journaled, interrupted transaction
abort            Restore old selection and file from the pending transaction
daemon           Subscription timer + runtime pin reconciliation; foreground

This program never invokes xkeen, changes netfilter or restarts production Xray.
It is not a kill-switch and cannot guarantee preservation of every game session.
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
		usage()
		return nil
	}
	c, err := hw.LoadConfig(*path)
	if err != nil {
		return err
	}
	engine := hw.New(c)
	if command == "daemon" {
		return daemon(c, engine)
	}
	if command == "status" || command == "doctor" || command == "nodes" {
		var v any
		var er error
		switch command {
		case "status":
			v, er = engine.Status()
		case "doctor":
			v, er = engine.Doctor()
		case "nodes":
			v, er = engine.Nodes()
		}
		if v != nil {
			printJSON(v)
		}
		return er
	}
	err = hw.WithLock(c, func() error {
		switch command {
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
			return er
		case "reconcile":
			return engine.Reconcile()
		case "select":
			if len(args) != 2 {
				return errors.New("select requires a tag from nodes")
			}
			return engine.Select(args[1])
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
	} else if command != "doctor" && command != "status" && command != "plan" && command != "nodes" {
		fmt.Println("OK (production Xray was not restarted)")
	}
	return err
}
func daemon(c hw.Config, e *hw.Engine) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	hw.SafeLog(c, "daemon_started", map[string]any{"interval_seconds": c.IntervalSeconds})
	next := hw.NextSubscriptionCheck(c)
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
				return er
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
