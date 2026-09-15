package main

import (
	"fmt"
	"local/xkeen-hot-watcher/internal/updater"
	"os"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "run" {
		err = updater.Timer()
	} else if len(os.Args) > 1 && os.Args[1] == "recover" {
		err = updater.Recover()
	} else {
		err = updater.Command(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Updater:", err)
		os.Exit(1)
	}
}
