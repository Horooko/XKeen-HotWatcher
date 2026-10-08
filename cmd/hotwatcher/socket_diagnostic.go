package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// /proc/net exposes socket endpoints without invoking netstat. Only counts
// for the configured transparent inbound port are returned to the report.
func countPortSockets(path string, port int, tcp bool) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	count := 0
	for rows := 0; scanner.Scan() && rows < 8192; rows++ {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		address := strings.Split(fields[1], ":")
		if len(address) != 2 {
			continue
		}
		parsed, err := strconv.ParseUint(address[1], 16, 16)
		if err != nil || int(parsed) != port {
			continue
		}
		if !tcp || fields[3] == "0A" { // TCP LISTEN
			count++
		}
	}
	return count, scanner.Err() == nil
}

func transparentListenerReport(tcpPort, udpPort int) []string {
	if tcpPort == 0 && udpPort == 0 {
		return []string{"Порты входов Xray в 03_inbounds.json не определены"}
	}
	lines := make([]string, 0, 4)
	for _, item := range []struct {
		name string
		path string
		port int
		tcp  bool
	}{
		{"TCP IPv4", "/proc/net/tcp", tcpPort, true},
		{"TCP IPv6", "/proc/net/tcp6", tcpPort, true},
		{"UDP IPv4", "/proc/net/udp", udpPort, false},
		{"UDP IPv6", "/proc/net/udp6", udpPort, false},
	} {
		if item.port == 0 {
			continue
		}
		count, known := countPortSockets(item.path, item.port, item.tcp)
		lines = append(lines, fmt.Sprintf("%s: порт=%d; /proc доступен=%v; сокетов=%d", item.name, item.port, known, count))
	}
	return lines
}
