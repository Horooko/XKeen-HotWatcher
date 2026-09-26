package hotwatcher

import "testing"

func TestProcMemoryParserUsesResidentAndAvailableKilobytes(t *testing.T) {
	data := []byte("MemTotal: 1015072 kB\nMemAvailable: 654020 kB\nVmRSS:\t609892 kB\n")
	available, err := procKilobytes(data, "MemAvailable:")
	if err != nil || available != 654020*1024 {
		t.Fatalf("available memory parsed incorrectly: %d, %v", available, err)
	}
	rss, err := procKilobytes(data, "VmRSS:")
	if err != nil || rss != 609892*1024 {
		t.Fatalf("resident memory parsed incorrectly: %d, %v", rss, err)
	}
	if _, err := procKilobytes([]byte("MemAvailable: unknown kB"), "MemAvailable:"); err == nil {
		t.Fatal("invalid available memory was accepted")
	}
}
