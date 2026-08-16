package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ProcessStats struct {
	Running int `json:"running"`
	Total   int `json:"total"`
}

type MemoryStats struct {
	Total     uint64  `json:"total"`
	Used      uint64  `json:"used"`
	Available uint64  `json:"available"`
	Percent   float64 `json:"percent"`
}

type DiskStats struct {
	Path      string  `json:"path"`
	Total     uint64  `json:"total"`
	Used      uint64  `json:"used"`
	Available uint64  `json:"available"`
	Percent   float64 `json:"percent"`
}

type NetworkStats struct {
	Iface   string `json:"iface"`
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

type SystemStats struct {
	Hostname  string         `json:"hostname"`
	OS        string         `json:"os"`
	Kernel    string         `json:"kernel"`
	CPUModel  string         `json:"cpu_model,omitempty"`
	CPUCores  int            `json:"cpu_cores"`
	CPUPercent float64       `json:"cpu_percent"`
	Load      []float64      `json:"load"`
	Processes ProcessStats   `json:"processes"`
	Uptime    uint64         `json:"uptime"`
	Memory    MemoryStats    `json:"memory"`
	Disk      DiskStats      `json:"disk"`
	Network   []NetworkStats `json:"network"`
}

func collectSystemStats(dataDir string) SystemStats {
	hostname, _ := os.Hostname()

	s := SystemStats{
		Hostname:  hostname,
		OS:        readOSRelease(),
		Kernel:    readFirstLine("/proc/sys/kernel/osrelease"),
		CPUModel:  readCPUModel(),
		CPUCores:  runtime.NumCPU(),
		CPUPercent: cpuPercent(),
		Load:      loadAverage(),
		Uptime:    uptimeSeconds(),
		Processes: processCounts(),
		Memory:    memoryStats(),
		Disk:      diskStats(dataDir),
		Network:   networkStats(),
	}
	return s
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		return strings.TrimSpace(string(data[:i]))
	}
	return strings.TrimSpace(string(data))
}

func readOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			v = strings.Trim(v, `"`)
			return v
		}
	}
	return "linux"
}

func readCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// cpuPercent measures CPU usage over a short interval by reading /proc/stat
// twice and computing the idle vs total jiffy delta.
func cpuPercent() float64 {
	idle1, total1 := readCPUStat()
	time.Sleep(250 * time.Millisecond)
	idle2, total2 := readCPUStat()

	idleDelta := idle2 - idle1
	totalDelta := total2 - total1
	if totalDelta == 0 {
		return 0
	}
	pct := (1 - float64(idleDelta)/float64(totalDelta)) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return round1(pct)
}

func readCPUStat() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "cpu ") {
		return 0, 0
	}
	fields := strings.Fields(lines[0])
	// fields[0] == "cpu"; the rest are jiffies:
	// user nice system idle iowait irq softirq steal guest guest_nice
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 { // idle + iowait count as idle
			idle += v
		}
	}
	return idle, total
}

func loadAverage() []float64 {
	line := readFirstLine("/proc/loadavg")
	fields := strings.Fields(line)
	out := make([]float64, 0, 3)
	for _, f := range fields[:min(3, len(fields))] {
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func processCounts() ProcessStats {
	line := readFirstLine("/proc/loadavg")
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ProcessStats{}
	}
	running, total := 0, 0
	parts := strings.Split(fields[3], "/")
	if len(parts) == 2 {
		running, _ = strconv.Atoi(parts[0])
		total, _ = strconv.Atoi(parts[1])
	}
	return ProcessStats{Running: running, Total: total}
}

func uptimeSeconds() uint64 {
	line := readFirstLine("/proc/uptime")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(v)
}

func memoryStats() MemoryStats {
	var m MemoryStats
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			total, _ = parseKBValue(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			available, _ = parseKBValue(line)
		}
	}
	m.Total = total
	m.Available = available
	if total > available {
		m.Used = total - available
	}
	if total > 0 {
		m.Percent = round1(float64(m.Used) / float64(total) * 100)
	}
	return m
}

func parseKBValue(line string) (uint64, bool) {
	fields := strings.Fields(line)
	// fields[0] is the "MemTotal:"-style label; the value is fields[1].
	if len(fields) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return v * 1024, true
}

func diskStats(path string) DiskStats {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return DiskStats{Path: path}
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	available := st.Bavail * bsize
	used := uint64(0)
	if total > available {
		used = total - available
	}
	pct := 0.0
	if total > 0 {
		pct = round1(float64(used) / float64(total) * 100)
	}
	return DiskStats{Path: path, Total: total, Used: used, Available: available, Percent: pct}
}

func networkStats() []NetworkStats {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var out []NetworkStats
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		iface := strings.TrimSpace(line[:i])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[i+1:])
		if len(fields) < 16 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		out = append(out, NetworkStats{Iface: iface, RXBytes: rx, TXBytes: tx})
	}
	return out
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
