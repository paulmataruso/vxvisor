// Package metrics samples host and per-VM resource usage, keeps a short in-memory
// ring buffer for live charts, and rolls samples up into the database. Host CPU
// comes from /proc/stat deltas, memory from /proc/meminfo, disk from statfs, and
// per-VM CPU/RSS from the qemu process's /proc entries.
package metrics

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vdxclone/internal/db"
)

// Sample is one metric reading. Throughput fields are bytes/second, computed
// from counter deltas over the real elapsed time between samples.
type Sample struct {
	Scope     string  `json:"scope"`      // host|vm
	TargetID  string  `json:"target_id"`  // "" for host, session id for vm
	Name      string  `json:"name"`       // display name
	CPUPct    float64 `json:"cpu_pct"`
	MemUsed   int64   `json:"mem_used"`
	MemTotal  int64   `json:"mem_total"`
	DiskUsed  int64   `json:"disk_used"`
	DiskTotal int64   `json:"disk_total"`
	DiskRead  int64   `json:"disk_read"`  // bytes/sec
	DiskWrite int64   `json:"disk_write"` // bytes/sec
	NetRx     int64   `json:"net_rx"`     // bytes/sec
	NetTx     int64   `json:"net_tx"`     // bytes/sec
	IOWait    float64 `json:"iowait"`     // host CPU iowait %
	CPUPres   float64 `json:"cpu_pres"`   // PSI cpu "some" avg10 (host)
	MemPres   float64 `json:"mem_pres"`   // PSI memory "some" avg10 (host)
	IOPres    float64 `json:"io_pres"`    // busiest physical disk utilization % (REAL device busy; NOT PSI io — see hostDiskBusy)
	TS        string  `json:"ts"`
}

// LiveSnapshot is what the dashboard WebSocket pushes each tick.
type LiveSnapshot struct {
	Host Sample   `json:"host"`
	VMs  []Sample `json:"vms"`
}

type cpuJiffies struct {
	busy, total, iowait uint64
}

type vmCPU struct {
	jiffies  uint64
	ioR, ioW uint64
	at       time.Time
}

// ioCounters holds cumulative byte counters plus the time they were read, so a
// later read yields a per-second rate.
type ioCounters struct {
	a, b uint64 // read/rx , write/tx
	at   time.Time
}

type Collector struct {
	db      *db.DB
	diskDir string

	mu       sync.Mutex
	prevHost cpuJiffies
	prevDisk ioCounters

	prevDiskTicks   map[string]uint64 // per-device io_ticks (ms) for device-busy %
	prevDiskTicksAt time.Time
	prevNet  ioCounters
	prevVM   map[int]vmCPU
	hostRing []Sample
	vmRing   map[string][]Sample
	live     LiveSnapshot
	ticks    int
}

const ringCap = 120 // ~20 min at a 10s interval

func NewCollector(d *db.DB, diskDir string) *Collector {
	return &Collector{db: d, diskDir: diskDir, prevVM: map[int]vmCPU{}, vmRing: map[string][]Sample{}}
}

// Collect runs one sampling pass. It is called on a ticker by the worker.
func (c *Collector) Collect() {
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339)

	host := Sample{Scope: "host", Name: "host", TS: ts}
	host.CPUPct, host.IOWait = c.hostCPU()
	host.CPUPres, host.MemPres, _ = readPSI()
	// I/O "pressure" is reported as the busiest physical disk's real utilization
	// (io_ticks delta), NOT PSI io: PSI io over-reports on some kernels (observed
	// pinned ~85% with zero D-state tasks, zero blkio-wait, idle devices), which
	// alarmed operators with a phantom. Device busy % reflects actual saturation.
	host.IOPres = c.hostDiskBusy(now)
	host.MemUsed, host.MemTotal = hostMem()
	host.DiskUsed, host.DiskTotal = diskUsage(c.diskDir)
	host.DiskRead, host.DiskWrite = c.hostDiskIO(now)
	host.NetRx, host.NetTx = c.hostNetIO(now)

	vms := c.vmSamples(now, ts)

	c.mu.Lock()
	c.hostRing = appendRing(c.hostRing, host)
	for _, v := range vms {
		c.vmRing[v.TargetID] = appendRing(c.vmRing[v.TargetID], v)
	}
	c.live = LiveSnapshot{Host: host, VMs: vms}
	c.ticks++
	rollup := c.ticks%6 == 1 // persist roughly once a minute at 10s cadence
	c.mu.Unlock()

	if rollup {
		c.persist(host)
		for _, v := range vms {
			c.persist(v)
		}
		if c.ticks%360 == 1 { // ~hourly: prune samples older than 7 days
			_, _ = c.db.Exec(`DELETE FROM metric_samples WHERE ts < datetime('now','-7 days')`)
		}
	}
}

// Live returns the most recent snapshot for the dashboard feed.
func (c *Collector) Live() LiveSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.live
}

// HostHistory returns the host ring buffer (for initial chart fill).
func (c *Collector) HostHistory() []Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Sample(nil), c.hostRing...)
}

func (c *Collector) persist(s Sample) {
	_, _ = c.db.Exec(`INSERT INTO metric_samples(scope,target_id,cpu_pct,mem_used,mem_total,disk_used,disk_total,disk_read,disk_write,net_rx,net_tx,iowait,cpu_pres,mem_pres,io_pres)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, s.Scope, s.TargetID, s.CPUPct, s.MemUsed, s.MemTotal, s.DiskUsed, s.DiskTotal, s.DiskRead, s.DiskWrite, s.NetRx, s.NetTx, s.IOWait, s.CPUPres, s.MemPres, s.IOPres)
}

// History returns persisted samples for a scope/target over the last `mins`
// minutes, oldest first, for drawing history charts.
func (c *Collector) History(scope, target string, mins int) []Sample {
	if mins <= 0 {
		mins = 60
	}
	rows, err := c.db.Query(`SELECT scope,target_id,cpu_pct,mem_used,mem_total,disk_used,disk_total,disk_read,disk_write,net_rx,net_tx,iowait,cpu_pres,mem_pres,io_pres,ts
		FROM metric_samples WHERE scope=? AND target_id=? AND ts >= datetime('now', ?) ORDER BY id`,
		scope, target, "-"+strconv.Itoa(mins)+" minutes")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var s Sample
		if rows.Scan(&s.Scope, &s.TargetID, &s.CPUPct, &s.MemUsed, &s.MemTotal, &s.DiskUsed, &s.DiskTotal,
			&s.DiskRead, &s.DiskWrite, &s.NetRx, &s.NetTx, &s.IOWait, &s.CPUPres, &s.MemPres, &s.IOPres, &s.TS) == nil {
			out = append(out, s)
		}
	}
	return out
}

// ---- host ----------------------------------------------------------------

// hostCPU returns busy CPU % and iowait % since the previous sample.
func (c *Collector) hostCPU() (cpu, iowait float64) {
	cur, ok := readProcStatCPU()
	if !ok {
		return 0, 0
	}
	c.mu.Lock()
	prev := c.prevHost
	c.prevHost = cur
	c.mu.Unlock()
	if prev.total == 0 || cur.total <= prev.total {
		return 0, 0
	}
	dt := float64(cur.total - prev.total)
	return round2(100 * float64(cur.busy-prev.busy) / dt), round2(100 * float64(cur.iowait-prev.iowait) / dt)
}

// readPSI reads Linux pressure-stall info ("some" avg10) for cpu/memory/io.
// Returns zeros when PSI is unavailable (kernel without CONFIG_PSI).
func readPSI() (cpu, mem, io float64) {
	return psiSome("/proc/pressure/cpu"), psiSome("/proc/pressure/memory"), psiSome("/proc/pressure/io")
}

func psiSome(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "avg10=") {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
				return v
			}
		}
	}
	return 0
}

func readProcStatCPU() (cpuJiffies, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuJiffies{}, false
	}
	line := data
	if i := indexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuJiffies{}, false
	}
	var total, idle, iowait uint64
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
		if i == 4 {
			iowait = v
		}
	}
	return cpuJiffies{busy: total - idle, total: total, iowait: iowait}, true
}

func hostMem() (used, total int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var memTotal, memAvail int64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			memTotal = v * 1024
		case "MemAvailable:":
			memAvail = v * 1024
		}
	}
	return memTotal - memAvail, memTotal
}

// ---- host disk / net throughput ------------------------------------------

func rate(cur, prev uint64, ds float64) int64 {
	if cur < prev || ds <= 0 {
		return 0
	}
	return int64(float64(cur-prev) / ds)
}

func (c *Collector) hostDiskIO(now time.Time) (readBps, writeBps int64) {
	r, w := readBlockBytes()
	c.mu.Lock()
	prev := c.prevDisk
	c.prevDisk = ioCounters{a: r, b: w, at: now}
	c.mu.Unlock()
	if prev.at.IsZero() {
		return 0, 0
	}
	ds := now.Sub(prev.at).Seconds()
	return rate(r, prev.a, ds), rate(w, prev.b, ds)
}

func (c *Collector) hostNetIO(now time.Time) (rxBps, txBps int64) {
	rx, tx := readNetBytes()
	c.mu.Lock()
	prev := c.prevNet
	c.prevNet = ioCounters{a: rx, b: tx, at: now}
	c.mu.Unlock()
	if prev.at.IsZero() {
		return 0, 0
	}
	ds := now.Sub(prev.at).Seconds()
	return rate(rx, prev.a, ds), rate(tx, prev.b, ds)
}

// hostDiskBusy returns the busiest physical disk's utilization % since the last
// sample, from /sys/block/<dev>/stat field 10 (io_ticks: milliseconds during
// which the device had I/O in flight). busy% = Δio_ticks / Δwall_ms * 100. This
// is the same quantity `iostat -x` prints as %util and reflects REAL device
// saturation — unlike PSI io, which can read high with no actual I/O happening.
func (c *Collector) hostDiskBusy(now time.Time) float64 {
	cur := readBlockIOTicks()
	c.mu.Lock()
	prev := c.prevDiskTicks
	prevAt := c.prevDiskTicksAt
	c.prevDiskTicks = cur
	c.prevDiskTicksAt = now
	c.mu.Unlock()
	if prevAt.IsZero() {
		return 0
	}
	ms := now.Sub(prevAt).Seconds() * 1000
	if ms <= 0 {
		return 0
	}
	var max float64
	for dev, t := range cur {
		p, ok := prev[dev]
		if !ok || t < p {
			continue
		}
		if busy := 100 * float64(t-p) / ms; busy > max {
			max = busy
		}
	}
	if max > 100 {
		max = 100
	}
	return round2(max)
}

// readBlockIOTicks reads per-device io_ticks (ms with I/O in flight) for whole
// physical disks, skipping virtual/loopback/ram/dm devices.
func readBlockIOTicks() map[string]uint64 {
	out := map[string]uint64{}
	ents, err := os.ReadDir("/sys/block")
	if err != nil {
		return out
	}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") ||
			strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "md") {
			continue
		}
		data, err := os.ReadFile("/sys/block/" + name + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) < 10 {
			continue
		}
		ticks, _ := strconv.ParseUint(f[9], 10, 64) // field 10: io_ticks (ms)
		out[name] = ticks
	}
	return out
}

// readBlockBytes sums read/written bytes across whole physical disks (via
// /sys/block/<dev>/stat), skipping virtual/loopback/ram/dm devices and
// partitions (which /sys/block does not list as top-level entries).
func readBlockBytes() (readBytes, writeBytes uint64) {
	ents, err := os.ReadDir("/sys/block")
	if err != nil {
		return 0, 0
	}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zram") ||
			strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "md") {
			continue
		}
		data, err := os.ReadFile("/sys/block/" + name + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) < 7 {
			continue
		}
		sr, _ := strconv.ParseUint(f[2], 10, 64) // sectors read
		sw, _ := strconv.ParseUint(f[6], 10, 64) // sectors written
		readBytes += sr * 512
		writeBytes += sw * 512
	}
	return readBytes, writeBytes
}

// readNetBytes sums rx/tx bytes across the host's real NICs (en*/eth*/wl*/bond*),
// ignoring loopback and virtual devices (taps, bridges, vxlan, veth).
func readNetBytes() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if !isHostNIC(name) {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx
}

func isHostNIC(name string) bool {
	for _, p := range []string{"en", "eth", "wl", "bond"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readProcPidIO returns cumulative read_bytes/write_bytes for a pid.
func readProcPidIO(pid int) (r, w uint64) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "read_bytes:":
			r = v
		case "write_bytes:":
			w = v
		}
	}
	return r, w
}

// ---- per-VM --------------------------------------------------------------

func (c *Collector) vmSamples(now time.Time, ts string) []Sample {
	rows, err := c.db.Query(`SELECT id,name,pid FROM sessions WHERE state='running' AND deleted_at IS NULL`)
	if err != nil {
		return nil
	}
	type vm struct {
		id, name string
		pid      int
	}
	var list []vm
	for rows.Next() {
		var v vm
		if err := rows.Scan(&v.id, &v.name, &v.pid); err == nil && v.pid > 0 {
			list = append(list, v)
		}
	}
	rows.Close()

	clk := clockTicks()
	var out []Sample
	for _, v := range list {
		s := Sample{Scope: "vm", TargetID: v.id, Name: v.name, TS: ts}
		if j, rss, ok := readProcPidCPU(v.pid); ok {
			ioR, ioW := readProcPidIO(v.pid)
			c.mu.Lock()
			prev, had := c.prevVM[v.pid]
			c.prevVM[v.pid] = vmCPU{jiffies: j, ioR: ioR, ioW: ioW, at: now}
			c.mu.Unlock()
			if had && now.After(prev.at) {
				ds := now.Sub(prev.at).Seconds()
				dj := float64(j-prev.jiffies) / float64(clk)
				if ds > 0 {
					s.CPUPct = round2(100 * dj / ds)
					s.DiskRead = rate(ioR, prev.ioR, ds)
					s.DiskWrite = rate(ioW, prev.ioW, ds)
				}
			}
			s.MemUsed = rss
		}
		out = append(out, s)
	}
	return out
}

// readProcPidCPU returns utime+stime jiffies and RSS bytes for a pid.
func readProcPidCPU(pid int) (jiffies uint64, rss int64, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	s := string(data)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+2 >= len(s) {
		return 0, 0, false
	}
	f := strings.Fields(s[rp+2:]) // f[0] == field 3 (state)
	// utime=14, stime=15, rss=24 (1-based); subtract 3 for this slice.
	if len(f) < 24-3+1 {
		return 0, 0, false
	}
	ut, _ := strconv.ParseUint(f[14-3], 10, 64)
	st, _ := strconv.ParseUint(f[15-3], 10, 64)
	rssPages, _ := strconv.ParseInt(f[24-3], 10, 64)
	return ut + st, rssPages * int64(os.Getpagesize()), true
}

// ---- helpers -------------------------------------------------------------

func appendRing(ring []Sample, s Sample) []Sample {
	ring = append(ring, s)
	if len(ring) > ringCap {
		ring = ring[len(ring)-ringCap:]
	}
	return ring
}

func diskUsage(dir string) (used, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0
	}
	total = int64(st.Blocks) * int64(st.Bsize)
	return total - int64(st.Bavail)*int64(st.Bsize), total
}

func clockTicks() float64 { return 100 } // _SC_CLK_TCK is 100 on Linux/amd64

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
