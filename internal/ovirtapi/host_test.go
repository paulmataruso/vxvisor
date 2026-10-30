package ovirtapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vdxclone/internal/imageio"
	"vdxclone/internal/qemu"
	"vdxclone/internal/secrets"
	"vdxclone/internal/vmbackup"
)

// TestHostSDKConformance runs the real oVirt Python SDK and the ovirt-imageio
// client (testdata/sdk_conformance.py) against this engine API, over TLS on
// loopback, with the VM's disk on a scratch QEMU: inventory, SSO, a full and
// an incremental backup of the running VM (with guest writes during each),
// an incremental of the stopped VM via qemu-nbd, checkpoint removal, and a
// restore (staged disk + upload + VM from the OVF + attach + NIC) whose disk
// must equal the source. The backend is the in-memory one; the data path is
// real.
//
// Needs qemu-system-x86_64, qemu-img, qemu-nbd and a Python venv with
// ovirt-engine-sdk-python + ovirt-imageio. Run with VDX_HOST_OVIRT=1,
// VDX_SDK_PYTHON=<venv>/bin/python and VDX_SDK_SCRIPT=<path to the script>.
func TestHostSDKConformance(t *testing.T) {
	if os.Getenv("VDX_HOST_OVIRT") != "1" {
		t.Skip("set VDX_HOST_OVIRT=1 (plus VDX_SDK_PYTHON, VDX_SDK_SCRIPT) to run the SDK conformance test")
	}
	py, script := os.Getenv("VDX_SDK_PYTHON"), os.Getenv("VDX_SDK_SCRIPT")
	if py == "" || script == "" {
		t.Fatal("VDX_SDK_PYTHON and VDX_SDK_SCRIPT must be set")
	}
	// A short root: NBD unix socket paths must fit sun_path.
	dir, err := os.MkdirTemp("/tmp", "vdxo")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	img := filepath.Join(dir, "disk.qcow2")
	hostRun(t, "qemu-img", "create", "-q", "-f", "qcow2", img, "64M")

	qmpSock := filepath.Join(dir, "qmp.sock")
	vmProc := exec.Command("qemu-system-x86_64", "-nodefaults", "-display", "none", "-S",
		"-machine", "q35", "-accel", "tcg", "-m", "64",
		"-qmp", "unix:"+qmpSock+",server=on,wait=off",
		"-drive", "file="+img+",if=none,id=disk0,format=qcow2,cache=writeback",
		"-device", "virtio-blk-pci,drive=disk0")
	vmProc.Stderr = os.Stderr
	if err := vmProc.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = vmProc.Wait(); close(exited) }()
	defer func() { _ = vmProc.Process.Kill(); <-exited }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(qmpSock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	var mu sync.Mutex
	running := true
	be := newMemBackend()
	be.nextID = randomID
	be.diskDir = filepath.Join(dir, "staged")
	if err := os.MkdirAll(be.diskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := be.vms["11111111-1111-4111-8111-111111111111"]
	src.Disk.Path, src.Disk.Provisioned, src.Disk.Actual = img, 64<<20, 0
	desc := func() vmbackup.Disk {
		mu.Lock()
		defer mu.Unlock()
		return vmbackup.Disk{VMID: src.ID, Path: img, Format: "qcow2", Running: running, QMPSocket: qmpSock,
			UID: -1, GID: -1}
	}
	be.backupDisk = func(*VM) (vmbackup.Disk, error) { return desc(), nil }
	be.removeHook = func(_, id string) error { return vmbackup.RemoveCheckpoint(desc(), id) }

	ca, err := secrets.LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), "conformance CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.LoadOrIssue(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	apiLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	ioLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	s := New(Config{PublicHost: "127.0.0.1", APIPort: port(apiLn), ImageioPort: port(ioLn),
		WorkRoot: filepath.Join(dir, "work"), CAPEM: ca.PEM, InstanceID: "5e1f0c2a-0000-4000-8000-000000000001",
		NodeName: "node1"}, be, imageio.NewServer())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	apiSrv, ioSrv := &http.Server{Handler: s.Handler()}, &http.Server{Handler: s.ImageioHandler()}
	go func() { _ = apiSrv.Serve(apiLn) }()
	go func() { _ = ioSrv.Serve(ioLn) }()
	defer apiSrv.Close()
	defer ioSrv.Close()

	// Hooks the script calls to act as the guest and to check results.
	hooks := http.NewServeMux()
	fail := func(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusInternalServerError) }
	hooks.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		q, err := qemu.DialQMP(qmpSock)
		if err != nil {
			fail(w, err)
			return
		}
		defer q.Close()
		cmd := fmt.Sprintf("write -P %s %s %s", r.FormValue("pattern"), r.FormValue("offset"), r.FormValue("length"))
		out, err := q.HMP(`qemu-io disk0 "` + cmd + `"`)
		if err == nil && strings.Contains(out, "rror") {
			err = fmt.Errorf("qemu-io: %s", out)
		}
		if err != nil {
			fail(w, err)
		}
	})
	hooks.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		q, err := qemu.DialQMP(qmpSock)
		if err != nil {
			fail(w, err)
			return
		}
		_, _ = q.Execute("quit", nil)
		q.Close()
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			fail(w, fmt.Errorf("QEMU did not quit"))
			return
		}
		mu.Lock()
		running = false
		mu.Unlock()
		be.mu.Lock()
		src.Status = "down"
		be.mu.Unlock()
	})
	compare := func(w http.ResponseWriter, other string) {
		mu.Lock()
		args := []string{"compare", "-f", "qcow2", "-F", "qcow2", img, other}
		if running {
			args = append(args[:1], append([]string{"-U"}, args[1:]...)...)
		}
		mu.Unlock()
		if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
			fail(w, fmt.Errorf("qemu-img compare %s: %v: %s", other, err, out))
		}
	}
	hooks.HandleFunc("/compare", func(w http.ResponseWriter, r *http.Request) { compare(w, r.FormValue("path")) })
	hooks.HandleFunc("/compare-disk", func(w http.ResponseWriter, r *http.Request) {
		id := r.FormValue("id")
		path := ""
		be.mu.Lock()
		if d := be.staged[id]; d != nil {
			path = d.Path
		}
		for _, v := range be.vms {
			if v.Disk != nil && v.Disk.ID == id {
				path = v.Disk.Path
			}
		}
		be.mu.Unlock()
		if path == "" {
			fail(w, fmt.Errorf("no disk %s", id))
			return
		}
		compare(w, path)
	})
	hs := httptest.NewServer(hooks)
	defer hs.Close()

	work := filepath.Join(dir, "client")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, "-I", script, "--engine", fmt.Sprintf("https://127.0.0.1:%d", port(apiLn)),
		"--ca", filepath.Join(dir, "ca.crt"), "--hook", hs.URL, "--work", work)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("SDK conformance script failed: %v", err)
	}

	// The worker the script created carried its cloud-config through.
	found := false
	for _, spec := range be.specs {
		if spec.Name == "veeam-worker-conformance" {
			found = true
			if spec.Purpose != "worker" || spec.CPUs != 2 || spec.MemoryMB != 2048 ||
				!strings.Contains(spec.UserData, "conformance-worker") || spec.Firmware != "uefi" {
				t.Errorf("worker spec %+v", spec)
			}
		}
		if spec.Name == "web01-restored" && (spec.Purpose != "restore" || spec.CPUs != 2 || spec.MemoryMB != 2048) {
			t.Errorf("restored VM spec %+v", spec)
		}
	}
	if !found {
		t.Error("the worker VM never reached the backend")
	}
	audit := strings.Join(be.audits, "\n")
	for _, want := range []string{"ovirt.backup.start ", "ovirt.backup.finalize ", "ovirt.transfer.start ",
		"ovirt.transfer.finalize ", "disk.attach "} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit trail lacks %q", want)
		}
	}
	// Nothing left running: no qemu-nbd of ours, no work dirs.
	if out, _ := exec.Command("pgrep", "-af", "qemu-nbd").Output(); strings.Contains(string(out), dir) {
		t.Errorf("qemu-nbd left running:\n%s", out)
	}
}

func hostRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}
