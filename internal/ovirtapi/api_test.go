package ovirtapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/imageio"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

type apiEnv struct {
	t  *testing.T
	s  *Server
	be *memBackend
	ts *httptest.Server
}

func newAPIEnv(t *testing.T) *apiEnv {
	t.Helper()
	be := newMemBackend()
	s := New(Config{PublicHost: "198.51.100.7", APIPort: 443, ImageioPort: 54322, WorkRoot: t.TempDir(),
		CAPEM:      []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
		InstanceID: "5e1f0c2a-0000-4000-8000-000000000001", NodeName: "node1"}, be, imageio.NewServer())
	s.now = func() time.Time { return created0.Add(2 * time.Hour) }
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &apiEnv{t: t, s: s, be: be, ts: ts}
}

type resp struct {
	code int
	hdr  http.Header
	body []byte
}

// call sends one request as admin (Basic auth). accept "xml" / "json" / "".
func (e *apiEnv) call(method, path, accept, body string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.SetBasicAuth("admin@internal", "secret")
	switch accept {
	case "xml":
		req.Header.Set("Accept", "application/xml")
		req.Header.Set("Content-Type", "application/xml")
	case "json":
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Version", "4")
	return e.send(req)
}

func (e *apiEnv) send(req *http.Request) resp {
	e.t.Helper()
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{code: r.StatusCode, hdr: r.Header, body: b}
}

func (e *apiEnv) want(r resp, code int) {
	e.t.Helper()
	if r.code != code {
		e.t.Fatalf("status %d, want %d: %s", r.code, code, r.body)
	}
}

func (e *apiEnv) jsonOf(r resp) map[string]any {
	e.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		e.t.Fatalf("not JSON: %v: %s", err, r.body)
	}
	return m
}

// golden compares body with testdata/name, or rewrites it under -update.
func golden(t *testing.T, name string, body []byte) {
	t.Helper()
	if strings.HasSuffix(name, ".json") {
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("%s: not JSON: %v", name, err)
		}
		body, _ = json.MarshalIndent(v, "", "  ")
		body = append(body, '\n')
	}
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update to create it)", err, t.Name())
	}
	if !bytes.Equal(want, body) {
		t.Errorf("%s differs from the golden file (go test -update rewrites it):\n--- got ---\n%s", name, body)
	}
}

// TestGoldenShapes pins the XML and JSON the API serves for the objects
// backup clients read: the oVirt SDK parses the XML, Veeam the JSON.
func TestGoldenShapes(t *testing.T) {
	e := newAPIEnv(t)
	vm := "11111111-1111-4111-8111-111111111111"
	for _, c := range []struct{ name, path string }{
		{"api_root", "/ovirt-engine/api"},
		{"vms", "/ovirt-engine/api/vms"},
		{"vm_follow", "/ovirt-engine/api/vms/" + vm + "?follow=disk_attachments.disk,nics.reporteddevices"},
		{"diskattachments", "/ovirt-engine/api/vms/" + vm + "/diskattachments"},
		{"nics", "/ovirt-engine/api/vms/" + vm + "/nics"},
		{"disks", "/ovirt-engine/api/disks"},
		{"storagedomains", "/ovirt-engine/api/storagedomains"},
		{"networks", "/ovirt-engine/api/networks"},
		{"vnicprofiles", "/ovirt-engine/api/vnicprofiles"},
		{"hosts", "/ovirt-engine/api/hosts"},
		{"clusters", "/ovirt-engine/api/clusters"},
		{"datacenters", "/ovirt-engine/api/datacenters"},
		{"checkpoints", "/ovirt-engine/api/vms/" + vm + "/checkpoints"},
		{"snapshots", "/ovirt-engine/api/vms/" + vm + "/snapshots"},
		{"fault_not_found", "/ovirt-engine/api/vms/00000000-dead-4000-8000-000000000000"},
	} {
		for _, f := range []string{"xml", "json"} {
			r := e.call("GET", c.path, f, "")
			if c.name == "fault_not_found" {
				e.want(r, http.StatusNotFound)
			} else {
				e.want(r, http.StatusOK)
			}
			if ct := r.hdr.Get("Content-Type"); !strings.Contains(ct, f) {
				t.Errorf("%s: Content-Type %q for %s", c.name, ct, f)
			}
			golden(t, c.name+"."+f, r.body)
		}
	}
	// With no Accept header the API answers JSON (what Veeam's plug-in expects).
	r := e.call("GET", "/ovirt-engine/api/vms", "", "")
	e.want(r, http.StatusOK)
	if !strings.Contains(r.hdr.Get("Content-Type"), "json") {
		t.Errorf("default format is %q, want JSON", r.hdr.Get("Content-Type"))
	}
	// The /v4 prefix is the same API.
	e.want(e.call("GET", "/ovirt-engine/api/v4/vms", "xml", ""), http.StatusOK)
}

// TestSSO covers the password grant, bearer use, logout and the error shapes.
func TestSSO(t *testing.T) {
	e := newAPIEnv(t)
	form := url.Values{"grant_type": {"password"}, "scope": {"ovirt-app-api"},
		"username": {"admin@internal"}, "password": {"secret"}}
	r := e.send(mustReq(t, "POST", e.ts.URL+"/ovirt-engine/sso/oauth/token", form))
	e.want(r, http.StatusOK)
	tok := e.jsonOf(r)
	access, _ := tok["access_token"].(string)
	if access == "" || tok["token_type"] != "bearer" || tok["scope"] != "ovirt-app-api" {
		t.Fatalf("token response %s", r.body)
	}

	get := func(token string) int {
		req := mustReq(t, "GET", e.ts.URL+"/ovirt-engine/api/vms", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return e.send(req).code
	}
	if c := get(access); c != http.StatusOK {
		t.Fatalf("bearer GET: %d", c)
	}
	if c := get("not-a-token"); c != http.StatusUnauthorized {
		t.Fatalf("bad bearer: %d", c)
	}

	form.Set("password", "wrong")
	r = e.send(mustReq(t, "POST", e.ts.URL+"/ovirt-engine/sso/oauth/token", form))
	e.want(r, http.StatusBadRequest)
	if m := e.jsonOf(r); m["error_code"] != "access_denied" || m["error"] == "" {
		t.Fatalf("SSO error shape: %s", r.body)
	}

	r = e.send(mustReq(t, "GET", e.ts.URL+"/ovirt-engine/services/sso-logout?token="+access, nil))
	if r.code != http.StatusOK {
		t.Fatalf("logout: %d", r.code)
	}
	if c := get(access); c != http.StatusUnauthorized {
		t.Fatalf("token still valid after logout: %d", c)
	}

	// No credentials: 401 with a Basic challenge and a fault body.
	r = e.send(mustReq(t, "GET", e.ts.URL+"/ovirt-engine/api", nil))
	e.want(r, http.StatusUnauthorized)
	if !strings.Contains(r.hdr.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("no Basic challenge: %v", r.hdr)
	}

	// The CA is published at the engine's pki-resource URL.
	r = e.send(mustReq(t, "GET", e.ts.URL+"/ovirt-engine/services/pki-resource?resource=ca-certificate&format=X509-PEM-CA", nil))
	e.want(r, http.StatusOK)
	if !bytes.Contains(r.body, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("pki-resource: %s", r.body)
	}
}

func mustReq(t *testing.T, method, u string, form url.Values) *http.Request {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	return req
}

// TestRestoreFromOVF replays a VM's own OVF (as backup software stores it)
// into POST /vms, in both encodings, and checks the spec it produces.
func TestRestoreFromOVF(t *testing.T) {
	e := newAPIEnv(t)
	vm := e.jsonOf(e.call("GET", "/ovirt-engine/api/vms/11111111-1111-4111-8111-111111111111", "json", ""))
	ovf := vm["initialization"].(map[string]any)["configuration"].(map[string]any)["data"].(string)
	if !strings.Contains(ovf, "ovf:Envelope") || !strings.Contains(ovf, "vxvisor:Instance") {
		t.Fatalf("OVF: %s", ovf)
	}

	body, _ := json.Marshal(map[string]any{
		"name":           "web01-restored",
		"cluster":        map[string]any{"id": e.s.clusterID()},
		"initialization": map[string]any{"configuration": map[string]any{"type": "ovf", "data": ovf}},
	})
	r := e.call("POST", "/ovirt-engine/api/vms", "json", string(body))
	e.want(r, http.StatusCreated)
	id, _ := e.jsonOf(r)["id"].(string)
	spec := e.be.specs[id]
	if spec.Name != "web01-restored" || spec.CPUs != 2 || spec.MemoryMB != 2048 || spec.Firmware != "uefi" ||
		spec.MachineType != "q35" || spec.OrgID != 1 || spec.Purpose != "restore" || !spec.GuestAgent {
		t.Errorf("restore spec %+v", spec)
	}

	// The same OVF in an XML request, with the original name (taken by the
	// source VM: a conflict, as on an engine).
	x := "<vm><name>web01</name><cluster id=\"" + e.s.clusterID() + "\"/><initialization><configuration>" +
		"<type>ovf</type><data>" + xmlEsc(ovf) + "</data></configuration></initialization></vm>"
	r = e.call("POST", "/ovirt-engine/api/vms", "xml", x)
	e.want(r, http.StatusConflict)
	if !bytes.Contains(r.body, []byte("<fault>")) {
		t.Errorf("XML fault: %s", r.body)
	}
	x = strings.Replace(x, "<name>web01</name>", "<name>web01-x</name>", 1)
	e.want(e.call("POST", "/ovirt-engine/api/vms", "xml", x), http.StatusCreated)

	// An unknown cluster is refused.
	e.want(e.call("POST", "/ovirt-engine/api/vms", "json", `{"name":"x","cluster":{"id":"nope"}}`), http.StatusBadRequest)
}

// TestWorkerLifecycle follows a backup-proxy deployment: VM with cloud-init,
// a staged disk, attach, NIC on a vNIC profile, start, read its IP, delete.
func TestWorkerLifecycle(t *testing.T) {
	e := newAPIEnv(t)
	sd := poolUUID(0)
	r := e.call("POST", "/ovirt-engine/api/vms", "json", `{
		"name": "veeam-worker-1",
		"cluster": {"id": "`+e.s.clusterID()+`"},
		"template": {"id": "`+blankTemplate+`"},
		"memory": "4294967296",
		"cpu": {"topology": {"sockets": "2", "cores": "1", "threads": "1"}},
		"bios": {"type": "q35_ovmf"},
		"os": {"type": "other_linux"},
		"initialization": {"custom_script": "#cloud-config\nruncmd:\n  - echo worker\n"}
	}`)
	e.want(r, http.StatusCreated)
	vmID := e.jsonOf(r)["id"].(string)
	spec := e.be.specs[vmID]
	if spec.CPUs != 2 || spec.MemoryMB != 4096 || spec.Firmware != "uefi" || spec.Purpose != "worker" ||
		!strings.Contains(spec.UserData, "echo worker") {
		t.Fatalf("worker spec %+v", spec)
	}
	// Starting without a disk is refused.
	e.want(e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/start", "json", "{}"), http.StatusBadRequest)

	r = e.call("POST", "/ovirt-engine/api/disks", "json", `{"name":"worker-root","provisioned_size":"8589934592",
		"format":"cow","sparse":"true","storage_domains":{"storage_domain":[{"id":"`+sd+`"}]}}`)
	e.want(r, http.StatusCreated)
	disk := e.jsonOf(r)
	diskID := disk["id"].(string)
	if disk["provisioned_size"] != "8589934592" || disk["format"] != "cow" {
		t.Errorf("created disk %s", r.body)
	}
	// A pool that can't hold files refuses staged disks.
	e.want(e.call("POST", "/ovirt-engine/api/storagedomains/"+poolUUID(3)+"/disks", "json",
		`{"name":"x","provisioned_size":"1073741824"}`), http.StatusBadRequest)

	r = e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/diskattachments", "json",
		`{"disk":{"id":"`+diskID+`"},"interface":"virtio_scsi","bootable":"true","active":"true"}`)
	e.want(r, http.StatusCreated)
	if a := e.jsonOf(r); a["id"] != diskID {
		t.Errorf("attachment %s", r.body)
	}
	// An attached disk can't be deleted.
	e.want(e.call("DELETE", "/ovirt-engine/api/disks/"+diskID, "json", ""), http.StatusConflict)

	r = e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/nics", "json",
		`{"name":"nic1","interface":"virtio","vnic_profile":{"id":"`+netUUID(5)+`"}}`)
	e.want(r, http.StatusCreated)
	if v, _ := e.be.VM(nil, vmID); v.NetID != 5 {
		t.Errorf("NIC not bound to port group 5: %+v", v)
	}
	e.want(e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/nics", "json",
		`{"vnic_profile":{"id":"00000000-0000-0000-0000-00000000beef"}}`), http.StatusNotFound)

	r = e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/start", "xml", "<action/>")
	e.want(r, http.StatusOK)
	if !bytes.Contains(r.body, []byte("<status>complete</status>")) {
		t.Errorf("action reply %s", r.body)
	}
	r = e.call("GET", "/ovirt-engine/api/vms/"+vmID+"/reporteddevices", "json", "")
	e.want(r, http.StatusOK)
	if !bytes.Contains(r.body, []byte("192.0.2.44")) {
		t.Errorf("reported devices %s", r.body)
	}
	r = e.call("GET", "/ovirt-engine/api/vms?search=name%3Dveeam-worker*", "json", "")
	if vms, _ := e.jsonOf(r)["vm"].([]any); len(vms) != 1 {
		t.Errorf("search found %d VMs: %s", len(vms), r.body)
	}

	e.want(e.call("POST", "/ovirt-engine/api/vms/"+vmID+"/stop", "json", "{}"), http.StatusOK)
	e.want(e.call("DELETE", "/ovirt-engine/api/vms/"+vmID, "json", ""), http.StatusOK)
	e.want(e.call("GET", "/ovirt-engine/api/vms/"+vmID, "json", ""), http.StatusNotFound)

	audit := strings.Join(e.be.audits, "\n")
	for _, want := range []string{"vm.create " + vmID + " worker", "disk.create " + diskID, "disk.attach " + diskID + " virtio_scsi",
		"nic.set " + vmID, "vm.delete " + vmID} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit trail lacks %q:\n%s", want, audit)
		}
	}
}

// TestSnapshotsAndCheckpoints: snapshots are recorded (the backup is the
// point in time), checkpoints list and delete through the backend.
func TestSnapshotsAndCheckpoints(t *testing.T) {
	e := newAPIEnv(t)
	vm := "11111111-1111-4111-8111-111111111111"
	r := e.call("POST", "/ovirt-engine/api/vms/"+vm+"/snapshots", "json", `{"description":"veeam","persist_memorystate":"false"}`)
	e.want(r, http.StatusCreated)
	sid := e.jsonOf(r)["id"].(string)
	r = e.call("GET", "/ovirt-engine/api/vms/"+vm+"/snapshots", "json", "")
	if l, _ := e.jsonOf(r)["snapshot"].([]any); len(l) != 2 {
		t.Fatalf("snapshots %s", r.body)
	}
	e.want(e.call("DELETE", "/ovirt-engine/api/vms/"+vm+"/snapshots/"+sid, "json", ""), http.StatusOK)
	e.want(e.call("GET", "/ovirt-engine/api/vms/"+vm+"/snapshots/"+sid, "json", ""), http.StatusNotFound)

	_ = e.be.AddCheckpoint(nil, Checkpoint{ID: "c1", VMID: vm, Created: created0})
	_ = e.be.AddCheckpoint(nil, Checkpoint{ID: "c2", VMID: vm, ParentID: "c1", Created: created0.Add(time.Hour)})
	r = e.call("GET", "/ovirt-engine/api/vms/"+vm+"/checkpoints/c2", "xml", "")
	e.want(r, http.StatusOK)
	if !bytes.Contains(r.body, []byte("<parent_id>c1</parent_id>")) {
		t.Errorf("checkpoint %s", r.body)
	}
	e.want(e.call("DELETE", "/ovirt-engine/api/vms/"+vm+"/checkpoints/c1", "json", ""), http.StatusOK)
	e.want(e.call("DELETE", "/ovirt-engine/api/vms/"+vm+"/checkpoints/c1", "json", ""), http.StatusNotFound)
}

// TestBackupAndTransferRefusals: requests the engine must refuse before
// touching any disk, and the VM's backup lock is released after a failure.
func TestBackupAndTransferRefusals(t *testing.T) {
	e := newAPIEnv(t)
	vm := "11111111-1111-4111-8111-111111111111"
	for i := 0; i < 2; i++ { // the second attempt must not see a leftover lock
		r := e.call("POST", "/ovirt-engine/api/vms/"+vm+"/backups", "json", `{"disks":{"disk":[{"id":"`+DiskIDForVM(vm)+`"}]}}`)
		e.want(r, http.StatusBadRequest)
	}
	e.want(e.call("POST", "/ovirt-engine/api/vms/"+vm+"/backups", "json", `{"disks":{"disk":[{"id":"not-this-vms"}]}}`), http.StatusBadRequest)
	e.want(e.call("GET", "/ovirt-engine/api/vms/"+vm+"/backups/nope", "json", ""), http.StatusNotFound)

	// A plain download (no backup) is not offered; an upload needs a staged disk.
	e.want(e.call("POST", "/ovirt-engine/api/imagetransfers", "json",
		`{"disk":{"id":"`+DiskIDForVM(vm)+`"},"direction":"download"}`), http.StatusBadRequest)
	e.want(e.call("POST", "/ovirt-engine/api/imagetransfers", "json",
		`{"disk":{"id":"`+DiskIDForVM(vm)+`"},"direction":"upload"}`), http.StatusConflict)
	e.want(e.call("POST", "/ovirt-engine/api/imagetransfers", "json",
		`{"disk":{"id":"x"},"direction":"sideways"}`), http.StatusBadRequest)
	e.want(e.call("POST", "/ovirt-engine/api/imagetransfers", "json",
		`{"backup":{"id":"nope"},"direction":"download"}`), http.StatusNotFound)

	// Images with an unknown ticket are refused by imageio on both listeners.
	r := e.send(mustReq(t, "OPTIONS", e.ts.URL+"/images/0123456789abcdef0123", nil))
	e.want(r, http.StatusForbidden)
}
