package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// This file holds the Phase-1 "core compute" JSON endpoints: VM power/spec/
// network edits, autostart, snapshots, and the installer-CD controls. Each is a
// thin wrapper over an existing service method — all authz + audit live in the
// service layer, so these only decode the body, call through, and map the error
// (writeErr maps ErrUnauthorized→403, ErrNotFound→404).

// restartSession power-cycles a VM (graceful stop then a fresh start) and
// returns the restarted session.
func (a *API) restartSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s, err := a.svc.RestartSession(p, r.PathValue("id"), ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s)
}

// setAutostart toggles a VM's "start at boot" flag.
func (a *API) setAutostart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.SetAutostart(p, r.PathValue("id"), body.On, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"autostart": body.On})
}

// updateSessionSpec changes a stopped VM's hardware profile (firmware, machine
// type, disk bus, NIC model, graphics, OS type, agent/TPM/Secure Boot, and the
// perf toggles). Applied on the next start; never touches the data disk. CPU/
// memory/disk sizing is a separate concern — use /resize for those.
func (a *API) updateSessionSpec(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Firmware    string `json:"firmware"`
		OSType      string `json:"os_type"`
		MachineType string `json:"machine_type"`
		DiskBus     string `json:"disk_bus"`
		NICModel    string `json:"nic_model"`
		VGA         string `json:"vga"`
		GuestAgent  bool   `json:"guest_agent"`
		TPM         bool   `json:"tpm"`
		SecureBoot  bool   `json:"secure_boot"`
		PinCPUs     bool   `json:"perf_pin"`
		HugePages   bool   `json:"perf_hugepages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	hw := session.HardwareSpec{
		Firmware: body.Firmware, OSType: body.OSType, MachineType: body.MachineType,
		DiskBus: body.DiskBus, NICModel: body.NICModel, VGA: body.VGA,
		GuestAgent: body.GuestAgent, TPM: body.TPM, SecureBoot: body.SecureBoot,
		PinCPUs: body.PinCPUs, HugePages: body.HugePages,
	}
	if err := a.svc.UpdateSessionSpec(p, r.PathValue("id"), hw, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "updated"})
}

// setSessionNetwork rebinds a VM's NIC to a port group (0 = default/NAT). The
// response reports whether the change applied live (true) or is deferred to the
// next start (false).
func (a *API) setSessionNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Network int64 `json:"network"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	live, err := a.svc.SetSessionNetwork(p, r.PathValue("id"), body.Network, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"live": live})
}

func (a *API) listSnapshots(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListSnapshots(p, r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.CreateSnapshot(p, r.PathValue("id"), body.Name, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) revertSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sid, _ := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err := a.svc.RevertSnapshot(p, r.PathValue("id"), sid, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) deleteSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sid, _ := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err := a.svc.DeleteSnapshot(p, r.PathValue("id"), sid, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ejectISO detaches the boot/installer ISO so the VM boots its disk (next start).
func (a *API) ejectISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.EjectISO(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// mountVirtio (re)enables auto-attaching the virtio-win driver CD (next start).
func (a *API) mountVirtio(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.MountVirtioISO(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ejectVirtio stops auto-attaching the virtio-win driver CD (next start).
func (a *API) ejectVirtio(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.EjectVirtioISO(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
