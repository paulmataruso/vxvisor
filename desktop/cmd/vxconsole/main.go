// Command vxconsole is the VXVisor desktop console client: a lightweight,
// VMRC-style app to connect to a VXVisor host, browse its VMs, run basic power
// operations, and open the VM console.
package main

import "github.com/paulmataruso/vxvisor/desktop/internal/ui"

// version is an optional build stamp via -ldflags "-X=main.version=...". Note:
// fyne-cross does NOT forward -ldflags to `go build`, so release builds instead
// bake the version into ui.Version through a generated version_gen.go init(). We
// therefore only override ui.Version when an ldflags value was actually provided —
// otherwise we'd clobber the generated version back to "dev" (which made the
// client think every launch was out of date and prompt to update).
var version = "dev"

func main() {
	if version != "dev" {
		ui.Version = version
	}
	ui.New().Run()
}
