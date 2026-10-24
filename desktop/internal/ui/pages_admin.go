package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-3 Updates page (admin): shows the running version + channel, checks
// GitHub on demand, applies an update (restarts vdxd), and exposes host power.

func (sh *shell) updatesPage() fyne.CanvasObject {
	currentTxt := boldText("…", 18)
	channel := selectWith([]string{"stable", "preview"}, "stable")
	guard := false
	channel.OnChanged = func(ch string) {
		if guard || ch == "" {
			return
		}
		sh.do(func() error { return sh.app.client.SetUpdateChannel(ch) }, func() { sh.toast("Update channel: " + ch) })
	}

	results := container.NewStack(mutedPara("Click “Check for updates” to query GitHub for the latest release."))

	statusBody := container.NewVBox(
		container.NewHBox(mutedText("Running version", 12)),
		currentTxt,
		spacer(8),
		container.NewBorder(nil, nil, mutedText("Channel", 12),
			container.NewThemeOverride(channel, compactTheme{})),
	)

	check := primaryBtn("Check for updates", func() {
		results.Objects = []fyne.CanvasObject{mutedText("Checking GitHub…", 12)}
		results.Refresh()
		go func() {
			st, err := sh.app.client.CheckUpdate()
			fyne.Do(func() {
				results.Objects = []fyne.CanvasObject{sh.updateResult(st, err)}
				results.Refresh()
			})
		}()
	})

	load := func() {
		go func() {
			st, err := sh.app.client.UpdateStatusInfo()
			fyne.Do(func() {
				if err != nil {
					currentTxt.Text = "unavailable"
				} else {
					currentTxt.Text = st.Current
					guard = true
					if st.Channel != "" {
						channel.SetSelected(st.Channel)
					}
					guard = false
				}
				canvas.Refresh(currentTxt)
			})
		}()
	}
	sh.pageReload["updates"] = load
	load()

	hostRestart := dangerBtn("Restart host", func() {
		sh.confirm("Restart host", "Reboot the entire host now? All VMs are stopped.", func() {
			sh.do(func() error { return sh.app.client.HostRestart() }, func() { sh.toast("Host restarting…") })
		})
	})
	hostShutdown := dangerBtn("Shut down host", func() {
		sh.confirm("Shut down host", "Power off the entire host now? All VMs are stopped.", func() {
			sh.do(func() error { return sh.app.client.HostShutdown() }, func() { sh.toast("Host shutting down…") })
		})
	})

	body := container.NewVBox(
		titledCard("Server", statusBody),
		spacer(10),
		titledCard("Available update", results),
		spacer(10),
		subSection("Host power", nil, container.NewThemeOverride(
			container.NewHBox(hostRestart, hSpace(10), hostShutdown), compactTheme{})),
	)
	return mgmtPage("Updates", check, body)
}

func (sh *shell) updateResult(st client.UpdateStatus, err error) fyne.CanvasObject {
	if err != nil {
		return mutedPara("Check failed: " + err.Error())
	}
	if st.UpToDate {
		return container.NewVBox(
			container.NewHBox(pill("ok", "ok"), hSpace(8), boldText("Up to date", 15)),
			mutedText("Latest: "+st.Latest+" ("+st.Channel+")", 12),
		)
	}
	apply := primaryBtn("Apply & restart", func() {
		sh.confirm("Apply update",
			"Download and apply "+st.Latest+", then restart vdxd? The server is briefly unavailable.",
			func() {
				sh.do(func() error { _, e := sh.app.client.ApplyUpdate(); return e },
					func() { sh.toast("Update applied — server restarting.") })
			})
	})
	head := container.NewHBox(pill("warn", "warn"), hSpace(8), boldText("Update available: "+st.Latest, 15))
	rows := container.NewVBox(head, spacer(4), mutedText("Current "+st.Current+" · channel "+st.Channel, 12))
	if st.PublishedAt != "" {
		rows.Add(mutedText("Published "+shortTime(st.PublishedAt), 11.5))
	}
	if st.Notes != "" {
		rows.Add(spacer(6))
		rows.Add(mutedPara(st.Notes))
	}
	rows.Add(spacer(8))
	rows.Add(container.NewThemeOverride(container.NewHBox(apply), compactTheme{}))
	return rows
}
