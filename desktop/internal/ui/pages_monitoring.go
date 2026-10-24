package ui

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-3 Monitoring page: host CPU% and memory% sparklines over a trailing
// window plus current stat tiles, polled from /api/metrics/history. (The web
// page's live WebSocket feed is approximated here by a 5s poll.)

func (sh *shell) monitoringPage() fyne.CanvasObject {
	cpuImg := canvas.NewImageFromImage(blankImage())
	cpuImg.FillMode = canvas.ImageFillStretch
	memImg := canvas.NewImageFromImage(blankImage())
	memImg.FillMode = canvas.ImageFillStretch
	tiles := container.NewStack()

	prim := nrgba(colPrimary)
	okc := nrgba(colOK)

	apply := func(samples []client.Sample) {
		var cpu, mem []float64
		var latest client.Sample
		have := false
		for _, s := range samples {
			cpu = append(cpu, s.CPUPct)
			mp := 0.0
			if s.MemTotal > 0 {
				mp = float64(s.MemUsed) / float64(s.MemTotal) * 100
			}
			mem = append(mem, mp)
			latest = s
			have = true
		}
		cpuImg.Image = sparklineImage(cpu, 100, 700, 90, prim)
		cpuImg.Refresh()
		memImg.Image = sparklineImage(mem, 100, 700, 90, okc)
		memImg.Refresh()

		memPct := 0.0
		if latest.MemTotal > 0 {
			memPct = float64(latest.MemUsed) / float64(latest.MemTotal) * 100
		}
		if !have {
			tiles.Objects = []fyne.CanvasObject{mutedText("No samples yet.", 12)}
		} else {
			tiles.Objects = []fyne.CanvasObject{container.NewGridWithColumns(4,
				statTile(itoaf(latest.CPUPct)+"%", "CPU", nil),
				statTile(itoaf(memPct)+"%", "Memory", nil),
				statTile(humanBytes(latest.NetRx)+"/s", "Net in", nil),
				statTile(humanBytes(latest.NetTx)+"/s", "Net out", nil),
			)}
		}
		tiles.Refresh()
	}

	load := func() {
		go func() {
			s, err := sh.app.client.MetricHistory("host", "", 10)
			fyne.Do(func() {
				if err == nil {
					apply(s)
				}
			})
		}()
	}
	sh.pageReload["monitoring"] = load
	load()

	// Live-ish updates: poll until the shell stops (sh.done), no sh.win race.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sh.done:
				return
			case <-t.C:
				s, err := sh.app.client.MetricHistory("host", "", 10)
				if err == nil {
					fyne.Do(func() { apply(s) })
				}
			}
		}
	}()

	chartH := func(img fyne.CanvasObject) fyne.CanvasObject {
		return container.New(&fixedHeightLayout{90}, img)
	}
	body := container.NewVBox(
		titledCard("Host CPU %", chartH(cpuImg)),
		spacer(8),
		titledCard("Host memory %", chartH(memImg)),
		spacer(8),
		titledCard("Now", tiles),
	)
	return mgmtPage("Monitoring", plainBtn("Refresh", func() { sh.reloadActive() }), body)
}
