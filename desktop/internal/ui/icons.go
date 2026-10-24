package ui

import "fyne.io/fyne/v2"

// Hand-drawn single-stroke icons, matching the web UI's inline SVG sprite so the
// desktop client speaks the same icon language.
//
// IMPORTANT: the stroke color is a concrete hex, NOT "currentColor". fyne only
// substitutes a color for a *themed* resource, and even then it rewrites the
// fill, never the stroke — so a raw static resource with stroke="currentColor"
// is handed verbatim to the SVG parser (oksvg), which rejects "currentColor"
// with "param mismatch", fails to decode, and then nil-derefs on paint. The
// theme is a fixed dark palette (vxTheme ignores the variant), so hardcoding the
// foreground token here renders correctly everywhere these icons appear.
const iconStroke = "#e6e9ef" // = colFg (--fg)

func svgIcon(name, body string) fyne.Resource {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="` + iconStroke + `" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` + body + `</svg>`
	return fyne.NewStaticResource(name+".svg", []byte(svg))
}

// #i-monitor
func monitorIcon() fyne.Resource {
	return svgIcon("monitor", `<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>`)
}

// #i-server (VM glyph in the sidebar list)
func serverIcon() fyne.Resource {
	return svgIcon("server", `<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>`)
}

// #i-grid (overview)
func gridIcon() fyne.Resource {
	return svgIcon("grid", `<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>`)
}
