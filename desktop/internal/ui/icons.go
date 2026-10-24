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

// Section icons for the management nav rail. These mirror the web UI's inline
// sprite so the desktop client reads the same way.
func boxIcon() fyne.Resource {
	return svgIcon("box", `<path d="M21 8V6a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 6v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l2-1"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/>`)
}
func layersIcon() fyne.Resource {
	return svgIcon("layers", `<path d="m12 2 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 17l9 5 9-5"/>`)
}
func activityIcon() fyne.Resource {
	return svgIcon("activity", `<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>`)
}
func trashIcon() fyne.Resource {
	return svgIcon("trash", `<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>`)
}
func discIcon() fyne.Resource {
	return svgIcon("disc", `<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/>`)
}
func archiveIcon() fyne.Resource {
	return svgIcon("archive", `<rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V8M9 12h6"/>`)
}
func databaseIcon() fyne.Resource {
	return svgIcon("database", `<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>`)
}
func shareIcon() fyne.Resource {
	return svgIcon("share", `<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.6 13.5 6.8 4M15.4 6.5l-6.8 4"/>`)
}
func networkIcon() fyne.Resource {
	return svgIcon("network", `<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2h14v2"/>`)
}
func routeIcon() fyne.Resource {
	return svgIcon("route", `<circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M9 19h6a3 3 0 0 0 3-3V8"/>`)
}
func routerIcon() fyne.Resource {
	return svgIcon("router", `<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h2M15 13V9a3 3 0 0 1 3-3h1M19 6l2-2M19 6l-2-2"/>`)
}
func shieldIcon() fyne.Resource {
	return svgIcon("shield", `<path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z"/>`)
}
func usersIcon() fyne.Resource {
	return svgIcon("users", `<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>`)
}
func keyIcon() fyne.Resource {
	return svgIcon("key", `<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 5l3 3M14 8l3 3"/>`)
}
func listIcon() fyne.Resource {
	return svgIcon("list", `<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>`)
}
func creditIcon() fyne.Resource {
	return svgIcon("credit", `<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>`)
}
func downloadIcon() fyne.Resource {
	return svgIcon("download", `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>`)
}
func buildingIcon() fyne.Resource {
	return svgIcon("building", `<rect x="4" y="2" width="16" height="20" rx="1"/><path d="M9 22v-4h6v4M8 6h.01M12 6h.01M16 6h.01M8 10h.01M12 10h.01M16 10h.01M8 14h.01M12 14h.01M16 14h.01"/>`)
}
func clusterIcon() fyne.Resource {
	return svgIcon("cluster", `<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M12 11 5.8 17M12 11l6.2 6"/>`)
}
func lockIcon() fyne.Resource {
	return svgIcon("lock", `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`)
}

// Action icons used on buttons (matching the web sprite's single-stroke style).
func plusIcon() fyne.Resource { return svgIcon("plus", `<path d="M12 5v14M5 12h14"/>`) }
func refreshIcon() fyne.Resource {
	return svgIcon("refresh", `<path d="M21 12a9 9 0 1 1-2.6-6.3M21 3v6h-6"/>`)
}
func playIcon() fyne.Resource { return svgIcon("play", `<path d="m6 4 14 8-14 8V4Z"/>`) }
func stopIcon() fyne.Resource {
	return svgIcon("stop", `<rect x="5" y="5" width="14" height="14" rx="2"/>`)
}
func gearIcon() fyne.Resource {
	return svgIcon("gear", `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 0 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H1a2 2 0 0 1 0-4h.1A1.6 1.6 0 0 0 2.6 7a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H7a1.6 1.6 0 0 0 1-1.5V1a2 2 0 0 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V7a1.6 1.6 0 0 0 1.5 1H23a2 2 0 0 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z"/>`)
}
func pencilIcon() fyne.Resource {
	return svgIcon("pencil", `<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>`)
}
func checkIcon() fyne.Resource { return svgIcon("check", `<path d="M20 6 9 17l-5-5"/>`) }
func cameraIcon() fyne.Resource {
	return svgIcon("camera", `<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2Z"/><circle cx="12" cy="13" r="4"/>`)
}
func tagIcon() fyne.Resource {
	return svgIcon("tag", `<path d="M20.6 13.4 12 22l-9-9V3h10l7.6 7.6a2 2 0 0 1 0 2.8ZM7 7h.01"/>`)
}
func folderOpenIcon() fyne.Resource {
	return svgIcon("folderopen", `<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v2H3V7ZM3 11h18l-2 8a2 2 0 0 1-2 1.6H5A2 2 0 0 1 3 19Z"/>`)
}
