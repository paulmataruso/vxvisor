package ui

import (
	"strings"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// vmSummary renders a short, plain-language description of a VM for the detail
// pane.
func vmSummary(s client.Session) string {
	var b strings.Builder
	b.WriteString(itoa(s.CPUs))
	b.WriteString(" vCPU, ")
	b.WriteString(itoa(s.MemoryMB))
	b.WriteString(" MB RAM, ")
	b.WriteString(itoa(s.DiskGB))
	b.WriteString(" GB disk")
	if s.GuestOS != "" {
		b.WriteString("\nGuest: ")
		b.WriteString(s.GuestOS)
	} else if s.OSType != "" {
		b.WriteString("\nType: ")
		b.WriteString(s.OSType)
	}
	if s.Kind != "" {
		b.WriteString("\nRole: ")
		b.WriteString(s.Kind)
	}
	return b.String()
}

// title upper-cases the first letter of a word (replacement for the deprecated
// strings.Title for our single-word verbs).
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
