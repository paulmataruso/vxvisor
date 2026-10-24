package ui

import "fyne.io/fyne/v2"

// X11 keysyms used by RFB KeyEvent messages.
const (
	ksBackSpace = 0xff08
	ksTab       = 0xff09
	ksReturn    = 0xff0d
	ksEscape    = 0xff1b
	ksInsert    = 0xff63
	ksDelete    = 0xffff
	ksHome      = 0xff50
	ksEnd       = 0xff57
	ksPageUp    = 0xff55
	ksPageDown  = 0xff56
	ksLeft      = 0xff51
	ksUp        = 0xff52
	ksRight     = 0xff53
	ksDown      = 0xff54

	ksShiftL   = 0xffe1
	ksControlL = 0xffe3
	ksAltL     = 0xffe9
	ksSuperL   = 0xffeb

	ksF1 = 0xffbe // F2..F12 are sequential from here
)

// specialKeysym maps Fyne's named keys to X11 keysyms. Printable characters are
// handled separately via TypedRune (where keysym == the rune for ASCII/Latin-1).
var specialKeysym = map[fyne.KeyName]uint32{
	fyne.KeyReturn:    ksReturn,
	fyne.KeyEnter:     ksReturn,
	fyne.KeyBackspace: ksBackSpace,
	fyne.KeyTab:       ksTab,
	fyne.KeyEscape:    ksEscape,
	fyne.KeyInsert:    ksInsert,
	fyne.KeyDelete:    ksDelete,
	fyne.KeyHome:      ksHome,
	fyne.KeyEnd:       ksEnd,
	fyne.KeyPageUp:    ksPageUp,
	fyne.KeyPageDown:  ksPageDown,
	fyne.KeyLeft:      ksLeft,
	fyne.KeyUp:        ksUp,
	fyne.KeyRight:     ksRight,
	fyne.KeyDown:      ksDown,
	fyne.KeySpace:     0x20,

	fyne.KeyF1:  ksF1,
	fyne.KeyF2:  ksF1 + 1,
	fyne.KeyF3:  ksF1 + 2,
	fyne.KeyF4:  ksF1 + 3,
	fyne.KeyF5:  ksF1 + 4,
	fyne.KeyF6:  ksF1 + 5,
	fyne.KeyF7:  ksF1 + 6,
	fyne.KeyF8:  ksF1 + 7,
	fyne.KeyF9:  ksF1 + 8,
	fyne.KeyF10: ksF1 + 9,
	fyne.KeyF11: ksF1 + 10,
	fyne.KeyF12: ksF1 + 11,
}

// runeKeysym returns the X11 keysym for a printable rune. For ASCII and Latin-1
// the keysym equals the code point; other Unicode uses the 0x01000000 + cp
// convention that X11/RFB define.
func runeKeysym(r rune) uint32 {
	if r >= 0x20 && r <= 0xff {
		return uint32(r)
	}
	return 0x01000000 + uint32(r)
}
