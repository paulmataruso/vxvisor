// Command svg2png rasterizes an SVG to a square PNG using the same oksvg+rasterx
// stack Fyne uses, so the output is guaranteed loadable by the app.
package main

import (
	"image"
	"image/png"
	"log"
	"os"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatal("usage: svg2png <in.svg> <out.png> <size>")
	}
	in, out := os.Args[1], os.Args[2]
	var size int
	if _, err := fmtSscan(os.Args[3], &size); err != nil || size <= 0 {
		log.Fatalf("bad size %q", os.Args[3])
	}

	icon, err := oksvg.ReadIcon(in, oksvg.StrictErrorMode)
	if err != nil {
		log.Fatalf("parse svg: %v", err)
	}
	icon.SetTarget(0, 0, float64(size), float64(size))

	rgba := image.NewRGBA(image.Rect(0, 0, size, size))
	scanner := rasterx.NewScannerGV(size, size, rgba, rgba.Bounds())
	raster := rasterx.NewDasher(size, size, scanner)
	icon.Draw(raster, 1.0)

	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, rgba); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s (%dx%d)", out, size, size)
}

func fmtSscan(s string, n *int) (int, error) {
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}
