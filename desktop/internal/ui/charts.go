package ui

import (
	"image"
	"image/color"
)

// sparklineImage renders a simple filled-under line chart of data (values in
// 0..max) into an RGBA image. Transparent background; the area under the line is
// lightly tinted. Used by the Monitoring page; the image is stretched to fit.
func sparklineImage(data []float64, max float64, w, h int, col color.NRGBA) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	if w < 2 || h < 2 || len(data) < 2 || max <= 0 {
		return img
	}
	fill := color.NRGBA{R: col.R, G: col.G, B: col.B, A: 0x30}

	ys := make([]int, len(data))
	xs := make([]int, len(data))
	for i, v := range data {
		frac := v / max
		if frac < 0 {
			frac = 0
		}
		if frac > 1 {
			frac = 1
		}
		xs[i] = int(float64(i) / float64(len(data)-1) * float64(w-1))
		ys[i] = int(float64(h-1) * (1 - frac))
	}
	// Fill under the polyline, column by column (linear-interpolated y).
	for x := 0; x < w; x++ {
		y := interpY(xs, ys, x)
		for yy := y; yy < h; yy++ {
			img.SetRGBA(x, yy, rgba(fill))
		}
	}
	// Stroke the line (2px).
	for i := 1; i < len(data); i++ {
		drawLine(img, xs[i-1], ys[i-1], xs[i], ys[i], col)
	}
	return img
}

func interpY(xs, ys []int, x int) int {
	if x <= xs[0] {
		return ys[0]
	}
	last := len(xs) - 1
	if x >= xs[last] {
		return ys[last]
	}
	for i := 1; i < len(xs); i++ {
		if x <= xs[i] {
			x0, x1 := xs[i-1], xs[i]
			y0, y1 := ys[i-1], ys[i]
			if x1 == x0 {
				return y1
			}
			return y0 + (y1-y0)*(x-x0)/(x1-x0)
		}
	}
	return ys[last]
}

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.NRGBA) {
	dx := abs(x1 - x0)
	dy := -abs(y1 - y0)
	sx := 1
	if x0 > x1 {
		sx = -1
	}
	sy := 1
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	for {
		plot(img, x0, y0, c)
		plot(img, x0, y0+1, c) // 2px thickness
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func plot(img *image.RGBA, x, y int, c color.NRGBA) {
	b := img.Bounds()
	if x < b.Min.X || x >= b.Max.X || y < b.Min.Y || y >= b.Max.Y {
		return
	}
	img.SetRGBA(x, y, rgba(c))
}

func rgba(c color.NRGBA) color.RGBA {
	// Straight-alpha to premultiplied for image/draw storage.
	a := uint32(c.A)
	return color.RGBA{
		R: uint8(uint32(c.R) * a / 255),
		G: uint8(uint32(c.G) * a / 255),
		B: uint8(uint32(c.B) * a / 255),
		A: c.A,
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// nrgba coerces a palette token to NRGBA for the chart renderer.
func nrgba(c color.Color) color.NRGBA {
	if n, ok := c.(color.NRGBA); ok {
		return n
	}
	r, g, b, a := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
}

func blankImage() image.Image { return image.NewRGBA(image.Rect(0, 0, 1, 1)) }
