package qemu

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ProgressFunc receives a 0..1 completion fraction during a long qemu-img copy.
type ProgressFunc func(frac float64)

// qemu-img -p redraws a line like "    (41.52/100%)" (carriage-return separated).
var reImgProgress = regexp.MustCompile(`\(\s*([0-9]+(?:\.[0-9]+)?)/100%\)`)

// runImgProgress runs `qemu-img <args>`. When onProg is nil it behaves like a
// plain blocking convert (combined output on error). When onProg is set, the
// caller must have included "-p"; this streams stdout and reports the fraction.
func runImgProgress(onProg ProgressFunc, args ...string) error {
	cmd := exec.Command("qemu-img", args...)
	if onProg == nil {
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Split(scanLinesOrCR)
	for sc.Scan() {
		if mm := reImgProgress.FindStringSubmatch(sc.Text()); mm != nil {
			if f, e := strconv.ParseFloat(mm[1], 64); e == nil {
				onProg(f / 100)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(errbuf.String()))
	}
	onProg(1)
	return nil
}

// scanLinesOrCR is a bufio.SplitFunc that breaks on \n OR \r, so qemu-img's
// carriage-return progress redraws each surface as their own token.
func scanLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i, b := range data {
		if b == '\n' || b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// withProgress inserts "-p" right after the "convert" verb when a progress sink
// is wired, so the same arg list serves both the plain and reporting paths.
func withProgress(onProg ProgressFunc, args []string) []string {
	if onProg == nil || len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, args[0], "-p")
	return append(out, args[1:]...)
}
