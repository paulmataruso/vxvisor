//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// applyUpdate replaces the running binary on Windows.
//
// A running .exe cannot be overwritten in-process (its path is locked while the
// image is mapped), so we hand off to a detached batch helper and exit
// IMMEDIATELY. Because we exit before the helper does the swap, the lock is
// released and the helper's move always lands on an unlocked file — there is no
// in-process file operation that can fail and leave us running the old binary.
//
// The helper:
//   1. retries `move /Y <new> <exe>` until it succeeds (the move fails while the
//      old process is still shutting down, so the loop doubles as "wait for the
//      lock to clear"), up to ~30 tries,
//   2. relaunches the new exe,
//   3. logs every step to <exe>.update.log for post-mortem,
//   4. deletes itself.
func applyUpdate(newPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, e := filepath.EvalSymlinks(exe); e == nil {
		exe = r
	}
	log := exe + ".update.log"
	bat := exe + ".update.bat"

	// %%~f0 is the batch's own path (for self-delete). Everything is logged so a
	// failed swap leaves evidence next to the exe instead of a silent loop.
	script := fmt.Sprintf(`@echo off
echo [%%date%% %%time%%] update helper start >"%s"
echo new="%s" >>"%s"
echo exe="%s" >>"%s"
ping -n 3 127.0.0.1 >nul
set /a tries=0
:retry
move /Y "%s" "%s" >>"%s" 2>&1
if not exist "%s" goto done
set /a tries+=1
echo swap not yet (try %%tries%%), file still locked >>"%s"
if %%tries%% geq 30 (echo GAVE UP after %%tries%% tries >>"%s" & goto launch)
ping -n 2 127.0.0.1 >nul
goto retry
:done
echo swap OK after %%tries%% tries >>"%s"
:launch
echo relaunching "%s" >>"%s"
start "" "%s"
echo [%%date%% %%time%%] done >>"%s"
del "%%~f0"
`,
		log, // start
		newPath, log, exe, log, // new/exe
		newPath, exe, log, // move
		newPath,      // if exist
		log,          // not yet
		log,          // gave up
		log,          // swap ok
		exe, log,     // relaunching
		exe,          // start
		log,          // done
	)
	if err := os.WriteFile(bat, []byte(script), 0o644); err != nil {
		return err
	}

	cmd := exec.Command("cmd", "/C", bat)
	// CREATE_NO_WINDOW (0x08000000) ONLY — no visible console for the helper or
	// its `ping` sleep. (Do NOT also set DETACHED_PROCESS 0x8: the two are
	// mutually exclusive, and combining them makes Windows ignore the no-window
	// request and pop a console. The child still outlives us without it.)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		os.Remove(bat)
		return err
	}
	os.Exit(0)
	return nil
}
