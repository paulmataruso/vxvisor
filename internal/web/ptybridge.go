package web

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// startPTY allocates a pseudo-terminal, starts cmd as its session leader with the
// slave as controlling TTY, and returns the master side. CGO-free (raw ioctls via
// x/sys/unix). Used for the LXC container console (an lxc-attach shell).
func startPTY(cmd *exec.Cmd, cols, rows int) (*os.File, error) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	// Unlock the slave (TIOCSPTLCK = 0) and find its number (TIOCGPTN).
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		ptmx.Close()
		return nil, err
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		ptmx.Close()
		return nil, err
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, err
	}
	defer slave.Close()
	if cols > 0 && rows > 0 {
		_ = setWinsize(ptmx, cols, rows)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		ptmx.Close()
		return nil, err
	}
	return ptmx, nil
}

func setWinsize(f *os.File, cols, rows int) error {
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
}

// bridgeWSPTY pipes a websocket (xterm.js) to a PTY master. Binary/text frames are
// keystrokes written to the PTY; a text frame that parses as {"resize":[c,r]} sets
// the window size instead (so full-screen TUIs render correctly).
func bridgeWSPTY(ws *websocket.Conn, ptmx *os.File) {
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done) }) }

	go func() { // PTY -> browser
		defer closeBoth()
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // browser -> PTY
		defer closeBoth()
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage {
				var msg struct {
					Resize []int `json:"resize"`
				}
				if json.Unmarshal(data, &msg) == nil && len(msg.Resize) == 2 {
					_ = setWinsize(ptmx, msg.Resize[0], msg.Resize[1])
					continue
				}
			}
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		}
	}()
	<-done
}
