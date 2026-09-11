//go:build linux || darwin

package terminal

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"unsafe"
)

// unixBackend 是 Linux 與 macOS 上的後端：/dev/ptmx 開一對虛擬終端機，
// 子行程用 setsid ＋ TIOCSCTTY 認領它當**控制終端機**。
//
// # 為什麼 Go 這裡比 TS 版簡單那麼多
//
// TS 版必須把自己重新 exec 一次（`__pty-child`）才有辦法在 fork 與 exec 之間
// 呼叫 login_tty —— bun 沒有那個掛勾，而在 bun 裡 fork() 會讓 JS runtime 當掉。
// Go 的 os/exec 本來就把 Setsid／Setctty 交給子行程去做（在 fork 之後、exec
// 之前，由 runtime 的 forkAndExecInChild 執行），所以不需要那一段再入的把戲。
//
// # 這一步不做會怎樣
//
// 沒有控制終端機的 shell 不會開 job control（`$-` 裡沒有 m）、不印互動式提示
// 字元，而且 line discipline 不會把 `\x03` 變成送給前景工作的 SIGINT ——
// 使用者按 Ctrl-C 什麼事都不會發生。這是「看起來開起來了但其實不是終端機」
// 的那種壞法，所以 Setctty 失敗要當作開啟失敗，不可以靜靜地繼續。
type unixBackend struct{}

func newPlatformBackend() (Backend, error) { return unixBackend{}, nil }

func (unixBackend) Name() string { return "pty" }

func (unixBackend) Open(spec Spec) (Handle, error) {
	if len(spec.Argv) == 0 {
		return nil, errf(CodeBadRequest, "沒有指定要跑哪一個程式")
	}
	master, slaveName, err := openPtmx()
	if err != nil {
		return nil, errf(CodeOpenFailed, "作業系統不給新的虛擬終端機：%v", err)
	}
	slave, err := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, errf(CodeOpenFailed, "開不了 %s：%v", slaveName, err)
	}

	// 視窗大小要在 shell 起來**之前**設好，否則它印出來的第一個提示字元是照
	// 80x24 排的，而畫面上那一格不是。
	if err := setWinsize(master, spec.Cols, spec.Rows); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, errf(CodeOpenFailed, "設不了視窗大小：%v", err)
	}

	cmd := &exec.Cmd{
		Path: spec.Argv[0],
		Args: spec.Argv,
		Dir:  spec.Cwd,
		Env:  envSlice(spec.Env),
		// 三個描述符都是 slave。子行程從 fd 0 認領它當控制終端機（Ctty: 0）。
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
		SysProcAttr: &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
			Ctty:    0,
		},
	}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, errf(CodeSpawnFailed, "起不了 %s：%v", spec.Argv[0], err)
	}
	// 父行程**立刻**放掉自己那一份 slave。留著的話，shell 結束時 master 永遠
	// 讀不到結束 —— 一個關掉的終端機會看起來像一個只是很安靜、而且永遠安靜的
	// 終端機。
	_ = slave.Close()

	return &unixPty{master: master, cmd: cmd, done: make(chan struct{})}, nil
}

type unixPty struct {
	master *os.File
	cmd    *exec.Cmd

	closeOnce sync.Once
	waitOnce  sync.Once
	done      chan struct{}
	exitCode  int
	waitErr   error
}

func (p *unixPty) Pid() int { return p.cmd.Process.Pid }

func (p *unixPty) Read(b []byte) (int, error) {
	n, err := p.master.Read(b)
	if err != nil && isEnd(err) {
		err = io.EOF
	}
	return n, err
}

func (p *unixPty) Write(b []byte) (int, error) {
	n, err := p.master.Write(b)
	if err != nil && isEnd(err) {
		// 打字給一個已經死掉的終端機不是錯誤，是沒有人聽見。
		return n, io.EOF
	}
	return n, err
}

// isEnd 判斷一個讀寫錯誤其實是「這個終端機結束了」。
//
// Linux 上，最後一個 slave 關掉之後讀 master 會拿到 EIO —— 那**就是**終端機的
// 結束，不是要回報的故障。macOS 回的是 EOF。兩個是同一件事。
func isEnd(err error) bool {
	return errors.Is(err, syscall.EIO) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.EOF)
}

func (p *unixPty) Resize(cols, rows int) error { return setWinsize(p.master, cols, rows) }

func (p *unixPty) SignalGroup(sig GroupSignal) error {
	pid := p.cmd.Process.Pid
	var s syscall.Signal
	switch sig {
	case SignalKill:
		s = syscall.SIGKILL
	case SignalTerm:
		s = syscall.SIGTERM
	default:
		s = syscall.SIGHUP
	}
	// 負的 pid ＝ 整個 process group，而那正是一個終端機的意思：shell **和**
	// 它啟動的一切。
	//
	// 這道防護不是理論上的：讓子行程自成一個 session 的是 Setsid，萬一它沒有
	// 成功，那個子行程還在**我們自己**的 group 裡，殺「它的」group 會反過來殺
	// 到我們。TS 版在 2026-09-06 量過：把 login_tty 拿掉之後，關掉一個終端機
	// 會把測試執行器一起帶走。
	if syscall.Getpgrp() == pid {
		return p.cmd.Process.Signal(s)
	}
	if err := syscall.Kill(-pid, s); err != nil {
		return p.cmd.Process.Signal(s)
	}
	return nil
}

func (p *unixPty) Wait() (int, error) {
	p.waitOnce.Do(func() {
		err := p.cmd.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
			p.exitCode = 0
		case errors.As(err, &ee):
			p.exitCode = ee.ExitCode()
		default:
			p.exitCode, p.waitErr = -1, err
		}
		close(p.done)
	})
	<-p.done
	return p.exitCode, p.waitErr
}

func (p *unixPty) Close() error {
	var err error
	p.closeOnce.Do(func() { err = p.master.Close() })
	return err
}

// winsize 是 struct winsize：**rows 在前**。把兩個換過來不會報錯，只會安靜地
// 給出錯的答案。
type winsize struct {
	rows, cols, xpixel, ypixel uint16
}

func setWinsize(f *os.File, cols, rows int) error {
	ws := winsize{rows: uint16(rows), cols: uint16(cols)}
	return ioctlPtr(f, syscall.TIOCSWINSZ, unsafe.Pointer(&ws))
}

// ioctlPtr 對一個 *os.File 做 ioctl，**不碰 f.Fd()**。
//
// f.Fd() 會把描述符切回阻塞模式並且從 runtime 的 poller 上拔掉，之後
// master.Close() 就叫不醒正卡在 Read 的那個 goroutine —— 症狀是關掉終端機
// 以後有一個 goroutine 永遠不會結束。SyscallConn().Control 借用描述符而不改
// 它的狀態，這是 Go 官方要求的做法。
func ioctlPtr(f *os.File, req uintptr, arg unsafe.Pointer) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioErr error
	if err := conn.Control(func(fd uintptr) {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
			ioErr = e
		}
	}); err != nil {
		return err
	}
	return ioErr
}

// ioctlVal 是參數不是指標、而是一個值的那種 ioctl（macOS 的 grantpt/unlockpt）。
func ioctlVal(f *os.File, req uintptr, value uintptr) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioErr error
	if err := conn.Control(func(fd uintptr) {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, value); e != 0 {
			ioErr = e
		}
	}); err != nil {
		return err
	}
	return ioErr
}

// envSlice 把 map 攤成 exec.Cmd 要的 KEY=VALUE，順序固定。
//
// 排序不是為了好看：一個順序會變的環境，會讓「同一個請求兩次跑出不同結果」
// 這種問題查不下去。
func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
