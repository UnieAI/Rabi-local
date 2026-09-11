//go:build darwin

package terminal

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// openPtmx 在 macOS 上開一對虛擬終端機。
//
// 跟 Linux 不同的三件事，每一件都只有在 macOS 上才成立：
//
//   - 名字是問出來的（TIOCPTYGNAME），不是算出來的 —— macOS 沒有 /dev/pts/N
//     這種可預測的命名。
//   - grantpt 是一個 ioctl（TIOCPTYGRANT），不是 libc 裡那個會 fork 出
//     pt_chown 的函式。
//   - **順序是 ptsname → grant → unlock**，照 macOS 自己的 libc 來。
//
// 回傳的字串長度上限 128 是 TIOCPTYGNAME 這個 ioctl 編碼裡帶的參數長度
// （_IOC_PARM_LEN(0x40807453) == 128）。
func openPtmx() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	fail := func(err error) (*os.File, string, error) {
		_ = master.Close()
		return nil, "", err
	}
	buf := make([]byte, 128)
	if err := ioctlPtr(master, syscall.TIOCPTYGNAME, unsafe.Pointer(&buf[0])); err != nil {
		return fail(err)
	}
	name := ""
	for i, c := range buf {
		if c == 0 {
			name = string(buf[:i])
			break
		}
	}
	if name == "" {
		return fail(errors.New("TIOCPTYGNAME 回的字串沒有結尾的 NUL"))
	}
	if err := ioctlVal(master, syscall.TIOCPTYGRANT, 0); err != nil {
		return fail(err)
	}
	if err := ioctlVal(master, syscall.TIOCPTYUNLK, 0); err != nil {
		return fail(err)
	}
	return master, name, nil
}
