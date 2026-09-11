//go:build linux

package terminal

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// openPtmx 在 Linux 上開一對虛擬終端機。
//
// 順序是 unlockpt 再 ptsname —— 反過來也拿得到名字，但那個裝置還鎖著，開它會
// 失敗，而失敗的訊息（EIO）跟「這台機器沒有 devpts」長得一模一樣。
func openPtmx() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	var zero int32
	if err := ioctlPtr(master, syscall.TIOCSPTLCK, unsafe.Pointer(&zero)); err != nil {
		_ = master.Close()
		return nil, "", err
	}
	var n uint32
	if err := ioctlPtr(master, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		_ = master.Close()
		return nil, "", err
	}
	return master, "/dev/pts/" + strconv.FormatUint(uint64(n), 10), nil
}
