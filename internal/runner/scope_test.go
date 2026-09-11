package runner

import (
	"os"
	"path/filepath"
	"testing"
)

// 這一組測試存在的理由：Scope 是本機唯一的一道關卡。它放行了不該放行的東西，
// 使用者的整個磁碟就暴露了 —— 而那是雲端說了算的路徑，不是他自己打的。
func TestScope(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "work")
	secret := filepath.Join(base, "secret")
	for _, d := range []string{work, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(secret, "keys.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := NewScope([]string{work})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("授權目錄本身可以", func(t *testing.T) {
		if _, err := s.Resolve(work); err != nil {
			t.Fatalf("root itself rejected: %v", err)
		}
	})

	t.Run("底下的檔案可以", func(t *testing.T) {
		if _, err := s.Resolve(filepath.Join(work, "a", "b.txt")); err != nil {
			t.Fatalf("child rejected: %v", err)
		}
	})

	t.Run("還不存在的路徑也可以（建檔要用）", func(t *testing.T) {
		if _, err := s.Resolve(filepath.Join(work, "does", "not", "exist", "yet.txt")); err != nil {
			t.Fatalf("non-existent child rejected: %v", err)
		}
	})

	t.Run("外面的目錄不行", func(t *testing.T) {
		if _, err := s.Resolve(secret); err == nil {
			t.Fatal("sibling directory was allowed")
		}
	})

	t.Run("用 .. 爬出去不行", func(t *testing.T) {
		if _, err := s.Resolve(filepath.Join(work, "..", "secret", "keys.txt")); err == nil {
			t.Fatal("../ escape was allowed")
		}
	})

	t.Run("相對路徑一律拒絕", func(t *testing.T) {
		if _, err := s.Resolve("work/a.txt"); err == nil {
			t.Fatal("relative path was allowed")
		}
	})

	t.Run("字首相同但不是子目錄不行", func(t *testing.T) {
		// /base/work-other 的字串開頭是 /base/work —— 只比字首會誤放。
		other := filepath.Join(base, "work-other")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Resolve(filepath.Join(other, "x.txt")); err == nil {
			t.Fatal("prefix-sibling was allowed")
		}
	})

	t.Run("指向外面的 symlink 不行", func(t *testing.T) {
		link := filepath.Join(work, "escape")
		if err := os.Symlink(secret, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		if _, err := s.Resolve(filepath.Join(link, "keys.txt")); err == nil {
			t.Fatal("symlink escape was allowed")
		}
	})

	t.Run("沒有授權時全部拒絕", func(t *testing.T) {
		empty, err := NewScope(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !empty.Empty() {
			t.Fatal("expected empty scope")
		}
		if _, err := empty.Resolve(work); err == nil {
			t.Fatal("empty scope allowed a path")
		}
	})
}

// 授權目錄本身是 symlink 時，底下的路徑仍然要能用 —— 比對的兩邊都要解析過，
// 只解析一邊會讓每一個合法路徑都被判成越界。
func TestScopeRootIsSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	s, err := NewScope([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(filepath.Join(link, "a.txt")); err != nil {
		t.Fatalf("path under symlinked root rejected: %v", err)
	}
	if _, err := s.Resolve(filepath.Join(real, "a.txt")); err != nil {
		t.Fatalf("path under the real root rejected: %v", err)
	}
}
