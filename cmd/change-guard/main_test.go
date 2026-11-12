package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckTokenFlagsBeforeAndAfterPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2000}`)) + ".synthetic"
	data := "users:\n- name: guard\n  user:\n    token: " + token + "\n"
	if e := os.WriteFile(path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{path, "--min-remaining", "100", "--now", "1000"}, {"--min-remaining", "100", "--now", "1000", path}, {path, "--min-remaining=100", "--now=1000"}} {
		if code := cgCheckToken(args); code != 0 {
			t.Fatalf("valid token argument order %v exited %d", args, code)
		}
	}
	if code := cgCheckToken([]string{path, "--min-remaining", "1500", "--now", "1000"}); code != 1 {
		t.Fatalf("expiry threshold ignored: exit=%d", code)
	}
}
