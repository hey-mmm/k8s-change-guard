package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommonCredentialFailureDoesNotExposeSecret(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	secret := "test-only-synthetic-secret\nsecond-line"
	if e := os.WriteFile(p, []byte(secret), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := Token(M{"github_token_file": p}, "github")
	if e == nil {
		t.Fatal("multiline credential accepted")
	}
	if strings.Contains(e.Error(), "test-only-synthetic-secret") {
		t.Fatal("credential leaked in error")
	}
}

func TestCommonReportWriteRejectsNonObjectRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "report.json")
	if e := WriteJSON(p, M{"decision": "BLOCK", "head_sha": strings.Repeat("a", 40)}); e != nil {
		t.Fatal(e)
	}
	m, e := ReadJSON(p)
	if e != nil || S(m, "decision") != "BLOCK" {
		t.Fatalf("read persisted report: %v", e)
	}
	if e := os.WriteFile(p, []byte(`[]`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadJSON(p); e == nil {
		t.Fatal("array report accepted")
	}
}

func TestCommonPolicyDigestIsIndependentOfMapInsertionOrder(t *testing.T) {
	a := M{"approvers": []any{"owner"}, "threshold": 0.05, "source": "固定证据"}
	b := M{"source": "固定证据", "threshold": 0.05, "approvers": []any{"owner"}}
	if Hash(a) == "" || Hash(a) != Hash(b) {
		t.Fatal("noncanonical policy digest")
	}
}

func TestCommonConfigRejectsDuplicateKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, []byte("require_digest: true\nrequire_digest: false\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(p); e == nil {
		t.Fatal("ambiguous duplicate policy accepted")
	}
}

func TestExplicitEmptyModelResultFailsClosed(t *testing.T) {
	old, newer, evidence, config, context, _ := engTestFixture()
	config["ai_required"] = false
	missing := Evaluate(old, newer, evidence, config, context, nil)
	malformed := Evaluate(old, newer, evidence, config, context, M{})
	if S(missing, "decision") != "PASS" {
		t.Fatalf("absent optional model=%s", S(missing, "decision"))
	}
	if S(malformed, "decision") != "ERROR" {
		t.Fatalf("malformed empty model=%s", S(malformed, "decision"))
	}
}
