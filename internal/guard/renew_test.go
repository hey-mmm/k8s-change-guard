package guard

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func rnTestToken(expiry float64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(M{"exp": expiry, "sub": "system:serviceaccount:change-guard:change-guard"})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".signature"
}

func rnTestConfigFile(t *testing.T, token string) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n  - name: change-guard\n    cluster:\n      server: https://10.0.0.1:6443\n      certificate-authority-data: Y2E=\nusers:\n  - name: change-guard\n    user:\n      token: " + token + "\ncontexts:\n  - name: change-guard\n    context:\n      cluster: change-guard\n      user: change-guard\n      namespace: demo\ncurrent-context: change-guard\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRNCheckTokenExpiry(t *testing.T) {
	token := rnTestToken(pdTestNow + 7200)
	path := rnTestConfigFile(t, token)
	result, err := CheckTokenExpiry(path, 3600, pdTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if Str(result["status"]) != "valid" || N(result, "remaining_seconds") != 7200 {
		t.Fatalf("unexpected expiry result: %#v", result)
	}
	if N(result, "expires_at") != pdTestNow+7200 {
		t.Fatalf("unexpected expires_at: %#v", result)
	}
	// Exactly at the threshold is not "greater than", matching the Python helper.
	result, err = CheckTokenExpiry(path, 7200, pdTestNow)
	if err != nil || Str(result["status"]) != "rotate" {
		t.Fatalf("threshold should require rotation: %#v err=%v", result, err)
	}
	result, err = CheckTokenExpiry(path, 60, pdTestNow+7200)
	if err != nil || Str(result["status"]) != "rotate" {
		t.Fatalf("expired token should rotate: %#v err=%v", result, err)
	}
	if _, err := CheckTokenExpiry(path, -1, pdTestNow); err == nil {
		t.Fatal("negative min-remaining accepted")
	}
}

func TestRNCheckTokenExpiryFailures(t *testing.T) {
	path := rnTestConfigFile(t, "not-a-jwt")
	if _, err := CheckTokenExpiry(path, 60, pdTestNow); err == nil {
		t.Fatal("malformed JWT accepted")
	}
	path = rnTestConfigFile(t, rnTestToken(0))
	// A zero exp is numeric and therefore a valid (expired) claim.
	result, err := CheckTokenExpiry(path, 60, pdTestNow)
	if err != nil || Str(result["status"]) != "rotate" {
		t.Fatalf("zero exp should rotate: %#v err=%v", result, err)
	}

	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	if _, err := CheckTokenExpiry(missing, 60, pdTestNow); err == nil {
		t.Fatal("missing kubeconfig accepted")
	}
	noToken := filepath.Join(directory, "no-token")
	if err := os.WriteFile(noToken, []byte("apiVersion: v1\nusers:\n  - name: change-guard\n    user: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTokenExpiry(noToken, 60, pdTestNow); err == nil {
		t.Fatal("kubeconfig without token accepted")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"soon"}`))
	nonNumeric := rnTestConfigFile(t, header+"."+payload+".signature")
	if _, err := CheckTokenExpiry(nonNumeric, 60, pdTestNow); err == nil {
		t.Fatal("non-numeric exp accepted")
	}
}

func TestRNRenewUpdatesOnlyTokenAndPreservesCluster(t *testing.T) {
	path := rnTestConfigFile(t, rnTestToken(pdTestNow+100))
	newToken := rnTestToken(pdTestNow + 43200)
	callCount := 0
	options := rnRenewOptions{
		kubeconfigPath: path,
		runner: func() (string, error) {
			callCount++
			return newToken + "\n", nil
		},
		lookup: func(string) (int, int, error) { return -1, -1, nil },
	}
	result, err := rnRenew(options)
	if err != nil {
		t.Fatal(err)
	}
	if Str(result["renewed"]) != "change-guard/change-guard" || Str(result["requested_lifetime"]) != "12h" {
		t.Fatalf("unexpected renewal result: %#v", result)
	}
	if callCount != 1 {
		t.Fatalf("runner called %d times", callCount)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), rnTestToken(pdTestNow+100)) {
		t.Fatal("old token remains in kubeconfig")
	}
	if !strings.Contains(string(data), newToken) {
		t.Fatal("new token missing from kubeconfig")
	}
	var config M
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if S(config, "clusters", "0", "cluster", "server") != "https://10.0.0.1:6443" {
		t.Fatalf("server was not preserved: %#v", config["clusters"])
	}
	if S(config, "clusters", "0", "cluster", "certificate-authority-data") != "Y2E=" {
		t.Fatalf("CA was not preserved: %#v", config["clusters"])
	}
	if S(config, "current-context") != "change-guard" {
		t.Fatalf("current-context was not preserved: %#v", config["current-context"])
	}
	users := pdList(config["users"])
	if len(users) != 1 {
		t.Fatalf("unexpected users: %#v", users)
	}
	if S(config, "users", "0", "user", "token") != newToken {
		t.Fatal("token was not replaced")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
		t.Fatalf("unexpected kubeconfig mode: %o", stat.Mode().Perm())
	}
}

func TestRNRenewRefusesMalformedInputs(t *testing.T) {
	newToken := rnTestToken(pdTestNow + 43200)
	path := rnTestConfigFile(t, rnTestToken(pdTestNow+100))
	before, _ := os.ReadFile(path)
	options := rnRenewOptions{
		kubeconfigPath: path,
		runner:         func() (string, error) { return "not-a-jwt", nil },
		lookup:         func(string) (int, int, error) { return -1, -1, nil },
	}
	if _, err := rnRenew(options); err == nil {
		t.Fatal("malformed minted token accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("kubeconfig was modified after a malformed token")
	}

	directory := t.TempDir()
	twoUsers := filepath.Join(directory, "two-users")
	content := "users:\n  - name: a\n    user:\n      token: " + newToken + "\n  - name: b\n    user:\n      token: " + newToken + "\n"
	if err := os.WriteFile(twoUsers, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	options = rnRenewOptions{
		kubeconfigPath: twoUsers,
		runner: func() (string, error) {
			called = true
			return newToken, nil
		},
		lookup: func(string) (int, int, error) { return -1, -1, nil },
	}
	if _, err := rnRenew(options); err == nil {
		t.Fatal("multi-user kubeconfig accepted")
	}
	if called {
		t.Fatal("kubectl was invoked before structure validation")
	}
}

func TestRNTokenFromKubeconfigUsesFirstUsableUser(t *testing.T) {
	token := rnTestToken(pdTestNow + 100)
	path := rnTestConfigFile(t, token)
	found, err := rnTokenFromKubeconfig(path)
	if err != nil || found != token {
		t.Fatalf("unexpected token lookup: %q err=%v", found, err)
	}
}

func TestRNReadYAMLRejectsOversizedAndInvalid(t *testing.T) {
	directory := t.TempDir()
	invalid := filepath.Join(directory, "invalid")
	if err := os.WriteFile(invalid, []byte("users: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rnReadYAML(invalid); err == nil {
		t.Fatal("invalid YAML accepted")
	}
	scalar := filepath.Join(directory, "scalar")
	if err := os.WriteFile(scalar, []byte("just-a-string\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rnReadYAML(scalar); err == nil {
		t.Fatal("non-mapping kubeconfig accepted")
	}
}

func TestRNWriteAtomicMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "kubeconfig")
	if err := rnWriteAtomic(path, []byte("apiVersion: v1\n"), -1, -1); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
		t.Fatalf("unexpected mode: %o", stat.Mode().Perm())
	}
	if remaining, _ := filepath.Glob(filepath.Join(directory, ".kubeconfig-*")); len(remaining) != 0 {
		t.Fatalf("temporary files remain: %v", remaining)
	}
}

func TestRNExpiryUsesWallClockWhenNotOverridden(t *testing.T) {
	path := rnTestConfigFile(t, rnTestToken(float64(time.Now().Unix())+7200))
	result, err := CheckTokenExpiry(path, 60)
	if err != nil {
		t.Fatal(err)
	}
	if Str(result["status"]) != "valid" {
		t.Fatalf("future token should be valid: %#v", result)
	}
}
