package guard

// Root-only ServiceAccount token provisioning and operator-side expiry checks.
//
// RenewServiceToken is a deliberately non-configurable helper: it accepts no
// arguments, reads only /etc/change-guard/kubeconfig and the administrator
// kubeconfig at /etc/kubernetes/admin.conf, and runs one fixed TokenRequest.
// The daemon/service user never invokes it and never receives administrator
// credentials.  The token value is never printed or included in errors.
//
// CheckTokenExpiry reads the token from a service kubeconfig, decodes the JWT
// payload locally, and reports whether it remains valid for at least the
// requested number of seconds.  It also never prints the token.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	rnServiceKubeconfigPath = "/etc/change-guard/kubeconfig"
	rnAdminKubeconfigPath   = "/etc/kubernetes/admin.conf"
	rnKubectlPath           = "/usr/bin/kubectl"
	rnServiceNamespace      = "change-guard"
	rnServiceAccount        = "change-guard"
	rnTokenTTL              = "12h"
	rnRequestTimeout        = 30
	rnMaxKubeconfigBytes    = 4 * 1024 * 1024
	rnMaxTokenBytes         = 64 * 1024
)

type rnRunner func() (string, error)
type rnLookup func(name string) (uid, gid int, err error)

type rnRenewOptions struct {
	kubeconfigPath string
	runner         rnRunner
	lookup         rnLookup
}

// CheckTokenExpiry reports the remaining lifetime of the JWT in a kubeconfig.
// status is "valid" when remaining_seconds > minRemaining, otherwise "rotate";
// the caller maps that to exit 0/1.  Pass an override for deterministic checks.
func CheckTokenExpiry(kubeconfig string, minRemaining int, nowOverride ...float64) (M, error) {
	if minRemaining < 0 {
		return nil, errors.New("min-remaining must be non-negative")
	}
	token, err := rnTokenFromKubeconfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	payload, err := rnDecodePayload(token)
	if err != nil {
		return nil, err
	}
	rawExpiry, exists := payload["exp"]
	if !exists {
		return nil, errors.New("token has no numeric exp claim")
	}
	expiry, valid := pdStrictNumber(rawExpiry)
	if !valid || math.IsNaN(expiry) || math.IsInf(expiry, 0) {
		return nil, errors.New("token has no numeric exp claim")
	}
	now := float64(time.Now().Unix())
	if len(nowOverride) > 0 {
		now = nowOverride[0]
		if math.IsNaN(now) || math.IsInf(now, 0) {
			return nil, errors.New("current time is invalid")
		}
	}
	remaining := int(expiry - now)
	status := "rotate"
	if remaining > minRemaining {
		status = "valid"
	}
	return M{
		"status":            status,
		"expires_at":        int64(expiry),
		"remaining_seconds": remaining,
	}, nil
}

// RenewServiceToken performs the fixed root-only TokenRequest.  It must run as
// root on the controller/control-plane host.  No arguments or environment
// commands are accepted.
func RenewServiceToken() (M, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root provisioning identity required")
	}
	return rnRenew(rnRenewOptions{
		kubeconfigPath: rnServiceKubeconfigPath,
		runner:         rnFixedTokenRequest,
		lookup:         rnLookupServiceAccount,
	})
}

func rnRenew(options rnRenewOptions) (M, error) {
	path := options.kubeconfigPath
	if path == "" {
		path = rnServiceKubeconfigPath
	}
	current, err := rnReadYAML(path)
	if err != nil {
		return nil, err
	}
	users := pdList(current["users"])
	if len(users) != 1 {
		return nil, errors.New("unexpected service kubeconfig structure")
	}
	firstUser, ok := users[0].(map[string]any)
	if !ok {
		return nil, errors.New("unexpected service kubeconfig structure")
	}
	runner := options.runner
	if runner == nil {
		runner = rnFixedTokenRequest
	}
	token, err := runner()
	if err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, "\r\n\x00") || strings.Count(token, ".") != 2 {
		return nil, errors.New("TokenRequest returned malformed credential")
	}
	firstUser["user"] = M{"token": token}
	users[0] = firstUser
	current["users"] = users
	encoded, err := yaml.Marshal(current)
	if err != nil {
		return nil, errors.New("service kubeconfig could not be encoded")
	}
	uid, gid := -1, -1
	lookup := options.lookup
	if lookup == nil {
		lookup = rnLookupServiceAccount
	}
	uid, gid, err = lookup("change-guard")
	if err != nil {
		return nil, errors.New("service account identity was not found")
	}
	if err := rnWriteAtomic(path, encoded, uid, gid); err != nil {
		return nil, err
	}
	return M{
		"renewed":            "change-guard/change-guard",
		"requested_lifetime": rnTokenTTL,
	}, nil
}

func rnFixedTokenRequest() (string, error) {
	contexted, cancel := context.WithTimeout(context.Background(), rnRequestTimeout*time.Second)
	defer cancel()
	command := exec.CommandContext(contexted, rnKubectlPath,
		"--kubeconfig="+rnAdminKubeconfigPath,
		"--request-timeout=20s",
		"-n", rnServiceNamespace,
		"create", "token", rnServiceAccount,
		"--duration="+rnTokenTTL,
	)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root"}
	command.Stdin = nil
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	if errors.Is(contexted.Err(), context.DeadlineExceeded) {
		return "", errors.New("fixed ServiceAccount TokenRequest timed out")
	}
	if runErr != nil {
		// Never echo kubectl stderr: a future failure mode could include
		// credential-adjacent data.  The operator can inspect the unit journal.
		_ = stderr
		return "", errors.New("fixed ServiceAccount TokenRequest failed")
	}
	if stdout.Len() > rnMaxTokenBytes {
		return "", errors.New("TokenRequest returned an oversized credential")
	}
	return strings.TrimSpace(stdout.String()), nil
}

func rnLookupServiceAccount(_ string) (int, int, error) {
	serviceUser, err := user.Lookup("change-guard")
	if err != nil {
		return 0, 0, err
	}
	serviceGroup, err := user.LookupGroup("change-guard")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(serviceUser.Uid)
	if err != nil {
		return 0, 0, errors.New("service account uid is invalid")
	}
	gid, err := strconv.Atoi(serviceGroup.Gid)
	if err != nil {
		return 0, 0, errors.New("service account gid is invalid")
	}
	return uid, gid, nil
}

func rnTokenFromKubeconfig(path string) (string, error) {
	config, err := rnReadYAML(path)
	if err != nil {
		return "", err
	}
	users := pdList(config["users"])
	if len(users) == 0 {
		return "", errors.New("kubeconfig has no users")
	}
	for _, item := range users {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		credentials, ok := entry["user"].(map[string]any)
		if !ok {
			continue
		}
		token, ok := credentials["token"].(string)
		if !ok {
			continue
		}
		token = strings.TrimSpace(token)
		if token != "" {
			return token, nil
		}
	}
	return "", errors.New("kubeconfig has no user token")
}

func rnReadYAML(path string) (M, error) {
	if path == "" {
		return nil, errors.New("kubeconfig path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read kubeconfig")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, errors.New("cannot read kubeconfig")
	}
	if stat.Size() > rnMaxKubeconfigBytes {
		return nil, errors.New("kubeconfig exceeds the size limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read kubeconfig")
	}
	if len(data) > rnMaxKubeconfigBytes {
		return nil, errors.New("kubeconfig exceeds the size limit")
	}
	var config M
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, errors.New("kubeconfig is invalid YAML")
	}
	if config == nil {
		return nil, errors.New("kubeconfig is not a mapping")
	}
	return config, nil
}

func rnDecodePayload(token string) (M, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	payload := parts[1]
	if padding := len(payload) % 4; padding != 0 {
		payload += strings.Repeat("=", 4-padding)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("token payload is not valid base64")
	}
	var value M
	if err := json.Unmarshal(decoded, &value); err != nil || value == nil {
		return nil, errors.New("token payload is not valid JSON")
	}
	return value, nil
}

func rnWriteAtomic(path string, data []byte, uid, gid int) error {
	directory := filepath.Dir(path)
	if directory == "" {
		directory = "."
	}
	temporary, err := os.CreateTemp(directory, ".kubeconfig-")
	if err != nil {
		return errors.New("cannot create a temporary kubeconfig")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	cleanup := func() {
		_ = temporary.Close()
	}
	if err := temporary.Chmod(0600); err != nil {
		cleanup()
		return errors.New("cannot set kubeconfig permissions")
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return errors.New("cannot write kubeconfig")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("cannot flush kubeconfig")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("cannot close kubeconfig")
	}
	if uid >= 0 && gid >= 0 {
		if err := os.Chown(temporaryPath, uid, gid); err != nil {
			return errors.New("cannot set kubeconfig ownership")
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("cannot replace kubeconfig")
	}
	return nil
}
