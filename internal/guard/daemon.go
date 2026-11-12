package guard

// Reliable GitHub gate daemon.
//
// The daemon polls every open pull request whose base is the configured main
// branch. For every pull request, including code-only changes, it renders the
// exact base and head snapshots, collects fresh read-only evidence, runs the
// trusted evaluator and DeepSeek review, stores an immutable report, and
// publishes the required change-guard/release commit status.
//
// Design constraints:
//   - Pending status is published before expensive work.
//   - Status success is possible only for PASS, or for REVIEW with a
//     *currently valid* manual approval. BLOCK is failure, evaluation failure
//     is error.
//   - Before success is published, the head SHA and current base branch tip are
//     re-read from GitHub. A changed SHA/base, an expired report, or a revoked
//     approval invalidates the old status and forces re-evaluation.
//   - Approval is the exact comment "/guard approve <evaluation_id>" from a
//     configured approver with *current* write/admin permission. For a personal
//     repository the current owner is proven from repository metadata.
//   - Reports are written atomically and may never be overwritten.
//   - A failure for one pull request is isolated.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	daemonSchemaVersion       = 2
	daemonPolicySchemaVersion = 1
	daemonMaxReportBytes      = 8 * 1024 * 1024
	daemonMaxIndexBytes       = 4 * 1024 * 1024
	daemonMaxApprovers        = 100
	daemonMaxPollSeconds      = 3600
	daemonDefaultPollSeconds  = 30
	daemonDefaultEvidenceTTL  = 300
	daemonStatusDetailLimit   = 140
	daemonChartPathPrefix     = "charts/demo/"
	daemonWorkflowPathPrefix  = ".github/workflows/"
	daemonApprovalSkewSeconds = 0
	daemonDefaultMaxOpenPRs   = 2000
	daemonMaxCredentialScopes = 100
	daemonMaxReportFindings   = 5000
	daemonReportState         = "index.json"
)

var daemonSeverityRank = map[string]int{"BLOCK": 3, "ERROR": 2, "REVIEW": 1}

// Only these config keys participate in the report policy binding. Credential
// locations/values, state paths, and polling knobs are deliberately excluded.
var daemonPolicyConfigKeys = []string{
	"repository",
	"base_branch",
	"status_context",
	"namespace",
	"deployment",
	"release_name",
	"allowed_image_repository",
	"require_digest",
	"approvers",
	"allow_fork_prs",
	"ai_required",
	"allow_pre_rendered",
	"renderer_mode",
	"approved_chart_digest",
	"merge_required_ci",
	"evidence_ttl_seconds",
	"render_timeout_seconds",
	"render_output_limit_bytes",
	"sandbox_memory_bytes",
	"sandbox_tmpfs_bytes",
	"kube_version",
	"kubeconfig",
	"kubectl",
	"helm",
	"bwrap",
	"knowledge_dir",
	"deepseek_model",
	"deepseek_url",
	"deepseek_timeout_seconds",
	"deepseek_total_timeout_seconds",
	"deepseek_max_response_bytes",
	"prometheus_url",
	"demo_url",
	"kubectl_timeout_seconds",
	"prometheus_timeout_seconds",
	"kubectl_max_output_bytes",
	"prometheus_max_response_bytes",
	"max_error_ratio",
	"max_p95_seconds",
	"memory_headroom_factor",
	"low_traffic_rps",
	"min_request_rate",
	"observation_seconds",
	"postdeploy_timeout_seconds",
	"postdeploy_poll_seconds",
	"require_pod_image_id",
	"strict_image_id_digest",
	"version_path",
	"ready_path",
	"argocd_namespace",
	"argo_application",
	"container_name",
}

var daemonRedactKeyParts = []string{
	"token", "secret", "password", "passwd", "authorization", "credential",
	"private_key", "privatekey", "api_key", "apikey", "kubeconfig_data", "cookie",
}

var (
	daemonApprovalIDRE = regexp.MustCompile(`\Aev-[0-9a-f]{16,64}\z`)
	daemonReportNameRE = regexp.MustCompile(`\Aev-[0-9a-f]{16,64}\.json\z`)
	daemonSafeErrorRE  = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	daemonDNSLabelRE   = regexp.MustCompile(`\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z`)
	daemonHex64RE      = regexp.MustCompile(`\A[0-9a-fA-F]{64}\z`)
	daemonSHARegex     = regexp.MustCompile(`\A[0-9a-f]{40,64}\z`)
)

// DaemonError is a fail-closed daemon configuration/state error.
type DaemonError struct{ Message string }

func (e *DaemonError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeText(e.Message, 800)
}

// DaemonBusyError reports that another daemon instance holds the state lock.
type DaemonBusyError struct{ Message string }

func (e *DaemonBusyError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeText(e.Message, 800)
}

func daemonErrorf(format string, args ...any) error {
	return &DaemonError{Message: fmt.Sprintf(format, args...)}
}

func daemonSafeText(value any, limit int) string {
	text := sanitizeText(value, limit)
	return daemonSafeErrorRE.ReplaceAllString(text, " ")
}

func daemonNowInt(clock func() int64) (int64, error) {
	value := clock()
	return value, nil
}

func daemonTime(value any) (int64, bool) {
	if value == nil {
		return 0, false
	}
	if number, ok := ghNumber(value); ok {
		return int64(number), true
	}
	if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
		if number, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
			return int64(number), true
		}
		return ghParseTime(text)
	}
	return 0, false
}

func daemonDecisionFromFindings(findings []M) string {
	severity := map[string]bool{}
	for _, finding := range findings {
		if value, ok := finding["severity"].(string); ok {
			severity[value] = true
		}
	}
	if severity["BLOCK"] {
		return "BLOCK"
	}
	if severity["ERROR"] {
		return "ERROR"
	}
	if severity["REVIEW"] {
		return "REVIEW"
	}
	return "PASS"
}

func daemonSanitizeValue(value any, depth int, key string) any {
	if depth > 12 {
		return "<depth-limit>"
	}
	lowered := strings.ToLower(key)
	for _, part := range daemonRedactKeyParts {
		if strings.Contains(lowered, part) {
			return "<redacted>"
		}
	}
	switch node := value.(type) {
	case map[string]any:
		result := M{}
		index := 0
		for childKey, child := range node {
			if index >= 500 {
				break
			}
			result[fmt.Sprint(childKey)] = daemonSanitizeValue(child, depth+1, fmt.Sprint(childKey))
			index++
		}
		return result
	case []any:
		limit := len(node)
		if limit > 2000 {
			limit = 2000
		}
		result := make([]any, limit)
		for index, child := range node[:limit] {
			result[index] = daemonSanitizeValue(child, depth+1, key)
		}
		return result
	case []string:
		// Bounded string slices such as changed_paths/workflow_paths must stay
		// arrays in the immutable report. Falling through to the default case
		// would stringify them and silently erase security-relevant paths.
		limit := len(node)
		if limit > 2000 {
			limit = 2000
		}
		result := make([]any, limit)
		for index, child := range node[:limit] {
			result[index] = daemonSafeText(child, 8000)
		}
		return result
	case []M:
		limit := len(node)
		if limit > 2000 {
			limit = 2000
		}
		result := make([]any, limit)
		for index, child := range node[:limit] {
			result[index] = daemonSanitizeValue(child, depth+1, key)
		}
		return result
	case string:
		return daemonSafeText(node, 8000)
	case float64:
		if math.IsNaN(node) || math.IsInf(node, 0) {
			return nil
		}
		return node
	case float32:
		number := float64(node)
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil
		}
		return number
	case nil, bool, int, int8, int16, int32, int64, uint, uint64:
		return value
	default:
		return daemonSafeText(node, 2000)
	}
}

// ---------------------------------------------------------------------------
// State store

type stateStore struct {
	root         string
	reportsDir   string
	approvalsDir string
	indexPath    string
	lockPath     string
}

func newStateStore(stateDir string) (*stateStore, error) {
	if strings.TrimSpace(stateDir) == "" || strings.ContainsRune(stateDir, 0) {
		return nil, daemonErrorf("state_dir must be a non-empty path")
	}
	root, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, daemonErrorf("state_dir is invalid")
	}
	store := &stateStore{
		root:         root,
		reportsDir:   filepath.Join(root, "reports"),
		approvalsDir: filepath.Join(root, "approvals"),
		indexPath:    filepath.Join(root, daemonReportState),
		lockPath:     filepath.Join(root, ".daemon.lock"),
	}
	for _, directory := range []string{store.root, store.reportsDir, store.approvalsDir} {
		if err = os.MkdirAll(directory, 0700); err != nil {
			return nil, daemonErrorf("cannot create state directory")
		}
	}
	return store, nil
}

func (s *stateStore) reportPath(evaluationID string) (string, error) {
	if !daemonApprovalIDRE.MatchString(evaluationID) {
		return "", daemonErrorf("evaluation id is invalid")
	}
	return filepath.Join(s.reportsDir, evaluationID+".json"), nil
}

func (s *stateStore) readReport(evaluationID string) (M, error) {
	path, err := s.reportPath(evaluationID)
	if err != nil {
		return nil, err
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, daemonErrorf("cannot read report: report is unavailable")
	}
	if info.Size() > daemonMaxReportBytes {
		return nil, daemonErrorf("report exceeds the size limit")
	}
	report, err := ReadJSON(path)
	if err != nil {
		return nil, daemonErrorf("report is invalid JSON")
	}
	return report, nil
}

func (s *stateStore) writeReport(report M) (string, bool, error) {
	evaluationID := Str(report["evaluation_id"])
	path, err := s.reportPath(evaluationID)
	if err != nil {
		return "", false, daemonErrorf("report has an invalid evaluation id")
	}
	encoded, encodeErr := CanonicalJSON(report)
	if encodeErr != nil {
		return "", false, daemonErrorf("report is not JSON serializable")
	}
	if len(encoded) > daemonMaxReportBytes {
		return "", false, daemonErrorf("evaluation report exceeds the size limit")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		existing, readErr := s.readReport(evaluationID)
		if readErr != nil {
			return "", false, readErr
		}
		existingEncoded, _ := CanonicalJSON(existing)
		if string(existingEncoded) == string(encoded) {
			return path, false, nil
		}
		return "", false, daemonErrorf("immutable report id collision with different content")
	}
	created, writeErr := daemonAtomicJSON(path, report, false)
	if writeErr != nil {
		return "", false, writeErr
	}
	if !created {
		existing, readErr := s.readReport(evaluationID)
		if readErr != nil {
			return "", false, readErr
		}
		existingEncoded, _ := CanonicalJSON(existing)
		if string(existingEncoded) != string(encoded) {
			return "", false, daemonErrorf("immutable report id collision with different content")
		}
	}
	return path, created, nil
}

func (s *stateStore) writeApproval(record M) (string, error) {
	evaluationID := Str(record["evaluation_id"])
	if !daemonApprovalIDRE.MatchString(evaluationID) {
		return "", daemonErrorf("approval has an invalid evaluation id")
	}
	commentID, ok := ghInt(record["comment_id"])
	if !ok || commentID < 1 {
		return "", daemonErrorf("approval has an invalid comment id")
	}
	path := filepath.Join(s.approvalsDir, fmt.Sprintf("%s-%d.json", evaluationID, commentID))
	if _, err := daemonAtomicJSON(path, record, false); err != nil {
		return "", err
	}
	return path, nil
}

func (s *stateStore) loadIndex() (M, error) {
	if _, err := os.Stat(s.indexPath); os.IsNotExist(err) {
		return M{"schema_version": daemonSchemaVersion, "prs": M{}}, nil
	}
	info, err := os.Stat(s.indexPath)
	if err != nil {
		return nil, daemonErrorf("cannot read state index")
	}
	if info.Size() > daemonMaxIndexBytes {
		return nil, daemonErrorf("state index exceeds the size limit")
	}
	index, err := ReadJSON(s.indexPath)
	if err != nil {
		return nil, daemonErrorf("state index is invalid JSON")
	}
	if _, ok := index["prs"]; !ok {
		index["prs"] = M{}
	}
	if _, ok := index["prs"].(map[string]any); !ok {
		return nil, daemonErrorf("state index has an invalid schema")
	}
	if _, ok := index["schema_version"]; !ok {
		index["schema_version"] = daemonSchemaVersion
	}
	return index, nil
}

func (s *stateStore) saveIndex(index M) error {
	return daemonWriteIndex(s.indexPath, index)
}

func daemonWriteIndex(path string, index M) error {
	_, err := daemonAtomicJSON(path, index, true)
	return err
}

func daemonAtomicJSON(path string, payload M, overwrite bool) (bool, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return false, daemonErrorf("cannot create state directory")
	}
	encoded, err := jsonMarshalIndented(payload)
	if err != nil {
		return false, daemonErrorf("state payload is not JSON serializable")
	}
	if len(encoded) > daemonMaxReportBytes {
		return false, daemonErrorf("state payload exceeds the report size limit")
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return false, daemonErrorf("cannot create temporary state file")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(encoded)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return false, daemonErrorf("cannot write temporary state file")
	}
	if closeErr != nil {
		return false, daemonErrorf("cannot close temporary state file")
	}
	if overwrite {
		if err = os.Rename(temporaryName, path); err != nil {
			// Windows cannot replace an existing file atomically with Rename.
			if removeErr := os.Remove(path); removeErr == nil {
				err = os.Rename(temporaryName, path)
			}
		}
		if err != nil {
			return false, daemonErrorf("cannot replace state file")
		}
		return true, nil
	}
	if err = os.Link(temporaryName, path); err == nil {
		return true, nil
	}
	if _, statErr := os.Stat(path); statErr == nil {
		return false, nil
	}
	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if openErr != nil {
		if os.IsExist(openErr) {
			return false, nil
		}
		return false, daemonErrorf("cannot create state file")
	}
	writeErr := func() error {
		if _, err := file.Write(encoded); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		return file.Close()
	}()
	if writeErr != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return false, daemonErrorf("cannot write state file")
	}
	return true, nil
}

func jsonMarshalIndented(value any) ([]byte, error) {
	// Reports are stored human-readable, but their canonical digest covers the
	// same value with sorted keys and no insignificant whitespace.
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func (s *stateStore) lock() (func(), error) {
	if err := os.MkdirAll(s.root, 0700); err != nil {
		return nil, daemonErrorf("cannot create state directory")
	}
	file, err := daemonPlatformLock(s.lockPath)
	if err != nil {
		if err == errDaemonStateLockBusy {
			return nil, &DaemonBusyError{Message: "another change-guard daemon is already running"}
		}
		return nil, daemonErrorf("cannot acquire state lock")
	}
	// The lock file itself is intentionally left in place. The exclusivity is
	// owned by the kernel advisory lock held on this descriptor, so SIGTERM,
	// SIGKILL, or a reboot releases it without any stale-lock cleanup. Never
	// remove the file: doing so can unlink another waiter's lock inode and
	// would break compatibility with the Python fcntl.flock lock file.
	release := func() { _ = daemonLockReleasedByKernel(file) }
	return release, nil
}

// ---------------------------------------------------------------------------
// Configuration / policy binding

func daemonValidateConfig(config M) (M, error) {
	if config == nil {
		return nil, daemonErrorf("config must be a mapping")
	}
	value := M{}
	for key, item := range config {
		value[key] = item
	}
	repository, ok := value["repository"].(string)
	if !ok || !ghRepoRE.MatchString(repository) {
		return nil, daemonErrorf("repository must be in owner/name form")
	}
	owner, name, _ := strings.Cut(repository, "/")
	if owner == "." || owner == ".." || name == "." || name == ".." {
		return nil, daemonErrorf("repository is invalid")
	}
	value["repository"] = repository

	baseBranch, err := ghValidateBranch(ifEmpty(CfgString(value, "base_branch", "main"), "main"))
	if err != nil {
		return nil, daemonErrorf("%s", err.Error())
	}
	statusContext, err := ghSanitizeStatusContext(CfgString(value, "status_context", "change-guard/release"))
	if err != nil {
		return nil, daemonErrorf("%s", err.Error())
	}
	value["base_branch"] = baseBranch
	value["status_context"] = statusContext

	stateDir := CfgString(value, "state_dir", "")
	if strings.TrimSpace(stateDir) == "" || strings.ContainsRune(stateDir, 0) {
		return nil, daemonErrorf("state_dir must be a non-empty path")
	}
	absoluteStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, daemonErrorf("state_dir must be a non-empty path")
	}
	value["state_dir"] = absoluteStateDir

	poll := CfgNum(value, "poll_seconds", daemonDefaultPollSeconds)
	if math.IsNaN(poll) || math.IsInf(poll, 0) || poll < 1 || poll > daemonMaxPollSeconds {
		return nil, daemonErrorf("poll_seconds must be between 1 and %d", daemonMaxPollSeconds)
	}
	value["poll_seconds"] = poll

	ttlValue, present := value["evidence_ttl_seconds"]
	if !present {
		ttlValue = daemonDefaultEvidenceTTL
	}
	ttl, ok := daemonIntStrict(ttlValue)
	if !ok || ttl < 30 || ttl > 86400 {
		return nil, daemonErrorf("evidence_ttl_seconds must be an integer between 30 and 86400")
	}
	value["evidence_ttl_seconds"] = ttl

	approvers := []string{}
	if raw, exists := value["approvers"]; exists && raw != nil {
		items, ok := daemonStringList(raw)
		if !ok || len(items) > daemonMaxApprovers {
			return nil, daemonErrorf("approvers must be a bounded list")
		}
		for _, item := range items {
			login, loginErr := ghValidateLogin(item)
			if loginErr != nil {
				return nil, daemonErrorf("%s", loginErr.Error())
			}
			if !containsString(approvers, login) {
				approvers = append(approvers, login)
			}
		}
	}
	value["approvers"] = approvers

	for _, key := range []string{"namespace", "deployment"} {
		item := CfgString(value, key, "demo")
		if !daemonDNSLabelRE.MatchString(item) {
			return nil, daemonErrorf("%s is not a valid Kubernetes DNS label", key)
		}
		value[key] = item
	}
	allowedRepo := CfgString(value, "allowed_image_repository", "ghcr.io/hey-mmm/observability-demo")
	if strings.TrimSpace(allowedRepo) == "" || strings.IndexFunc(allowedRepo, unicode.IsSpace) >= 0 {
		return nil, daemonErrorf("allowed_image_repository is invalid")
	}
	value["allowed_image_repository"] = strings.TrimSpace(allowedRepo)

	digests, err := daemonNormalizedDigestList(value["approved_chart_digest"], "approved_chart_digest")
	if err != nil {
		return nil, err
	}
	value["approved_chart_digest"] = digests

	for _, key := range []string{"ai_required", "allow_fork_prs", "report_comment", "use_proxy_env", "require_verified_status_write"} {
		if raw, exists := value[key]; exists {
			if _, isBool := raw.(bool); !isBool {
				return nil, daemonErrorf("%s must be boolean", key)
			}
		}
	}
	daemonDefaultBool(value, "ai_required", true)
	daemonDefaultBool(value, "allow_fork_prs", false)
	daemonDefaultBool(value, "report_comment", false)
	daemonDefaultBool(value, "use_proxy_env", true)
	daemonDefaultBool(value, "require_verified_status_write", false)

	if raw, exists := value["credential_probe_sha"]; exists && raw != nil {
		text, isStr := raw.(string)
		if !isStr || !daemonSHARegex.MatchString(text) {
			return nil, daemonErrorf("credential_probe_sha must be a hexadecimal Git SHA or null")
		}
	}
	if raw, exists := value["status_target_url"]; exists && raw != nil {
		text, isStr := raw.(string)
		if !isStr || !strings.HasPrefix(text, "https://") {
			return nil, daemonErrorf("status_target_url must be an HTTPS URL")
		}
	}
	if raw, exists := value["max_open_prs"]; exists {
		number, isInt := daemonIntStrict(raw)
		if !isInt || number < 1 || number > 100000 {
			return nil, daemonErrorf("max_open_prs must be a bounded positive integer")
		}
		value["max_open_prs"] = number
	}
	return value, nil
}

func daemonDefaultBool(config M, key string, fallback bool) {
	if _, exists := config[key]; !exists {
		config[key] = fallback
	}
}

func daemonIntStrict(value any) (int64, bool) {
	if number, ok := ghInt(value); ok {
		return number, true
	}
	if number, ok := ghNumber(value); ok && number == math.Trunc(number) {
		return int64(number), true
	}
	return 0, false
}

func daemonStringList(value any) ([]string, bool) {
	switch items := value.(type) {
	case []string:
		return append([]string(nil), items...), true
	case []any:
		result := make([]string, 0, len(items))
		for _, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	case string:
		return []string{items}, true
	}
	return nil, false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func daemonNormalizedDigestList(value any, field string) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	items, ok := daemonStringList(value)
	if !ok {
		return nil, daemonErrorf("%s must be a SHA-256 hex string or a list of them", field)
	}
	cleaned := []string{}
	for _, item := range items {
		if !daemonHex64RE.MatchString(item) {
			return nil, daemonErrorf("%s entries must be 64-character SHA-256 hex strings", field)
		}
		lowered := strings.ToLower(item)
		if !containsString(cleaned, lowered) {
			cleaned = append(cleaned, lowered)
		}
	}
	sort.Strings(cleaned)
	return cleaned, nil
}

func daemonPolicyConfigSnapshot(config M) (M, error) {
	if config == nil {
		return nil, daemonErrorf("config must be a mapping")
	}
	snapshot := M{}
	for _, key := range daemonPolicyConfigKeys {
		value, exists := config[key]
		if !exists {
			continue
		}
		switch key {
		case "approvers", "approved_chart_digest":
			items, ok := daemonStringList(value)
			if !ok {
				return nil, daemonErrorf("%s is invalid", key)
			}
			sorted := append([]string(nil), items...)
			sort.Strings(sorted)
			snapshot[key] = sorted
		case "merge_required_ci":
			snapshot[key] = fmt.Sprint(value)
		default:
			snapshot[key] = value
		}
	}
	return snapshot, nil
}

func daemonPolicyDigest(config M) (string, error) {
	snapshot, err := daemonPolicyConfigSnapshot(config)
	if err != nil {
		return "", err
	}
	return Hash(M{"policy_schema_version": daemonPolicySchemaVersion, "config": snapshot}), nil
}

func daemonCurrentPolicyBinding(config M) (M, error) {
	digest, err := daemonPolicyDigest(config)
	if err != nil {
		return nil, err
	}
	return M{
		"guard_version":         Version,
		"rule_version":          RuleVersion,
		"policy_schema_version": daemonPolicySchemaVersion,
		"policy_digest":         digest,
	}, nil
}

func daemonReportDigestMatches(report M) bool {
	if report == nil {
		return false
	}
	digest := Str(report["report_digest"])
	if !regexp.MustCompile(`\A[0-9a-f]{64}\z`).MatchString(digest) {
		return false
	}
	clone := M{}
	for key, value := range report {
		if key != "report_digest" {
			clone[key] = value
		}
	}
	encoded, err := CanonicalJSON(clone)
	if err != nil {
		return false
	}
	return HashBytes(encoded) == digest
}

// HashBytes returns sha256 hex of raw bytes. Kept local to avoid changing the
// shared common helper surface.
func HashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func daemonPriority(decision string) int {
	switch decision {
	case "PASS":
		return 0
	case "REVIEW":
		return 1
	case "ERROR":
		return 2
	case "BLOCK":
		return 3
	default:
		return 2
	}
}

// ---------------------------------------------------------------------------
// Daemon

type daemonGitHubAPI interface {
	VerifyCredentials(string) (M, error)
	ListOpenPullRequests(string, int, int) ([]PullRequestInfo, error)
	GetPullRequest(int64) (PullRequestInfo, error)
	GetBranchHead(string) (string, error)
	FetchPullRequestCandidate(int64, bool) (PullRequestCandidate, error)
	ListIssueComments(int64) ([]M, error)
	GetRepositoryIdentity() (M, error)
	GetUserPermission(string) (string, error)
	CreateCommitStatus(string, string, string, string, string) (M, error)
	CreateIssueComment(int64, string) (M, error)
}

type guardDaemon struct {
	config   M
	github   daemonGitHubAPI
	concrete *GitHub
	store    *stateStore
	render   func(string, M) ([]M, error)
	collect  func(M) M
	analyze  func(M, M) M
	evaluate func([]M, []M, M, M, M, M) M
	now      func() int64
	sleep    func(time.Duration)
}

func newGuardDaemon(config M) (*guardDaemon, error) {
	validated, err := daemonValidateConfig(config)
	if err != nil {
		return nil, err
	}
	github, err := NewGitHub(validated)
	if err != nil {
		return nil, err
	}
	return newGuardDaemonWith(validated, github, github)
}

func newGuardDaemonWith(config M, api daemonGitHubAPI, concrete *GitHub) (*guardDaemon, error) {
	if api == nil {
		return nil, daemonErrorf("github client is missing")
	}
	store, err := newStateStore(CfgString(config, "state_dir", ""))
	if err != nil {
		return nil, err
	}
	return &guardDaemon{
		config:   config,
		github:   api,
		concrete: concrete,
		store:    store,
		render:   RenderTree,
		collect:  Collect,
		analyze:  Analyze,
		evaluate: Evaluate,
		now:      Now,
		sleep:    time.Sleep,
	}, nil
}

func (d *guardDaemon) renderConfig() M {
	config := M{}
	for key, value := range d.config {
		config[key] = value
	}
	config["namespace"] = CfgString(d.config, "namespace", "demo")
	config["deployment"] = CfgString(d.config, "deployment", "demo")
	config["release_name"] = CfgString(d.config, "release_name", CfgString(d.config, "deployment", "demo"))
	return config
}

// RunDaemon runs one poll (once) or polls until SIGINT/SIGTERM.
func RunDaemon(config M, once bool) error {
	daemon, err := newGuardDaemon(config)
	if err != nil {
		return err
	}
	if once {
		summary := daemon.runOnce()
		if Str(summary["status"]) != "ok" {
			return daemonErrorf("%s", daemonSafeText(summary["error"], 800))
		}
		return nil
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	poll := time.Duration(CfgNum(daemon.config, "poll_seconds", daemonDefaultPollSeconds) * float64(time.Second))
	if poll <= 0 {
		poll = daemonDefaultPollSeconds * time.Second
	}
	backoff := poll
	for {
		summary := daemon.runOnce()
		log.Printf("change-guard poll status=%s prs=%d errors=%d", Str(summary["status"]), len(Arr(summary["prs"])), len(Arr(summary["errors"])))
		if Str(summary["status"]) == "ok" {
			backoff = poll
		} else if backoff < 300*time.Second {
			backoff *= 2
			if backoff > 300*time.Second {
				backoff = 300 * time.Second
			}
		}
		select {
		case <-stop:
			return nil
		case <-time.After(backoff):
		}
	}
}

// EvaluatePR evaluates one pull request immediately and publishes its status.
func EvaluatePR(config M, number int) (M, error) {
	if number < 1 {
		return nil, daemonErrorf("pull request number is invalid")
	}
	numericNumber := int64(number)
	daemon, err := newGuardDaemon(config)
	if err != nil {
		return nil, err
	}
	now := daemon.now()
	index, err := daemon.store.loadIndex()
	if err != nil {
		return nil, err
	}
	release, err := daemon.store.lock()
	if err != nil {
		return nil, err
	}
	defer release()
	result, err := daemon.processPullRequest(PullRequestInfo{Number: numericNumber}, index, now, true)
	if err != nil {
		return nil, err
	}
	index["updated_at"] = now
	if saveErr := daemon.store.saveIndex(index); saveErr != nil {
		return nil, saveErr
	}
	return result, nil
}

func (d *guardDaemon) runOnce() M {
	now := d.now()
	index, err := d.store.loadIndex()
	if err != nil {
		return M{"status": "error", "checked_at": now, "error": daemonSafeText(err, 800), "prs": []any{}}
	}
	release, err := d.store.lock()
	if err != nil {
		if _, busy := err.(*DaemonBusyError); busy {
			return M{"status": "error", "checked_at": now, "error": daemonSafeText(err, 800), "prs": []any{}}
		}
		return M{"status": "error", "checked_at": now, "error": daemonSafeText(err, 800), "prs": []any{}}
	}
	defer release()
	return d.runOnceLocked(index, now)
}

func (d *guardDaemon) runOnceLocked(index M, now int64) M {
	errorsList := []string{}
	prResults := []M{}
	index["prs"] = daemonEnsurePRMap(index)
	credentials, verifyErr := d.github.VerifyCredentials(CfgString(d.config, "credential_probe_sha", ""))
	if verifyErr != nil {
		message := fmt.Sprintf("GitHub credential verification failed: %s", daemonSafeText(verifyErr, 500))
		log.Printf("%s", message)
		index["updated_at"] = now
		_ = d.store.saveIndex(index)
		return M{"status": "error", "checked_at": now, "error": message, "prs": []any{}}
	}
	if Bool(d.config["require_verified_status_write"]) && Str(credentials["statuses_write"]) == "inferred" {
		message := "GitHub credential verification failed: status write permission is inferred, not verified; configure credential_probe_sha or disable require_verified_status_write"
		index["updated_at"] = now
		_ = d.store.saveIndex(index)
		return M{"status": "error", "checked_at": now, "error": message, "prs": []any{}}
	}
	storedCredentials := M{}
	for _, key := range []string{"status", "login", "repository", "private", "token_kind", "scopes", "permissions", "statuses_write", "default_branch"} {
		storedCredentials[key] = credentials[key]
	}
	index["github"] = storedCredentials

	prs, err := d.github.ListOpenPullRequests(CfgString(d.config, "base_branch", "main"), ghMaxPRPerPage, ghMaxPRPages)
	if err != nil {
		message := fmt.Sprintf("cannot list open pull requests: %s", daemonSafeText(err, 500))
		log.Printf("%s", message)
		index["updated_at"] = now
		_ = d.store.saveIndex(index)
		return M{"status": "error", "checked_at": now, "error": message, "prs": []any{}}
	}
	maxPRs := int64(daemonDefaultMaxOpenPRs)
	if raw, exists := d.config["max_open_prs"]; exists {
		if parsed, ok := daemonIntStrict(raw); ok {
			maxPRs = parsed
		}
	}
	if int64(len(prs)) > maxPRs {
		message := fmt.Sprintf("open pull request count %d exceeds configured maximum %d", len(prs), maxPRs)
		index["updated_at"] = now
		_ = d.store.saveIndex(index)
		return M{"status": "error", "checked_at": now, "error": message, "prs": []any{}}
	}

	seen := map[string]bool{}
	for _, pr := range prs {
		seen[strconv.FormatInt(pr.Number, 10)] = true
		result, processErr := d.processPullRequest(pr, index, now, false)
		if processErr != nil {
			result = d.handlePullRequestError(pr, processErr, index, now, "")
		}
		prResults = append(prResults, result)
		if statusError := Str(result["status_error"]); statusError != "" {
			errorsList = append(errorsList, fmt.Sprintf("PR #%d: %s", pr.Number, statusError))
		}
	}

	closedCount := 0
	for key, raw := range daemonEnsurePRMap(index) {
		if seen[key] {
			continue
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if Bool(entry["closed_revoked"]) {
			continue
		}
		last := asM(entry["last_status"])
		if sha, ok := last["sha"].(string); ok && sha != "" {
			if revokeErr := d.revokeStatus(sha, "PR is closed or merged; the release evaluation is no longer valid", "error"); revokeErr != nil {
				errorsList = append(errorsList, fmt.Sprintf("PR #%s: closed status revocation failed: %s", key, daemonSafeText(revokeErr, 300)))
			} else {
				closedCount++
			}
		}
		entry["closed_revoked"] = true
		entry["closed_at"] = now
	}
	index["schema_version"] = daemonSchemaVersion
	index["updated_at"] = now
	if saveErr := d.store.saveIndex(index); saveErr != nil {
		return M{"status": "error", "checked_at": now, "error": daemonSafeText(saveErr, 800), "prs": prResults}
	}
	status := "ok"
	if len(errorsList) > 0 {
		status = "error"
	}
	credentialSummary := M{}
	for _, key := range []string{"login", "token_kind", "statuses_write", "permissions"} {
		credentialSummary[key] = storedCredentials[key]
	}
	sortedResults := append([]M(nil), prResults...)
	sort.Slice(sortedResults, func(i, j int) bool {
		return N(sortedResults[i], "number") < N(sortedResults[j], "number")
	})
	if len(errorsList) > 100 {
		errorsList = errorsList[:100]
	}
	return M{
		"status":             status,
		"checked_at":         now,
		"credentials":        credentialSummary,
		"prs":                sortedResults,
		"closed_invalidated": closedCount,
		"errors":             errorsList,
	}
}

func daemonEnsurePRMap(index M) M {
	if existing, ok := index["prs"].(map[string]any); ok && existing != nil {
		return existing
	}
	created := M{}
	index["prs"] = created
	return created
}

func daemonPREntry(index M, key string) M {
	prs := daemonEnsurePRMap(index)
	if entry, ok := prs[key].(map[string]any); ok && entry != nil {
		return entry
	}
	entry := M{}
	prs[key] = entry
	return entry
}

func (d *guardDaemon) processPullRequest(listed PullRequestInfo, index M, now int64, force bool) (M, error) {
	if listed.Number < 1 {
		return nil, daemonErrorf("pull request listing returned an invalid number")
	}
	key := strconv.FormatInt(listed.Number, 10)
	prev := daemonPREntry(index, key)
	prev["number"] = listed.Number

	for attempt := 0; attempt < 2; attempt++ {
		pr, err := d.github.GetPullRequest(listed.Number)
		if err != nil {
			return nil, err
		}
		if pr.State != "open" {
			return d.invalidateClosedPR(pr, prev, index, now), nil
		}
		currentBase, err := d.github.GetBranchHead(CfgString(d.config, "base_branch", "main"))
		if err != nil {
			return nil, err
		}
		prev["closed_revoked"] = false

		if pr.Draft {
			if pendingErr := d.ensurePending(pr, currentBase, prev, now, "Draft PR; waiting for review"); pendingErr != nil {
				return nil, pendingErr
			}
			entry := d.entryFromReport(prev, pr, currentBase, nil, now)
			daemonEnsurePRMap(index)[key] = entry
			return M{
				"number": pr.Number, "decision": "REVIEW", "state": "pending",
				"draft": true, "evaluation_id": nil, "head_sha": pr.HeadSHA, "base_sha": currentBase,
			}, nil
		}

		if !force {
			cached, cacheErr := d.loadValidCached(prev, pr, currentBase, now)
			if cacheErr == nil && cached != nil {
				approval, approvalError := d.resolveApproval(cached, pr)
				desired := d.desiredStatus(cached, approval)
				published, publishErr := d.publish(cached, pr, desired, approval, prev, now)
				if publishErr != nil {
					return nil, publishErr
				}
				if Bool(published["stale"]) {
					sha := Str(cached["head_sha"])
					if sha == "" {
						sha = pr.HeadSHA
					}
					_ = d.revokeStatus(sha, "PR head/base changed or evidence expired; re-evaluating", "pending")
					continue
				}
				return M{
					"number": pr.Number, "decision": cached["decision"], "state": published["state"],
					"evaluation_id": cached["evaluation_id"], "reused": true,
					"approval": published["approval"], "approval_error": approvalError,
					"status_error": published["error"],
				}, nil
			}
		}

		last := asM(prev["last_status"])
		if state := Str(last["state"]); state == "success" || state == "failure" || state == "error" {
			_ = d.revokeStatus(Str(last["sha"]), "Evaluation expired; re-evaluating", "pending")
		}
		if pendingErr := d.ensurePending(pr, currentBase, prev, now, "Evaluating release; pending evidence and policy checks"); pendingErr != nil {
			return nil, pendingErr
		}
		report, evaluateErr := d.evaluateReport(pr, currentBase)
		if evaluateErr != nil {
			return nil, evaluateErr
		}
		if _, _, writeErr := d.store.writeReport(report); writeErr != nil {
			return nil, writeErr
		}
		approval, approvalError := d.resolveApproval(report, pr)
		desired := d.desiredStatus(report, approval)
		published, publishErr := d.publish(report, pr, desired, approval, prev, now)
		if publishErr != nil {
			return nil, publishErr
		}
		if Bool(published["stale"]) || Bool(published["expired"]) {
			_ = d.revokeStatus(Str(report["head_sha"]), "PR head/base changed; re-evaluating", "pending")
			continue
		}
		entry := d.entryFromReport(prev, pr, currentBase, report, now)
		entry["last_status"] = published["last_status"]
		entry["approval"] = published["approval"]
		daemonEnsurePRMap(index)[key] = entry
		return M{
			"number": pr.Number, "decision": report["decision"], "state": published["state"],
			"evaluation_id": report["evaluation_id"], "reused": false,
			"approval": published["approval"], "approval_error": approvalError,
			"status_error": published["error"],
		}, nil
	}

	fresh, err := d.github.GetPullRequest(listed.Number)
	if err != nil {
		prev["last_error"] = daemonSafeText(err, 500)
	} else if baseNow, baseErr := d.github.GetBranchHead(CfgString(d.config, "base_branch", "main")); baseErr == nil {
		_ = d.ensurePending(fresh, baseNow, prev, now, "PR changed; evaluation queued")
	}
	daemonEnsurePRMap(index)[key] = prev
	return M{
		"number": listed.Number, "decision": "REVIEW", "state": "pending",
		"evaluation_id": nil, "changed_during_evaluation": true,
	}, nil
}

func (d *guardDaemon) loadValidCached(prev M, pr PullRequestInfo, currentBase string, now int64) (M, error) {
	evaluationID := Str(prev["evaluation_id"])
	if evaluationID == "" || !daemonApprovalIDRE.MatchString(evaluationID) {
		return nil, nil
	}
	if Str(prev["head_sha"]) != pr.HeadSHA || Str(prev["base_sha"]) != currentBase {
		return nil, nil
	}
	report, err := d.store.readReport(evaluationID)
	if err != nil {
		return nil, nil
	}
	if N(report, "schema_version") != daemonSchemaVersion {
		return nil, nil
	}
	if Str(report["head_sha"]) != pr.HeadSHA || Str(report["base_sha"]) != currentBase {
		return nil, nil
	}
	expiresAt, ok := daemonTime(report["expires_at"])
	if !ok || expiresAt <= now {
		return nil, nil
	}
	if Str(report["decision"]) == "ERROR" {
		return nil, nil
	}
	if Str(report["evaluation_id"]) != evaluationID {
		return nil, nil
	}
	binding, bindingErr := daemonCurrentPolicyBinding(d.config)
	if bindingErr != nil {
		return nil, nil
	}
	reportBinding := asM(report["policy_binding"])
	if Hash(reportBinding) != Hash(binding) {
		return nil, nil
	}
	if Str(report["policy_digest"]) != Str(binding["policy_digest"]) {
		return nil, nil
	}
	if Str(report["guard_version"]) != Str(binding["guard_version"]) {
		return nil, nil
	}
	if Str(report["rule_version"]) != Str(binding["rule_version"]) {
		return nil, nil
	}
	if !daemonReportDigestMatches(report) {
		return nil, nil
	}
	if decision := Str(report["decision"]); decision == "PASS" || decision == "REVIEW" {
		changedPaths := Arr(report["changed_paths"])
		for _, raw := range changedPaths {
			if IsWorkflowPath(raw) {
				return nil, nil
			}
		}
		context := asM(report["context"])
		if Bool(context["workflow_changed"]) || Bool(report["workflow_changed"]) {
			return nil, nil
		}
		approved := daemonApprovedDigests(d.config)
		if len(approved) == 0 || !containsString(approved, Str(report["chart_digest"])) {
			return nil, nil
		}
	}
	return report, nil
}

func daemonApprovedDigests(config M) []string {
	items, ok := daemonStringList(config["approved_chart_digest"])
	if !ok {
		return nil
	}
	lowered := make([]string, len(items))
	for index, item := range items {
		lowered[index] = strings.ToLower(item)
	}
	return lowered
}

// ---------------------------------------------------------------------------
// Evaluation

func (d *guardDaemon) evaluateReport(pr PullRequestInfo, baseSHA string) (M, error) {
	now := d.now()
	allowFork := Bool(d.config["allow_fork_prs"])
	candidate, err := d.github.FetchPullRequestCandidate(pr.Number, allowFork)
	if err != nil {
		return nil, err
	}
	if candidate.BaseSHA != baseSHA {
		return nil, daemonErrorf("base branch moved while fetching the candidate")
	}
	if candidate.PullRequest.HeadSHA != pr.HeadSHA {
		return nil, daemonErrorf("pull request head changed while fetching the candidate")
	}

	context := d.buildContext(candidate)
	temporary, err := os.MkdirTemp("", "change-guard-tree-")
	if err != nil {
		return nil, daemonErrorf("cannot create renderer workspace")
	}
	defer os.RemoveAll(temporary)
	baseDir := filepath.Join(temporary, "base")
	headDir := filepath.Join(temporary, "head")
	if _, err = candidate.BaseSnapshot.Materialize(baseDir); err != nil {
		return nil, err
	}
	if _, err = candidate.HeadSnapshot.Materialize(headDir); err != nil {
		return nil, err
	}
	renderConfig := d.renderConfig()
	oldResources, err := d.render(baseDir, renderConfig)
	if err != nil {
		return nil, daemonErrorf("base render failed: %s", daemonSafeText(err, 500))
	}
	var newResources []M
	if daemonFilesEqual(candidate.BaseSnapshot.RendererFiles, candidate.HeadSnapshot.RendererFiles) {
		newResources = oldResources
	} else {
		newResources, err = d.render(headDir, renderConfig)
		if err != nil {
			return nil, daemonErrorf("head render failed: %s", daemonSafeText(err, 500))
		}
	}
	if newResources == nil || len(newResources) == 0 {
		return nil, daemonErrorf("renderer returned no resources for the candidate")
	}

	evidence := d.collect(d.config)
	if evidence == nil {
		return nil, daemonErrorf("evidence collector did not return a mapping")
	}
	collectedAt, ok := daemonTime(evidence["collected_at"])
	if !ok || collectedAt <= 0 {
		return nil, daemonErrorf("evidence has no valid collection timestamp")
	}

	initialConfig := M{}
	for key, value := range d.config {
		initialConfig[key] = value
	}
	initialConfig["ai_required"] = false
	initial := d.evaluate(oldResources, newResources, evidence, initialConfig, context, M{})
	if initial == nil {
		return nil, daemonErrorf("engine did not return an evaluation object")
	}
	aiResult := d.analyzeSafely(initial, evidence, context, candidate)
	result := d.evaluate(oldResources, newResources, evidence, d.config, context, aiResult)
	if result == nil {
		return nil, daemonErrorf("engine did not return an evaluation object")
	}
	result = d.escalateResult(result, context)

	images := d.deploymentImages(newResources)
	evidenceSummary := d.evidenceSummary(evidence)
	evidenceDigest := Hash(evidenceSummary)
	binding, err := daemonCurrentPolicyBinding(d.config)
	if err != nil {
		return nil, err
	}
	chartDigest := context["chart_digest"]
	workflowChanged := Bool(context["workflow_changed"])
	trust := M{
		"evidence_collected_at": collectedAt,
		"evidence_digest":       evidenceDigest,
		"render_digest":         result["render_digest"],
		"old_render_digest":     result["old_render_digest"],
		"decision":              result["decision"],
		"findings_digest":       Hash(Arr(result["findings"])),
		"head_tree_sha":         candidate.HeadSnapshot.TreeSHA,
		"base_tree_sha":         candidate.BaseSnapshot.TreeSHA,
		"head_tree_digest":      candidate.HeadSnapshot.TreeDigest,
		"base_tree_digest":      candidate.BaseSnapshot.TreeDigest,
		"rule_version":          RuleVersion,
		"chart_digest":          chartDigest,
		"workflow_changed":      workflowChanged,
		"guard_version":         binding["guard_version"],
		"policy_digest":         binding["policy_digest"],
		"ai_status":             aiResult["status"],
		"ai_model":              aiResult["model"],
		"started_at":            now,
	}
	identity := M{
		"schema_version":    daemonSchemaVersion,
		"repository":        d.config["repository"],
		"pr":                pr.Number,
		"head_sha":          pr.HeadSHA,
		"base_sha":          baseSHA,
		"head_tree_sha":     candidate.HeadSnapshot.TreeSHA,
		"base_tree_sha":     candidate.BaseSnapshot.TreeSHA,
		"render_digest":     result["render_digest"],
		"old_render_digest": result["old_render_digest"],
		"policy_binding":    binding,
	}
	for key, value := range trust {
		identity[key] = value
	}
	evaluationID := "ev-" + Hash(identity)[:24]
	ttl := int64(CfgNum(d.config, "evidence_ttl_seconds", daemonDefaultEvidenceTTL))
	engineExpires, hasEngineExpires := daemonTime(result["expires_at"])
	if !hasEngineExpires {
		engineExpires = collectedAt + ttl
	}
	expiresAt := engineExpires
	if collectedAt+ttl < expiresAt {
		expiresAt = collectedAt + ttl
	}
	if now+ttl < expiresAt {
		expiresAt = now + ttl
	}
	if expiresAt <= now {
		expiresAt = now + 1
	}

	report := M{
		"schema_version": daemonSchemaVersion,
		"evaluation_id":  evaluationID,
		"repository":     d.config["repository"],
		"pull_request": M{
			"number":          pr.Number,
			"title":           daemonSafeText(pr.Title, 300),
			"author":          daemonSafeText(pr.Author, 100),
			"head_ref":        daemonSafeText(pr.HeadRef, 255),
			"head_repository": daemonSafeText(pr.HeadRepo, 200),
			"base_ref":        daemonSafeText(pr.BaseRef, 255),
			"pr_base_sha":     candidate.PRBaseSHA,
		},
		"head_sha":               pr.HeadSHA,
		"base_sha":               baseSHA,
		"base_branch":            d.config["base_branch"],
		"head_tree_sha":          candidate.HeadSnapshot.TreeSHA,
		"base_tree_sha":          candidate.BaseSnapshot.TreeSHA,
		"head_tree_digest":       candidate.HeadSnapshot.TreeDigest,
		"base_tree_digest":       candidate.BaseSnapshot.TreeDigest,
		"tree_entry_count":       candidate.HeadSnapshot.EntryCount,
		"changed_paths":          daemonFirstStrings(candidate.ChangedPaths, 500),
		"changed_count":          candidate.ChangedCount,
		"tree_diff_truncated":    candidate.TreeDiffTruncated,
		"argo":                   candidate.Argo.AsContext(),
		"render_digest":          result["render_digest"],
		"old_render_digest":      result["old_render_digest"],
		"deployment_images":      images,
		"decision":               result["decision"],
		"findings":               Arr(result["findings"]),
		"evaluated_at":           result["evaluated_at"],
		"expires_at":             expiresAt,
		"evidence_ttl_seconds":   ttl,
		"rule_version":           RuleVersion,
		"guard_version":          binding["guard_version"],
		"policy_binding":         binding,
		"policy_digest":          binding["policy_digest"],
		"chart_digest":           chartDigest,
		"approved_chart_digests": daemonApprovedDigests(d.config),
		"workflow_changed":       workflowChanged,
		"evidence":               evidenceSummary,
		"evidence_digest":        evidenceDigest,
		"ai":                     d.aiSummary(aiResult),
		"context": M{
			"tree_changes":               daemonFirstStrings(daemonAnyStrings(context["tree_changes"]), 500),
			"deployment_related_changes": daemonFirstStrings(daemonAnyStrings(context["deployment_related_changes"]), 200),
			"workflow_changed":           workflowChanged,
			"workflow_paths":             daemonFirstStrings(daemonAnyStrings(context["workflow_paths"]), 50),
			"chart_digest":               chartDigest,
			"argo":                       candidate.Argo.AsContext(),
			"changed_count":              candidate.ChangedCount,
			"tree_diff_truncated":        candidate.TreeDiffTruncated,
		},
		"evaluation":     result,
		"created_at":     now,
		"status_context": d.config["status_context"],
		"report_digest":  nil,
	}
	sanitized := daemonSanitizeValue(report, 0, "").(M)
	digestInput := M{}
	for key, value := range sanitized {
		if key != "report_digest" {
			digestInput[key] = value
		}
	}
	sanitized["report_digest"] = Hash(digestInput)
	encoded, err := CanonicalJSON(sanitized)
	if err != nil {
		return nil, daemonErrorf("evaluation report is not JSON serializable")
	}
	if len(encoded) > daemonMaxReportBytes {
		return nil, daemonErrorf("evaluation report exceeds the size limit")
	}
	return sanitized, nil
}

func daemonFilesEqual(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for path, value := range left {
		other, ok := right[path]
		if !ok || !reflect.DeepEqual(value, other) {
			return false
		}
	}
	return true
}

func daemonAnyStrings(value any) []string {
	items := Arr(value)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func daemonFirstStrings(values []string, limit int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	return append([]string(nil), values...)
}

func (d *guardDaemon) buildContext(candidate PullRequestCandidate) M {
	changed := append([]string(nil), candidate.ChangedPaths...)
	deploymentRelated := make([]string, 0)
	for _, path := range changed {
		if isDeploymentPath(path) {
			deploymentRelated = append(deploymentRelated, path)
		}
	}
	workflowPaths := make([]string, 0)
	for _, path := range changed {
		if IsWorkflowPath(path) {
			workflowPaths = append(workflowPaths, path)
		}
	}
	baseWorkflow := WorkflowTreeSignature(candidate.BaseSnapshot.Entries)
	headWorkflow := WorkflowTreeSignature(candidate.HeadSnapshot.Entries)
	workflowChanged := !ghWorkflowSignatureEqual(baseWorkflow, headWorkflow) || len(workflowPaths) > 0
	if !ghWorkflowSignatureEqual(baseWorkflow, headWorkflow) {
		workflowPaths = ghChangedWorkflowPaths(baseWorkflow, headWorkflow)
	}
	chartDigest, _ := ChartDigestFromFiles(candidate.HeadSnapshot.RendererFiles)
	argoContext := candidate.Argo.AsContext()
	context := M{
		"repository":                 d.config["repository"],
		"pull_request":               candidate.PullRequest.Number,
		"head_sha":                   candidate.PullRequest.HeadSHA,
		"base_sha":                   candidate.BaseSHA,
		"pr_base_sha":                candidate.PRBaseSHA,
		"head_ref":                   daemonSafeText(candidate.PullRequest.HeadRef, 255),
		"base_ref":                   d.config["base_branch"],
		"head_tree_sha":              candidate.HeadSnapshot.TreeSHA,
		"base_tree_sha":              candidate.BaseSnapshot.TreeSHA,
		"head_tree_digest":           candidate.HeadSnapshot.TreeDigest,
		"base_tree_digest":           candidate.BaseSnapshot.TreeDigest,
		"tree_entry_count":           candidate.HeadSnapshot.EntryCount,
		"changed_paths":              daemonFirstStrings(changed, 500),
		"tree_changes":               daemonFirstStrings(changed, 500),
		"deployment_related_changes": daemonFirstStrings(deploymentRelated, 200),
		"changed_count":              candidate.ChangedCount,
		"tree_diff_truncated":        candidate.TreeDiffTruncated,
		"workflow_changed":           workflowChanged,
		"workflow_paths":             daemonFirstStrings(workflowPaths, 50),
		"chart_digest":               chartDigest,
		"approved_chart_digests":     daemonApprovedDigests(d.config),
		"argo":                       argoContext,
	}
	for key, value := range argoContext {
		context[key] = value
	}
	return context
}

func (d *guardDaemon) analyzeSafely(initial, evidence, context M, candidate PullRequestCandidate) M {
	inputs := M{
		"repository": d.config["repository"],
		"pull_request": M{
			"number": candidate.PullRequest.Number,
			"title":  daemonSafeText(candidate.PullRequest.Title, 300),
			"author": daemonSafeText(candidate.PullRequest.Author, 100),
		},
		"head_sha":         candidate.PullRequest.HeadSHA,
		"base_sha":         candidate.BaseSHA,
		"render_digest":    initial["render_digest"],
		"decision_preview": initial["decision"],
		"findings_preview": daemonFirstAny(Arr(initial["findings"]), 100),
		"changes":          daemonFirstAny(Arr(initial["changes"]), 200),
		"evidence":         d.evidenceSummary(evidence),
		"context": M{
			"changed_paths": daemonFirstStrings(daemonAnyStrings(context["tree_changes"]), 200),
			"argo":          context["argo"],
		},
	}
	var result M
	func() {
		defer func() {
			if recover() != nil {
				result = M{
					"status": "error", "model": CfgString(d.config, "deepseek_model", "deepseek-chat"),
					"summary": "", "additional_risks": []any{}, "citations": []any{},
					"error": "AI analyzer panicked",
				}
			}
		}()
		result = d.analyze(inputs, d.config)
	}()
	if result == nil {
		return M{
			"status": "error", "model": CfgString(d.config, "deepseek_model", "deepseek-chat"),
			"summary": "", "additional_risks": []any{}, "citations": []any{},
			"error": "AI analyzer returned an invalid result",
		}
	}
	return result
}

func daemonFirstAny(values []any, limit int) []any {
	if len(values) > limit {
		values = values[:limit]
	}
	return append([]any(nil), values...)
}

func (d *guardDaemon) escalateResult(result M, context M) M {
	findings := make([]M, 0)
	existing := map[string]bool{}
	for _, raw := range Arr(result["findings"]) {
		finding, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		severity := Str(finding["severity"])
		if _, known := daemonSeverityRank[severity]; !known {
			continue
		}
		findings = append(findings, finding)
		existing[Str(finding["rule_id"])+"\x00"+Str(finding["field"])] = true
	}
	escalations := []M{}
	add := func(ruleID, severity, field, message string, evidence M) {
		key := ruleID + "\x00" + field
		if existing[key] {
			return
		}
		existing[key] = true
		if evidence == nil {
			evidence = M{}
		}
		item := M{"rule_id": ruleID, "severity": severity, "field": field, "message": message, "evidence": evidence}
		findings = append(findings, item)
		escalations = append(escalations, item)
	}

	declaredPaths := daemonAnyStrings(context["changed_paths"])
	relatedPaths := daemonAnyStrings(context["deployment_related_changes"])
	workflowPaths := []string{}
	for _, path := range append(append([]string{}, declaredPaths...), relatedPaths...) {
		if IsWorkflowPath(path) {
			workflowPaths = append(workflowPaths, path)
		}
	}
	sort.Strings(workflowPaths)
	workflowPaths = daemonDedupe(workflowPaths)
	if len(workflowPaths) > 0 || Bool(context["workflow_changed"]) {
		add("WORKFLOW_CHANGE_BLOCKED", "BLOCK", "context.workflow_changed",
			"a .github/workflows/ file changed; CI workflow content must be identical on base and head",
			M{"paths": daemonFirstStrings(workflowPaths, 20), "count": len(workflowPaths)})
	}
	approved := []string{}
	for _, item := range Arr(context["approved_chart_digests"]) {
		if text, ok := item.(string); ok {
			approved = append(approved, text)
		}
	}
	chartDigest := Str(context["chart_digest"])
	if len(approved) == 0 {
		add("APPROVED_CHART_DIGEST_NOT_CONFIGURED", "ERROR", "context.approved_chart_digest",
			"approved_chart_digest is not configured; charts/demo cannot be trusted", M{})
	} else if !containsString(approved, chartDigest) {
		add("APPROVED_CHART_DIGEST_MISMATCH", "BLOCK", "context.chart_digest",
			"candidate charts/demo bytes do not match the operator-approved chart digest",
			M{"chart_digest": chartDigest, "approved_chart_digests": daemonFirstStrings(approved, 20)})
	}
	if Bool(context["argo_source_changed"]) {
		add("ARGOCD_SOURCE_CHANGED", "BLOCK", "context.argo_source_changed",
			"Argo CD Application source repository/path/revision changed", M{"paths": argoPaths(context)})
	}
	if Bool(context["argo_application_changed"]) {
		add("ARGOCD_APPLICATION_CHANGED", "REVIEW", "context.argo_application_changed",
			"An Argo CD Application/ApplicationSet changed and requires manual review", M{"paths": argoPaths(context)})
	}
	if Bool(context["argo_project_changed"]) {
		add("ARGOCD_PROJECT_CHANGED", "REVIEW", "context.argo_project_changed",
			"An Argo CD AppProject changed and requires manual review", M{"paths": argoPaths(context)})
	}
	if Bool(context["argo_manifest_error"]) {
		add("ARGOCD_MANIFEST_INVALID", "REVIEW", "context.argo_manifest_error",
			"Argo CD manifests could not be parsed; their source/project impact cannot be proven", M{})
	}
	if Bool(context["tree_diff_truncated"]) {
		add("TREE_DIFF_TRUNCATED", "REVIEW", "context.tree_diff_truncated",
			"the repository tree diff was truncated; manual review is required",
			M{"changed_count": context["changed_count"]})
	}
	extraPaths := []string{}
	for _, path := range relatedPaths {
		if strings.HasPrefix(path, daemonChartPathPrefix) || path == "gitops/demo/values.yaml" || IsWorkflowPath(path) {
			continue
		}
		lowered := strings.ToLower(path)
		if strings.HasPrefix(lowered, "gitops/argocd/") || strings.HasSuffix(lowered, "/application.yaml") ||
			strings.HasSuffix(lowered, "/application.yml") || strings.HasSuffix(lowered, "/project.yaml") ||
			strings.HasSuffix(lowered, "/project.yml") {
			continue
		}
		extraPaths = append(extraPaths, path)
	}
	if len(extraPaths) > 0 {
		add("DEPLOYMENT_CONFIG_CHANGE", "REVIEW", "context.deployment_related_changes",
			"a deployment-related path outside the trusted rendered chart changed",
			M{"paths": daemonFirstStrings(extraPaths, 20), "count": len(extraPaths)})
	}
	if len(escalations) == 0 {
		return result
	}
	sort.SliceStable(findings, func(i, j int) bool {
		leftRank := daemonSeverityRank[Str(findings[i]["severity"])]
		rightRank := daemonSeverityRank[Str(findings[j]["severity"])]
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		leftRule := Str(findings[i]["rule_id"])
		rightRule := Str(findings[j]["rule_id"])
		if leftRule != rightRule {
			return leftRule < rightRule
		}
		return Str(findings[i]["field"]) < Str(findings[j]["field"])
	})
	updated := M{}
	for key, value := range result {
		updated[key] = value
	}
	findingValues := make([]any, len(findings))
	for index, finding := range findings {
		findingValues[index] = finding
	}
	updated["findings"] = findingValues
	updated["decision"] = daemonDecisionFromFindings(findings)
	escalationValues := make([]any, len(escalations))
	for index, item := range escalations {
		escalationValues[index] = item
	}
	updated["daemon_escalations"] = escalationValues
	if audit, ok := result["audit"].(map[string]any); ok {
		checks := make([]any, len(findings))
		for index, finding := range findings {
			checks[index] = M{
				"rule_id": finding["rule_id"], "severity": finding["severity"],
				"field": finding["field"], "message": finding["message"],
			}
		}
		auditCopy := M{}
		for key, value := range audit {
			auditCopy[key] = value
		}
		auditCopy["checks"] = checks
		auditCopy["daemon_escalations"] = escalationValues
		updated["audit"] = auditCopy
	}
	return updated
}

func argoPaths(context M) []string {
	return daemonFirstStrings(daemonAnyStrings(context["argo_changed_paths"]), 20)
}

func daemonDedupe(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (d *guardDaemon) deploymentImages(resources []M) []M {
	images := []M{}
	namespace := CfgString(d.config, "namespace", "demo")
	name := CfgString(d.config, "deployment", "demo")
	for _, resource := range resources {
		if Str(resource["kind"]) != "Deployment" {
			continue
		}
		metadata := asM(resource["metadata"])
		if Str(metadata["name"]) != name {
			continue
		}
		resourceNamespace := Str(metadata["namespace"])
		if resourceNamespace == "" {
			resourceNamespace = namespace
		}
		if resourceNamespace != namespace {
			continue
		}
		spec := asM(resource["spec"])
		template := asM(spec["template"])
		podSpec := asM(template["spec"])
		for _, group := range []string{"containers", "initContainers"} {
			for _, raw := range Arr(podSpec[group]) {
				container, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				image := Str(container["image"])
				if image == "" {
					continue
				}
				images = append(images, M{
					"container": truncateRunes(Str(container["name"]), 200),
					"init":      group == "initContainers",
					"image":     truncateRunes(image, 1000),
				})
			}
		}
	}
	sort.SliceStable(images, func(i, j int) bool {
		leftInit := Bool(images[i]["init"])
		rightInit := Bool(images[j]["init"])
		if leftInit != rightInit {
			return !leftInit
		}
		leftContainer := Str(images[i]["container"])
		rightContainer := Str(images[j]["container"])
		if leftContainer != rightContainer {
			return leftContainer < rightContainer
		}
		return Str(images[i]["image"]) < Str(images[j]["image"])
	})
	return images
}

func (d *guardDaemon) evidenceSummary(evidence M) M {
	metrics := asM(evidence["metrics"])
	sourceTimestamps := asM(metrics["source_timestamps"])
	alerts := Arr(metrics["alerts"])
	alertSummary := make([]any, 0)
	for index, raw := range alerts {
		if index >= 50 {
			break
		}
		alert, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		labels := alert["labels"]
		if labels == nil {
			labels = M{}
		}
		alertSummary = append(alertSummary, M{
			"name":   daemonSafeText(alert["name"], 200),
			"state":  daemonSafeText(alert["state"], 50),
			"labels": daemonSanitizeValue(labels, 1, "labels"),
		})
	}
	capacity := asM(evidence["capacity"])
	deployment := asM(evidence["deployment"])
	nodes := Arr(evidence["nodes"])
	pods := Arr(evidence["pods"])
	rawErrors := Arr(evidence["errors"])
	errorSummary := make([]any, 0)
	for index, item := range rawErrors {
		if index >= 20 {
			break
		}
		errorSummary = append(errorSummary, daemonSafeText(item, 500))
	}
	timestamps := M{}
	index := 0
	for key, value := range sourceTimestamps {
		if index >= 20 {
			break
		}
		if parsed, ok := daemonTime(value); ok {
			timestamps[key] = parsed
		} else {
			timestamps[key] = nil
		}
		index++
	}
	capacitySummary := M{}
	for _, key := range []string{"available_cpu_millicores", "available_memory_bytes", "allocatable_cpu_millicores", "allocatable_memory_bytes", "workers_ready"} {
		capacitySummary[key] = daemonFinite(capacity[key])
	}
	deploymentImages := make([]any, 0)
	for index, item := range Arr(deployment["images"]) {
		if index >= 20 {
			break
		}
		deploymentImages = append(deploymentImages, daemonSafeText(item, 500))
	}
	return M{
		"collected_at": daemonNullableTime(evidence["collected_at"]),
		"errors":       errorSummary,
		"metrics": M{
			"memory_working_set_bytes": daemonFinite(metrics["memory_working_set_bytes"]),
			"request_rate":             daemonFinite(metrics["request_rate"]),
			"error_ratio":              daemonFinite(metrics["error_ratio"]),
			"p95_seconds":              daemonFinite(metrics["p95_seconds"]),
			"alerts":                   alertSummary,
			"source_timestamps":        timestamps,
		},
		"capacity": capacitySummary,
		"deployment": M{
			"name":           daemonSafeText(deployment["name"], 200),
			"namespace":      daemonSafeText(deployment["namespace"], 200),
			"replicas":       deployment["replicas"],
			"ready_replicas": deployment["ready_replicas"],
			"images":         deploymentImages,
		},
		"node_count": len(nodes),
		"pod_count":  len(pods),
	}
}

func daemonFinite(value any) any {
	number, ok := ghNumber(value)
	if !ok {
		return nil
	}
	return number
}

func daemonNullableTime(value any) any {
	if parsed, ok := daemonTime(value); ok {
		return parsed
	}
	return nil
}

func (d *guardDaemon) aiSummary(aiResult M) M {
	if aiResult == nil {
		return M{"status": "missing"}
	}
	risks := Arr(aiResult["additional_risks"])
	citations := Arr(aiResult["citations"])
	riskSummary := make([]any, 0)
	for index, raw := range risks {
		if index >= 10 {
			break
		}
		risk, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		severity := risk["severity"]
		if severity == nil {
			severity = "REVIEW"
		}
		riskSummary = append(riskSummary, M{
			"title":    daemonSafeText(risk["title"], 300),
			"detail":   daemonSafeText(risk["detail"], 1000),
			"severity": severity,
		})
	}
	citationSummary := make([]any, 0)
	for index, raw := range citations {
		if index >= 10 {
			break
		}
		citation, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		citationSummary = append(citationSummary, M{
			"case_id":       daemonSafeText(citation["case_id"], 100),
			"source":        daemonSafeText(citation["source"], 500),
			"source_sha256": daemonSafeText(citation["source_sha256"], 64),
			"source_commit": daemonSafeText(citation["source_commit"], 64),
			"line_start":    citation["line_start"],
			"line_end":      citation["line_end"],
		})
	}
	var errorValue any
	if Str(aiResult["error"]) != "" {
		errorValue = daemonSafeText(aiResult["error"], 800)
	}
	return M{
		"status":           aiResult["status"],
		"model":            daemonSafeText(aiResult["model"], 100),
		"summary":          daemonSafeText(aiResult["summary"], 2000),
		"additional_risks": riskSummary,
		"citations":        citationSummary,
		"error":            errorValue,
	}
}

// ---------------------------------------------------------------------------
// Approval

func (d *guardDaemon) approvalPermission(login, association string) (string, string) {
	if association == "OWNER" {
		identity, err := d.github.GetRepositoryIdentity()
		if err != nil {
			return "", fmt.Sprintf("cannot verify current repository owner: %s", daemonSafeText(err, 400))
		}
		if identity == nil {
			return "", "repository identity response is invalid"
		}
		ownerLogin := Str(identity["owner_login"])
		ownerType := Str(identity["owner_type"])
		if strings.EqualFold(ownerLogin, login) && ownerType == "User" {
			return ghOwnerApprovalPermission, ""
		}
	}
	permission, err := d.github.GetUserPermission(login)
	if err != nil {
		return "", fmt.Sprintf("cannot verify current write permission for %s: %s", login, daemonSafeText(err, 400))
	}
	if ghWritePermissions[permission] {
		return permission, ""
	}
	return "", ""
}

func (d *guardDaemon) resolveApproval(report M, pr PullRequestInfo) (M, string) {
	if Str(report["decision"]) != "REVIEW" {
		return nil, ""
	}
	approvers, _ := daemonStringList(d.config["approvers"])
	if len(approvers) == 0 {
		return nil, "no approvers are configured; REVIEW cannot be approved"
	}
	evaluationID := Str(report["evaluation_id"])
	evaluatedAt, evaluatedOK := daemonTime(report["evaluated_at"])
	expiresAt, expiresOK := daemonTime(report["expires_at"])
	if !daemonApprovalIDRE.MatchString(evaluationID) || !evaluatedOK || !expiresOK {
		return nil, "report timestamps are invalid"
	}
	if Str(report["head_sha"]) != pr.HeadSHA {
		return nil, "report head no longer matches the pull request"
	}
	now := d.now()
	if now >= expiresAt {
		return nil, "report has expired"
	}
	comments, err := d.github.ListIssueComments(pr.Number)
	if err != nil {
		return nil, fmt.Sprintf("cannot read approval comments: %s", daemonSafeText(err, 500))
	}
	type candidate struct {
		CommentID   int64
		Login       string
		Association string
		EffectiveAt int64
		CreatedAt   any
		UpdatedAt   any
		URL         any
	}
	candidates := []candidate{}
	for _, comment := range comments {
		body := comment["body"]
		if parsed, ok := parseApprovalBody(body); !ok || parsed != evaluationID {
			continue
		}
		user := asM(comment["user"])
		login := Str(user["login"])
		if login == "" || !containsString(approvers, login) {
			continue
		}
		created, createdOK := ghParseTime(comment["created_at"])
		updated, updatedOK := ghParseTime(comment["updated_at"])
		var effective int64
		haveEffective := false
		if createdOK {
			effective = created
			haveEffective = true
		}
		if updatedOK && (!haveEffective || updated > effective) {
			effective = updated
			haveEffective = true
		}
		if !haveEffective {
			continue
		}
		if effective < evaluatedAt-demonApprovalSkew() || effective >= expiresAt {
			continue
		}
		commentID, ok := ghInt(comment["id"])
		if !ok || commentID < 1 {
			continue
		}
		candidateValue := candidate{
			CommentID: commentID, Login: login,
			Association: strings.ToUpper(Str(comment["author_association"])),
			EffectiveAt: effective, URL: comment["html_url"],
		}
		if createdOK {
			candidateValue.CreatedAt = created
		}
		if updatedOK {
			candidateValue.UpdatedAt = updated
		}
		candidates = append(candidates, candidateValue)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].EffectiveAt != candidates[j].EffectiveAt {
			return candidates[i].EffectiveAt > candidates[j].EffectiveAt
		}
		return candidates[i].CommentID > candidates[j].CommentID
	})
	permissionError := ""
	for _, item := range candidates {
		permission, permissionErr := d.approvalPermission(item.Login, item.Association)
		if permission == "" {
			if permissionErr != "" {
				permissionError = permissionErr
			}
			continue
		}
		if Str(report["head_sha"]) != pr.HeadSHA {
			return nil, "report head changed during approval verification"
		}
		record := M{
			"evaluation_id": evaluationID,
			"comment_id":    item.CommentID,
			"login":         item.Login,
			"permission":    permission,
			"approved_at":   item.EffectiveAt,
			"created_at":    item.CreatedAt,
			"updated_at":    item.UpdatedAt,
			"checked_at":    d.now(),
			"head_sha":      report["head_sha"],
			"base_sha":      report["base_sha"],
			"expires_at":    expiresAt,
			"comment_url":   item.URL,
		}
		if _, err = d.store.writeApproval(record); err != nil {
			return nil, fmt.Sprintf("cannot persist approval record: %s", daemonSafeText(err, 400))
		}
		return record, ""
	}
	return nil, permissionError
}

func demonApprovalSkew() int64 { return daemonApprovalSkewSeconds }

// ---------------------------------------------------------------------------
// Status publication

func (d *guardDaemon) desiredStatus(report M, approval M) M {
	decision := Str(report["decision"])
	evaluationID := Str(report["evaluation_id"])
	switch decision {
	case "PASS":
		return M{"state": "success", "description": fmt.Sprintf("PASS %s head/base verified", evaluationID)}
	case "BLOCK":
		top := daemonTopFinding(report, "BLOCK")
		return M{"state": "failure", "description": fmt.Sprintf("BLOCK %s: %s [%s]", Str(top["rule_id"]), Str(top["message"]), evaluationID)}
	case "ERROR":
		top := daemonTopFinding(report, "ERROR")
		return M{"state": "error", "description": fmt.Sprintf("ERROR %s: %s [%s]", Str(top["rule_id"]), Str(top["message"]), evaluationID)}
	case "REVIEW":
		if approval != nil {
			return M{"state": "success", "description": fmt.Sprintf("REVIEW approved by %s [%s]", Str(approval["login"]), evaluationID)}
		}
		return M{"state": "pending", "description": fmt.Sprintf("REVIEW required - comment /guard approve %s", evaluationID)}
	default:
		return M{"state": "error", "description": fmt.Sprintf("invalid evaluation decision [%s]", evaluationID)}
	}
}

func daemonTopFinding(report M, severity string) M {
	for _, raw := range Arr(report["findings"]) {
		finding, ok := raw.(map[string]any)
		if ok && Str(finding["severity"]) == severity {
			return finding
		}
	}
	return M{"rule_id": severity, "message": "release blocked"}
}

func (d *guardDaemon) publish(report M, pr PullRequestInfo, desired M, approval M, prev M, now int64) (M, error) {
	state := Str(desired["state"])
	description := Str(desired["description"])
	if !ghStatusStates[state] {
		state = "error"
		description = "invalid status state"
	}
	if state == "success" {
		fresh, err := d.github.GetPullRequest(pr.Number)
		if err != nil {
			return nil, err
		}
		baseNow, err := d.github.GetBranchHead(CfgString(d.config, "base_branch", "main"))
		if err != nil {
			return nil, err
		}
		current := d.now()
		expiresAt, _ := daemonTime(report["expires_at"])
		if fresh.State != "open" || fresh.Draft || fresh.HeadSHA != Str(report["head_sha"]) ||
			baseNow != Str(report["base_sha"]) || current >= expiresAt {
			return M{"state": "pending", "stale": true, "error": nil}, nil
		}
		if Str(report["decision"]) == "REVIEW" {
			freshApproval, _ := d.resolveApproval(report, fresh)
			if freshApproval == nil || approval == nil || N(freshApproval, "comment_id") != N(approval, "comment_id") {
				state = "pending"
				description = fmt.Sprintf("REVIEW approval is no longer valid - comment /guard approve %s", Str(report["evaluation_id"]))
				approval = nil
			}
		}
		finalPR, err := d.github.GetPullRequest(pr.Number)
		if err != nil {
			return nil, err
		}
		finalBase, err := d.github.GetBranchHead(CfgString(d.config, "base_branch", "main"))
		if err != nil {
			return nil, err
		}
		if finalPR.State != "open" || finalPR.Draft || finalPR.HeadSHA != Str(report["head_sha"]) || finalBase != Str(report["base_sha"]) {
			return M{"state": "pending", "stale": true, "error": nil}, nil
		}
	}

	last := asM(prev["last_status"])
	if Str(last["sha"]) == Str(report["head_sha"]) && Str(last["state"]) == state &&
		daemonSafeText(last["description"], daemonStatusDetailLimit) == daemonSafeText(description, daemonStatusDetailLimit) {
		d.writeOptionalComment(report, pr, prev)
		return M{"state": state, "last_status": last, "approval": daemonApprovalSummary(approval), "skipped": true}, nil
	}
	response, err := d.github.CreateCommitStatus(Str(report["head_sha"]), state, description,
		CfgString(d.config, "status_context", "change-guard/release"), CfgString(d.config, "status_target_url", ""))
	if err != nil {
		return M{"state": state, "error": fmt.Sprintf("status publication failed: %s", daemonSafeText(err, 500)), "approval": daemonApprovalSummary(approval)}, nil
	}
	statusRecord := M{
		"sha":           report["head_sha"],
		"state":         state,
		"description":   daemonSafeText(description, daemonStatusDetailLimit),
		"context":       CfgString(d.config, "status_context", "change-guard/release"),
		"posted_at":     d.now(),
		"evaluation_id": report["evaluation_id"],
		"github_id":     response["id"],
	}
	prev["last_status"] = statusRecord
	d.writeOptionalComment(report, pr, prev)
	return M{"state": state, "last_status": statusRecord, "approval": daemonApprovalSummary(approval), "skipped": false}, nil
}

func daemonApprovalSummary(approval M) any {
	if approval == nil {
		return nil
	}
	return M{
		"login":         approval["login"],
		"comment_id":    approval["comment_id"],
		"approved_at":   approval["approved_at"],
		"permission":    approval["permission"],
		"evaluation_id": approval["evaluation_id"],
		"head_sha":      approval["head_sha"],
		"base_sha":      approval["base_sha"],
	}
}

func (d *guardDaemon) writeOptionalComment(report M, pr PullRequestInfo, prev M) {
	if !Bool(d.config["report_comment"]) {
		return
	}
	if _, exists := prev["comment_id"]; exists {
		return
	}
	marker := fmt.Sprintf("<!-- change-guard:evaluation:%s -->", Str(report["evaluation_id"]))
	findings := Arr(report["findings"])
	lines := []string{
		marker,
		fmt.Sprintf("### Change Guard `%s`", Str(report["evaluation_id"])),
		fmt.Sprintf("Decision: **%s**", Str(report["decision"])),
		fmt.Sprintf("Head: `%s`  ", Str(report["head_sha"])),
		fmt.Sprintf("Base: `%s`  ", Str(report["base_sha"])),
		fmt.Sprintf("Expires: `%s`  ", ghISOUTC(daemonTimeOrZero(report["expires_at"]))),
		fmt.Sprintf("Report digest: `%s`", Str(report["report_digest"])),
	}
	for index, raw := range findings {
		if index >= 8 {
			break
		}
		if finding, ok := raw.(map[string]any); ok {
			lines = append(lines, fmt.Sprintf("- **%s** `%s`: %s", Str(finding["severity"]), Str(finding["rule_id"]), Str(finding["message"])))
		}
	}
	if Str(report["decision"]) == "REVIEW" {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Manual approval: `/guard approve %s`", Str(report["evaluation_id"])))
	}
	response, err := d.github.CreateIssueComment(pr.Number, strings.Join(lines, "\n"))
	if err != nil {
		prev["comment_error"] = daemonSafeText(err, 500)
		return
	}
	if commentID, ok := ghInt(response["id"]); ok {
		prev["comment_id"] = commentID
		if url, ok := response["html_url"].(string); ok {
			prev["comment_url"] = url
		}
	}
}

func daemonTimeOrZero(value any) int64 {
	parsed, _ := daemonTime(value)
	return parsed
}

func (d *guardDaemon) ensurePending(pr PullRequestInfo, baseSHA string, prev M, now int64, reason string) error {
	last := asM(prev["last_status"])
	if sha := Str(last["sha"]); sha != "" && sha != pr.HeadSHA {
		_ = d.revokeStatus(sha, "Superseded by a newer head commit", "pending")
	}
	if Str(last["sha"]) == pr.HeadSHA && Str(last["state"]) == "pending" && Str(prev["pending_base_sha"]) == baseSHA {
		return nil
	}
	description := fmt.Sprintf("%s [%s/%s]", reason, daemonShortSHA(pr.HeadSHA), daemonShortSHA(baseSHA))
	response, err := d.github.CreateCommitStatus(pr.HeadSHA, "pending", description,
		CfgString(d.config, "status_context", "change-guard/release"), CfgString(d.config, "status_target_url", ""))
	if err != nil {
		prev["last_error"] = "pending status failed: " + daemonSafeText(err, 500)
		return daemonErrorf("%s", prev["last_error"])
	}
	prev["pending_base_sha"] = baseSHA
	prev["last_status"] = M{
		"sha":           pr.HeadSHA,
		"state":         "pending",
		"description":   daemonSafeText(description, daemonStatusDetailLimit),
		"context":       CfgString(d.config, "status_context", "change-guard/release"),
		"posted_at":     now,
		"evaluation_id": nil,
		"github_id":     response["id"],
	}
	return nil
}

func daemonShortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func (d *guardDaemon) revokeStatus(sha, reason, state string) error {
	if !daemonSHARegex.MatchString(sha) {
		return nil
	}
	response, err := d.github.CreateCommitStatus(sha, state, "Change Guard: "+reason,
		CfgString(d.config, "status_context", "change-guard/release"), CfgString(d.config, "status_target_url", ""))
	_ = response
	return err
}

// ---------------------------------------------------------------------------
// Error handling / summaries

func (d *guardDaemon) handlePullRequestError(pr PullRequestInfo, err error, index M, now int64, baseSHA string) M {
	key := strconv.FormatInt(pr.Number, 10)
	prev := daemonPREntry(index, key)
	message := daemonSafeText(err, 800)
	prev["last_error"] = message
	if baseSHA == "" {
		baseSHA, _ = d.github.GetBranchHead(CfgString(d.config, "base_branch", "main"))
	}
	report, reportErr := d.errorReport(pr, baseSHA, message, now)
	if reportErr != nil {
		prev["last_error"] = daemonSafeText(reportErr, 800)
		daemonEnsurePRMap(index)[key] = prev
		return M{
			"number": pr.Number, "decision": "ERROR", "state": "unknown",
			"status_error": fmt.Sprintf("failed to publish error state: %s", daemonSafeText(reportErr, 400)),
			"error":        message,
		}
	}
	if _, _, writeErr := d.store.writeReport(report); writeErr != nil {
		prev["last_error"] = daemonSafeText(writeErr, 800)
		daemonEnsurePRMap(index)[key] = prev
		return M{
			"number": pr.Number, "decision": "ERROR", "state": "unknown",
			"status_error": fmt.Sprintf("failed to publish error state: %s", daemonSafeText(writeErr, 400)),
			"error":        message,
		}
	}
	prev["evaluation_id"] = report["evaluation_id"]
	prev["head_sha"] = report["head_sha"]
	prev["base_sha"] = report["base_sha"]
	prev["decision"] = "ERROR"
	prev["expires_at"] = report["expires_at"]
	statusError := ""
	response, statusErr := d.github.CreateCommitStatus(pr.HeadSHA, "error", "ERROR: "+message,
		CfgString(d.config, "status_context", "change-guard/release"), CfgString(d.config, "status_target_url", ""))
	if statusErr != nil {
		statusError = fmt.Sprintf("error status publication failed: %s", daemonSafeText(statusErr, 400))
	} else {
		prev["last_status"] = M{
			"sha":           pr.HeadSHA,
			"state":         "error",
			"description":   daemonSafeText("ERROR: "+message, daemonStatusDetailLimit),
			"context":       CfgString(d.config, "status_context", "change-guard/release"),
			"posted_at":     now,
			"evaluation_id": report["evaluation_id"],
			"github_id":     response["id"],
		}
	}
	daemonEnsurePRMap(index)[key] = prev
	return M{
		"number": pr.Number, "decision": "ERROR",
		"state":         daemonPick(statusError == "", "error", "unknown"),
		"evaluation_id": report["evaluation_id"],
		"status_error":  daemonEmptyNil(statusError),
		"error":         message,
	}
}

func daemonPick(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func daemonEmptyNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (d *guardDaemon) errorReport(pr PullRequestInfo, baseSHA, message string, now int64) (M, error) {
	if !daemonSHARegex.MatchString(pr.HeadSHA) {
		return nil, daemonErrorf("cannot create an error report without a valid head SHA")
	}
	binding, err := daemonCurrentPolicyBinding(d.config)
	if err != nil {
		return nil, err
	}
	identity := M{
		"schema_version": daemonSchemaVersion,
		"type":           "evaluation-error",
		"repository":     d.config["repository"],
		"pr":             pr.Number,
		"head_sha":       pr.HeadSHA,
		"base_sha":       baseSHA,
		"message":        message,
		"policy_binding": binding,
		"at":             now,
	}
	evaluationID := "ev-" + Hash(identity)[:24]
	ttl := int64(CfgNum(d.config, "evidence_ttl_seconds", daemonDefaultEvidenceTTL))
	finding := M{
		"rule_id": "DAEMON_EVALUATION_ERROR", "severity": "ERROR",
		"field": "evaluation", "message": message, "evidence": M{},
	}
	report := M{
		"schema_version": daemonSchemaVersion,
		"evaluation_id":  evaluationID,
		"type":           "evaluation-error",
		"repository":     d.config["repository"],
		"pull_request": M{
			"number": pr.Number,
			"title":  daemonSafeText(pr.Title, 300),
			"author": daemonSafeText(pr.Author, 100),
		},
		"head_sha":        pr.HeadSHA,
		"base_sha":        baseSHA,
		"base_branch":     d.config["base_branch"],
		"decision":        "ERROR",
		"evaluated_at":    now,
		"expires_at":      now + ttl,
		"rule_version":    RuleVersion,
		"guard_version":   binding["guard_version"],
		"policy_binding":  binding,
		"policy_digest":   binding["policy_digest"],
		"chart_digest":    nil,
		"evidence":        M{"collected_at": now, "errors": []any{message}},
		"evidence_digest": Hash(M{"error": message}),
		"findings":        []any{finding},
		"evaluation": M{
			"decision": "ERROR", "findings": []any{finding}, "changes": []any{},
			"evaluated_at": now, "expires_at": now + ttl, "render_digest": nil,
		},
		"ai":             M{"status": "error", "error": message},
		"created_at":     now,
		"status_context": d.config["status_context"],
		"report_digest":  nil,
	}
	sanitized := daemonSanitizeValue(report, 0, "").(M)
	digestInput := M{}
	for key, value := range sanitized {
		if key != "report_digest" {
			digestInput[key] = value
		}
	}
	sanitized["report_digest"] = Hash(digestInput)
	return sanitized, nil
}

func (d *guardDaemon) invalidateClosedPR(pr PullRequestInfo, prev M, index M, now int64) M {
	last := asM(prev["last_status"])
	if !Bool(prev["closed_revoked"]) {
		if sha := Str(last["sha"]); sha != "" {
			if err := d.revokeStatus(sha, "PR is closed or merged", "error"); err != nil {
				prev["last_error"] = "closed status revocation failed: " + daemonSafeText(err, 500)
			}
		}
	}
	prev["closed_revoked"] = true
	prev["closed_at"] = now
	daemonEnsurePRMap(index)[strconv.FormatInt(pr.Number, 10)] = prev
	return M{
		"number": pr.Number, "decision": "ERROR", "state": "error",
		"closed": true, "error": "pull request is closed or merged",
	}
}

func (d *guardDaemon) entryFromReport(prev M, pr PullRequestInfo, baseSHA string, report M, now int64) M {
	entry := M{}
	for key, value := range prev {
		entry[key] = value
	}
	entry["number"] = pr.Number
	entry["head_sha"] = pr.HeadSHA
	entry["base_sha"] = baseSHA
	entry["updated_at"] = now
	entry["closed_revoked"] = false
	if report != nil {
		for _, key := range []string{"evaluation_id", "decision", "expires_at", "render_digest", "head_tree_sha", "base_tree_sha", "report_digest", "chart_digest", "guard_version", "policy_digest"} {
			entry[key] = report[key]
		}
	}
	return entry
}

// ---------------------------------------------------------------------------
// Small local helpers
