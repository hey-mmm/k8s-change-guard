package guard

// Hardened GitHub access for the k8s change guard.
//
// This file is deliberately small and boring: it only speaks to the fixed
// GitHub REST API host, it never checks out or executes a pull-request branch,
// and it materialises only the files the trusted renderer is allowed to read.
//
// Security properties:
//   - A pull request is identified by its exact head SHA. The baseline is the
//     *current* base branch tip, not the possibly stale base.sha on the PR.
//   - The candidate tree is obtained from the Git Trees/Blobs APIs. Full
//     archives are never downloaded or extracted, so there is no archive path
//     traversal surface. Symlinks, submodules, unsafe paths, duplicate paths,
//     truncated trees, and oversized files are rejected.
//   - Only charts/demo/** and gitops/demo/values.yaml are written into the
//     renderer tree. Argo CD / deployment manifests are read in memory.
//   - API responses are bounded, redirects are refused, retries are bounded,
//     and authentication tokens are never included in errors or reports.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	githubAPIURL               = "https://api.github.com"
	ghDefaultTimeoutSeconds    = 20
	ghDefaultMaxResponseBytes  = int64(8 * 1024 * 1024)
	ghDefaultRetries           = 2
	ghMaxRateLimitWaitSeconds  = 60.0
	ghMaxPRPages               = 20
	ghMaxPRPerPage             = 100
	ghMaxCommentPages          = 10
	ghMaxComments              = 1000
	ghMaxTreeEntries           = 100000
	ghMaxChangedPaths          = 5000
	ghMaxRenderFiles           = 256
	ghMaxRenderFileBytes       = int64(2 * 1024 * 1024)
	ghMaxRenderTotalBytes      = int64(12 * 1024 * 1024)
	ghMaxArgoFiles             = 64
	ghMaxArgoFileBytes         = int64(512 * 1024)
	ghMaxArgoTotalBytes        = int64(4 * 1024 * 1024)
	ghMaxStatusDescription     = 140
	ghMaxStatusContext         = 100
	ghMaxCommentBytes          = 60000
	ghMaxRepoPathBytes         = 4096
	ghMaxTokenBytes            = 512
	ghOwnerApprovalPermission  = "owner"
	ghChartPathPrefix          = "charts/demo/"
	ghValuesPath               = "gitops/demo/values.yaml"
	ghWorkflowPathPrefix       = ".github/workflows/"
	ghDeploymentRelatedPrefix  = "gitops/argocd/"
	ghRendererPathPrefix       = "charts/demo/"
	ghGitBlobHeaderFmt         = "blob %d\x00"
	ghMaxBlobCacheEntries      = 4096
	ghMaxTreeDiffPathRetention = ghMaxChangedPaths
)

var ghStatusStates = map[string]bool{"error": true, "failure": true, "pending": true, "success": true}
var ghWritePermissions = map[string]bool{"admin": true, "write": true}
var ghClassicStatusScopes = []string{"repo", "repo:status"}

var (
	ghApprovalRE       = regexp.MustCompile(`\A/guard approve ([A-Za-z0-9][A-Za-z0-9_-]{0,127})\z`)
	ghRepoRE           = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\z`)
	ghSHARE            = regexp.MustCompile(`\A[0-9a-f]{40,64}\z`)
	ghLoginRE          = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\z`)
	ghBranchRE         = regexp.MustCompile(`\A[A-Za-z0-9._/-]{1,255}\z`)
	ghSafeControlRE    = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	ghStatusContextRE  = regexp.MustCompile(`\A[A-Za-z0-9._/-]{1,100}\z`)
	ghPrivateKeyRE     = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	ghBearerRE         = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	ghTokenRE          = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}`)
	ghJWTRE            = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`)
	ghDigitRE          = regexp.MustCompile(`\A[0-9]+\z`)
	ghWorkflowSuffixes = []string{"/application.yaml", "/application.yml", "/project.yaml", "/project.yml"}
)

// Deployment-related prefixes that can alter what is deployed even when they
// are not consumed by the trusted Helm renderer.
var ghDeploymentPathPrefixes = []string{
	"charts/",
	"gitops/",
	"argocd/",
	"deploy/",
	"deployment/",
	"deployments/",
	"k8s/",
	"kubernetes/",
	"manifests/",
	"helm/",
	"environments/",
	"env/",
	"terraform/",
	".github/workflows/",
}

var ghRedactKeyParts = []string{
	"token", "secret", "password", "passwd", "authorization", "credential",
	"private_key", "privatekey", "api_key", "apikey", "kubeconfig", "cookie",
}

// GitHubError is a fail-closed GitHub/API error with a sanitized message.
type GitHubError struct {
	Message   string
	Status    int
	Code      string
	Retryable bool
	Details   M
}

func (e *GitHubError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeText(e.Message, 800)
}

// AsDict returns the sanitized error representation used in reports.
func (e *GitHubError) AsDict() M {
	if e == nil {
		return M{}
	}
	return M{
		"code":      e.Code,
		"status":    e.Status,
		"retryable": e.Retryable,
		"message":   e.Error(),
		"details":   Clone(orEmptyM(e.Details)),
	}
}

func ghError(code, format string, args ...any) *GitHubError {
	return &GitHubError{Message: fmt.Sprintf(format, args...), Code: code}
}

func ghErrorStatus(code string, status int, format string, args ...any) *GitHubError {
	return &GitHubError{Message: fmt.Sprintf(format, args...), Code: code, Status: status}
}

func ghIsCode(err error, code string) bool {
	var ge *GitHubError
	if errors.As(err, &ge) {
		return ge.Code == code
	}
	return false
}

func orEmptyM(value M) M {
	if value == nil {
		return M{}
	}
	return value
}

// PullRequestInfo is the sanitized immutable identity of a pull request.
type PullRequestInfo struct {
	Number    int64
	Title     string
	Author    string
	State     string
	Draft     bool
	HeadSHA   string
	HeadRef   string
	HeadRepo  string
	BaseSHA   string
	BaseRef   string
	BaseRepo  string
	CreatedAt int64
	UpdatedAt int64
	RawURL    string
}

// TreeEntry is one validated Git tree object entry.
type TreeEntry struct {
	Path string
	Mode string
	Kind string
	SHA  string
	Size int64
}

// TreeSnapshot is an immutable, digest-bound view of one Git commit tree.
type TreeSnapshot struct {
	SHA           string
	TreeSHA       string
	Entries       map[string]TreeEntry
	RendererFiles map[string][]byte
	ArgoFiles     map[string][]byte
	TreeDigest    string
	EntryCount    int
	RendererBytes int64
	ArgoBytes     int64
}

// PullRequestCandidate is the exact base/head pair to be evaluated.
type PullRequestCandidate struct {
	PullRequest       PullRequestInfo
	BaseSHA           string
	BaseSnapshot      TreeSnapshot
	HeadSnapshot      TreeSnapshot
	ChangedPaths      []string
	ChangedCount      int
	TreeDiffTruncated bool
	Argo              ArgoAnalysis
	PRBaseSHA         string
}

// ArgoAnalysis summarises security-relevant Argo CD manifest changes.
type ArgoAnalysis struct {
	ArgoSourceChanged      bool
	ArgoApplicationChanged bool
	ArgoProjectChanged     bool
	ArgoManifestError      bool
	ArgoChangedPaths       []string
	Applications           int
}

// AsContext renders the Argo analysis into report context.
func (a ArgoAnalysis) AsContext() M {
	paths := a.ArgoChangedPaths
	if paths == nil {
		paths = []string{}
	}
	if len(paths) > 200 {
		paths = paths[:200]
	}
	return M{
		"argo_source_changed":      a.ArgoSourceChanged,
		"argo_application_changed": a.ArgoApplicationChanged,
		"argo_project_changed":     a.ArgoProjectChanged,
		"argo_manifest_error":      a.ArgoManifestError,
		"argo_changed_paths":       paths,
		"argo_application_count":   a.Applications,
	}
}

// ---------------------------------------------------------------------------
// Generic helpers

func sanitizeText(value any, limit int) string {
	text := fmt.Sprint(value)
	text = ghPrivateKeyRE.ReplaceAllString(text, "<redacted>")
	text = ghBearerRE.ReplaceAllString(text, "<redacted>")
	text = ghTokenRE.ReplaceAllString(text, "<redacted>")
	text = ghJWTRE.ReplaceAllString(text, "<redacted>")
	text = ghSafeControlRE.ReplaceAllString(text, " ")
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) > limit {
		if limit <= 3 {
			return string(runes[:maxInt(0, limit)])
		}
		return string(runes[:limit-3]) + "..."
	}
	return text
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ghHeader(headers map[string]string, name string) string {
	lowered := strings.ToLower(name)
	for key, value := range headers {
		if strings.ToLower(key) == lowered {
			return value
		}
	}
	return ""
}

func ghParseRetryAfter(value string) (float64, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return 0, false
	}
	return seconds, true
}

func ghParseTime(value any) (int64, bool) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return 0, false
	}
	text = strings.TrimSpace(text)
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04:05.999999999"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.Unix(), true
		}
	}
	return 0, false
}

func ghISOUTC(timestamp int64) string {
	if timestamp == 0 {
		return "unknown"
	}
	return time.Unix(timestamp, 0).UTC().Format("2006-01-02T15:04:05Z")
}

func normalizeRepoPath(value any) (string, error) {
	path, ok := value.(string)
	if !ok || path == "" {
		return "", ghError("path_invalid", "repository path is empty or not a string")
	}
	if len([]byte(path)) > ghMaxRepoPathBytes {
		return "", ghError("path_invalid", "repository path exceeds the size limit")
	}
	if strings.Contains(path, "\\") || strings.ContainsRune(path, 0) || ghSafeControlRE.MatchString(path) {
		return "", ghError("path_invalid", "repository path contains a forbidden character: %q", path)
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return "", ghError("path_invalid", "repository path is not a clean relative path: %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return "", ghError("path_traversal", "repository path contains a traversal component: %q", path)
		}
	}
	return path, nil
}

func isDeploymentPath(path string) bool {
	lowered := strings.ToLower(path)
	for _, prefix := range ghDeploymentPathPrefixes {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	return false
}

func isRendererPath(path string) bool {
	return path == ghValuesPath || strings.HasPrefix(path, ghRendererPathPrefix)
}

func isArgoPath(path string) bool {
	lowered := strings.ToLower(path)
	if strings.HasPrefix(lowered, "gitops/argocd/") || strings.HasPrefix(lowered, "argocd/") {
		return true
	}
	for _, suffix := range ghWorkflowSuffixes {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	switch lowered {
	case "application.yaml", "application.yml", "project.yaml", "project.yml":
		return true
	}
	return false
}

func parseApprovalBody(body any) (string, bool) {
	text, ok := body.(string)
	if !ok {
		return "", false
	}
	match := ghApprovalRE.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return "", false
	}
	return match[1], true
}

func ghValidateBranch(branch any) (string, error) {
	text, ok := branch.(string)
	if !ok || !ghBranchRE.MatchString(text) {
		return "", ghError("invalid_branch", "base branch name is invalid")
	}
	if strings.HasPrefix(text, "/") || strings.HasSuffix(text, "/") {
		return "", ghError("invalid_branch", "base branch name contains a traversal component")
	}
	for _, part := range strings.Split(text, "/") {
		if part == ".." {
			return "", ghError("invalid_branch", "base branch name contains a traversal component")
		}
	}
	return text, nil
}

func ghValidateSHA(value any, label string) (string, error) {
	text, ok := value.(string)
	if !ok || !ghSHARE.MatchString(text) {
		return "", ghError("invalid_sha", "%s is not a hexadecimal Git object id", label)
	}
	return text, nil
}

func ghValidateLogin(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !ghLoginRE.MatchString(text) {
		return "", ghError("invalid_login", "GitHub login is invalid")
	}
	return text, nil
}

func ghSanitizeStatusDescription(value any) string {
	text := sanitizeText(value, ghMaxStatusDescription)
	if text == "" {
		return "change-guard evaluation"
	}
	return text
}

func ghSanitizeStatusContext(value any) (string, error) {
	text := sanitizeText(value, ghMaxStatusContext)
	if !ghStatusContextRE.MatchString(text) {
		return "", ghError("invalid_status_context", "status context contains unsupported characters")
	}
	return text, nil
}

func ghValidSHA(value string) bool {
	return ghSHARE.MatchString(value)
}

func ghInt(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		return int64(number), true
	case uint64:
		if number > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		parsed, err := number.Int64()
		if err == nil {
			return parsed, true
		}
		f, err := number.Float64()
		if err != nil || f != math.Trunc(f) {
			return 0, false
		}
		return int64(f), true
	}
	return 0, false
}

func ghNumber(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, !math.IsNaN(number) && !math.IsInf(number, 0)
	case json.Number:
		f, err := number.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	if i, ok := ghInt(value); ok {
		return float64(i), true
	}
	return 0, false
}

func ghQuotePathSegment(segment string) string {
	return url.PathEscape(segment)
}

func ghBranchPath(branch string) string {
	// Branch slashes are part of the path; quote everything else.
	escaped := url.PathEscape(branch)
	return strings.ReplaceAll(escaped, "%2F", "/")
}

// ---------------------------------------------------------------------------
// Filesystem materialisation

// Materialize writes only pre-validated renderer files below destination.
func (s TreeSnapshot) Materialize(destination string) ([]string, error) {
	root, err := filepath.Abs(destination)
	if err != nil {
		return nil, ghError("path_not_permitted", "materialisation root is invalid")
	}
	if info, statErr := os.Lstat(root); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ghError("symlink_not_permitted", "materialisation root must not be a symlink")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, ghError("path_not_permitted", "cannot create materialisation root")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, ghError("path_not_permitted", "materialisation root is not a directory")
	}

	names := make([]string, 0, len(s.RendererFiles))
	for name := range s.RendererFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	written := make([]string, 0, len(names))
	for _, relative := range names {
		path, pathErr := normalizeRepoPath(relative)
		if pathErr != nil {
			return nil, pathErr
		}
		if !isRendererPath(path) {
			return nil, ghError("path_not_permitted", "refusing to materialise non-renderer path %q", path)
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		if !ghWithinRoot(root, target) {
			return nil, ghError("path_traversal", "materialised path escapes its root: %q", path)
		}
		parts := strings.Split(path, "/")
		current := root
		for _, part := range parts[:len(parts)-1] {
			current = filepath.Join(current, part)
			if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return nil, ghError("symlink_not_permitted", "materialisation parent is a symlink: %q", path)
			}
			if _, statErr := os.Stat(current); os.IsNotExist(statErr) {
				if mkErr := os.Mkdir(current, 0700); mkErr != nil {
					return nil, ghError("path_not_permitted", "cannot create materialisation parent")
				}
			}
			if info, statErr := os.Stat(current); statErr != nil || !info.IsDir() {
				return nil, ghError("path_not_permitted", "materialisation parent is not a directory: %q", path)
			}
		}
		if _, statErr := os.Lstat(target); statErr == nil {
			return nil, ghError("path_not_permitted", "refusing to overwrite existing file %q", path)
		}
		descriptor, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return nil, ghError("path_not_permitted", "cannot create materialised file %q", path)
		}
		content := s.RendererFiles[relative]
		if _, writeErr := descriptor.Write(content); writeErr != nil {
			_ = descriptor.Close()
			_ = os.Remove(target)
			return nil, ghError("path_not_permitted", "cannot write materialised file %q", path)
		}
		if syncErr := descriptor.Sync(); syncErr != nil {
			_ = descriptor.Close()
			_ = os.Remove(target)
			return nil, ghError("path_not_permitted", "cannot sync materialised file %q", path)
		}
		if closeErr := descriptor.Close(); closeErr != nil {
			_ = os.Remove(target)
			return nil, ghError("path_not_permitted", "cannot close materialised file %q", path)
		}
		written = append(written, path)
	}
	return written, nil
}

func ghWithinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if relative == "." {
		return true
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func ghTreeDigest(entries map[string]TreeEntry) string {
	values := make([]TreeEntry, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Path < values[j].Path })
	payload := make([]any, len(values))
	for index, entry := range values {
		payload[index] = []any{entry.Path, entry.Mode, entry.Kind, entry.SHA}
	}
	return Hash(payload)
}

// ---------------------------------------------------------------------------
// HTTP transport

// GitHub is the bounded GitHub REST client used by the daemon and merger.
type GitHub struct {
	repository       string
	owner            string
	repo             string
	token            string
	baseURL          string
	httpClient       *http.Client
	timeout          time.Duration
	maxResponseBytes int64
	retries          int
	sleep            func(time.Duration)
	baseBranch       string
	lastHeaders      map[string]string
	blobCache        map[string][]byte
}

// NewGitHub builds the client from validated configuration. The API host is
// intentionally not configurable; this prevents an SSRF primitive.
func NewGitHub(config M) (*GitHub, error) {
	return ghNewGitHubWith(config, githubAPIURL, nil)
}

func ghNewGitHubWith(config M, baseURL string, httpClient *http.Client) (*GitHub, error) {
	if config == nil {
		return nil, ghError("invalid_config", "config must be a mapping")
	}
	repository, ok := config["repository"].(string)
	if !ok || !ghRepoRE.MatchString(repository) {
		return nil, ghError("invalid_repository", "repository must be in owner/name form")
	}
	owner, name, _ := strings.Cut(repository, "/")
	if owner == "." || owner == ".." || name == "." || name == ".." {
		return nil, ghError("invalid_repository", "repository owner/name is invalid")
	}
	token, err := Token(config, "github")
	if err != nil {
		return nil, ghError("invalid_token", "GitHub token is missing or malformed")
	}
	if len(token) > ghMaxTokenBytes || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return nil, ghError("invalid_token", "GitHub token is missing or malformed")
	}
	timeout := CfgNum(config, "github_timeout_seconds", ghDefaultTimeoutSeconds)
	if timeout != math.Trunc(timeout) || timeout < 1 || timeout > 120 {
		return nil, ghError("invalid_timeout", "GitHub timeout must be between 1 and 120 seconds")
	}
	maxBytes := CfgNum(config, "github_max_response_bytes", float64(ghDefaultMaxResponseBytes))
	if maxBytes != math.Trunc(maxBytes) || maxBytes < 4096 || maxBytes > 64*1024*1024 {
		return nil, ghError("invalid_limit", "GitHub response size limit is invalid")
	}
	retries := CfgNum(config, "github_retries", ghDefaultRetries)
	if retries != math.Trunc(retries) || retries < 0 || retries > 5 {
		return nil, ghError("invalid_retries", "GitHub retry count is invalid")
	}
	baseBranch := "main"
	if raw, present := config["base_branch"]; present {
		baseBranch, err = ghValidateBranch(raw)
		if err != nil {
			return nil, err
		}
	}
	proxyEnv := true
	if raw, present := config["use_proxy_env"]; present {
		flag, isBool := raw.(bool)
		if !isBool {
			return nil, ghError("invalid_config", "use_proxy_env must be boolean")
		}
		proxyEnv = flag
	}
	client := httpClient
	if client == nil {
		transport := &http.Transport{}
		if proxyEnv {
			transport.Proxy = http.ProxyFromEnvironment
		}
		client = &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &GitHub{
		repository:       repository,
		owner:            owner,
		repo:             name,
		token:            token,
		baseURL:          strings.TrimRight(baseURL, "/"),
		httpClient:       client,
		timeout:          time.Duration(int(timeout)) * time.Second,
		maxResponseBytes: int64(maxBytes),
		retries:          int(retries),
		sleep:            time.Sleep,
		baseBranch:       baseBranch,
		lastHeaders:      map[string]string{},
		blobCache:        map[string][]byte{},
	}, nil
}

// API performs one bounded GitHub REST request. body is JSON encoded when not
// nil; the response is decoded into dynamic JSON values.
func (g *GitHub) API(method, path string, body any) (any, error) {
	data, _, err := g.request(method, path, nil, body, map[int]bool{200: true, 201: true, 202: true, 204: true}, nil)
	return data, err
}

func (g *GitHub) readBody(response *http.Response) ([]byte, error) {
	if value := response.Header.Get("Content-Length"); value != "" {
		if length, parseErr := strconv.ParseInt(value, 10, 64); parseErr == nil && length > g.maxResponseBytes {
			return nil, ghError("response_too_large", "GitHub response exceeded the size limit")
		}
	}
	limited := io.LimitReader(response.Body, g.maxResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, ghError("network_error", "GitHub response could not be read")
	}
	if int64(len(raw)) > g.maxResponseBytes {
		return nil, ghError("response_too_large", "GitHub response exceeded the size limit")
	}
	return raw, nil
}

func ghDecodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return value, nil
}

func (g *GitHub) request(method, path string, params url.Values, body any, expected map[int]bool, retries *int) (any, map[string]string, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "://") || ghSafeControlRE.MatchString(path) || strings.ContainsAny(path, " \t\r\n") {
		return nil, nil, ghError("invalid_path", "GitHub API path is invalid")
	}
	attempts := g.retries
	if retries != nil {
		attempts = *retries
	}
	if attempts < 0 || attempts > 5 {
		return nil, nil, ghError("invalid_retries", "GitHub retry count is invalid")
	}
	parsed, err := url.Parse(g.baseURL + path)
	if err != nil {
		return nil, nil, ghError("invalid_path", "GitHub API path is invalid")
	}
	if params != nil {
		parsed.RawQuery = params.Encode()
	}
	var encodedBody []byte
	if body != nil {
		encodedBody, err = json.Marshal(body)
		if err != nil {
			return nil, nil, ghError("invalid_body", "GitHub request body is not JSON serializable")
		}
	}
	headers := map[string]string{
		"Authorization":        "Bearer " + g.token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
		"User-Agent":           "k8s-change-guard/1",
	}
	lastError := ghError("network_error", "GitHub request failed")
	for attempt := 0; attempt <= attempts; attempt++ {
		var reader io.Reader
		if encodedBody != nil {
			reader = bytes.NewReader(encodedBody)
		}
		requestContext, cancel := context.WithTimeout(context.Background(), g.timeout)
		request, reqErr := http.NewRequestWithContext(requestContext, method, parsed.String(), reader)
		if reqErr != nil {
			cancel()
			return nil, nil, ghError("transport_error", "GitHub transport failed")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, requestErr := g.httpClient.Do(request)
		if requestErr != nil {
			cancel()
			lastError = &GitHubError{Message: "GitHub request failed: network error", Code: "network_error", Retryable: true}
			if attempt < attempts {
				g.sleep(ghBackoff(attempt))
				continue
			}
			return nil, nil, lastError
		}
		responseHeaders := map[string]string{}
		for key, values := range response.Header {
			if len(values) > 0 {
				responseHeaders[key] = values[0]
			}
		}
		status := response.StatusCode
		var raw []byte
		if status != 204 && status != 304 {
			raw, err = g.readBody(response)
			_ = response.Body.Close()
			cancel()
			if err != nil {
				return nil, nil, err
			}
		} else {
			_ = response.Body.Close()
			cancel()
		}
		g.lastHeaders = responseHeaders

		if expected[status] {
			if len(raw) == 0 {
				return nil, responseHeaders, nil
			}
			value, decodeErr := ghDecodeJSON(raw)
			if decodeErr != nil {
				return nil, nil, ghError("invalid_json", "GitHub returned invalid JSON")
			}
			return value, responseHeaders, nil
		}

		switch status {
		case 301, 302, 303, 307, 308:
			return nil, responseHeaders, ghErrorStatus("redirect_refused", status, "GitHub redirects are not followed")
		}

		if status == 403 || status == 429 {
			remaining := ghHeader(responseHeaders, "X-RateLimit-Remaining")
			retryAfter, hasRetryAfter := ghParseRetryAfter(ghHeader(responseHeaders, "Retry-After"))
			reset := ghHeader(responseHeaders, "X-RateLimit-Reset")
			wait := 0.0
			haveWait := false
			if hasRetryAfter {
				wait = retryAfter
				haveWait = true
			}
			if !haveWait && remaining == "0" && reset != "" {
				if epoch, parseErr := strconv.ParseFloat(reset, 64); parseErr == nil {
					wait = math.Max(1.0, epoch-float64(time.Now().Unix())+1.0)
					haveWait = true
				}
			}
			rateLimited := remaining == "0" || hasRetryAfter || status == 429
			if rateLimited {
				if !haveWait {
					wait = 5.0
				}
				if wait > ghMaxRateLimitWaitSeconds {
					return nil, responseHeaders, &GitHubError{
						Message: "GitHub rate limit requires a wait longer than the configured bound",
						Status:  status,
						Code:    "rate_limited",
						Details: M{"retry_after_seconds": math.Round(wait*10) / 10},
					}
				}
				lastError = &GitHubError{
					Message:   "GitHub rate limit was reached",
					Status:    status,
					Code:      "rate_limited",
					Retryable: true,
					Details:   M{"retry_after_seconds": math.Round(wait*10) / 10},
				}
				if attempt < attempts {
					g.sleep(time.Duration(math.Min(wait, ghMaxRateLimitWaitSeconds) * float64(time.Second)))
					continue
				}
				return nil, responseHeaders, lastError
			}
		}

		if status >= 500 {
			lastError = &GitHubError{
				Message:   fmt.Sprintf("GitHub API returned HTTP %d", status),
				Status:    status,
				Code:      "server_error",
				Retryable: true,
			}
			if attempt < attempts {
				g.sleep(ghBackoff(attempt))
				continue
			}
			return nil, responseHeaders, lastError
		}

		detail := "no response body"
		if len(raw) > 0 {
			detail = sanitizeText(string(raw), 400)
		}
		switch status {
		case 401:
			return nil, responseHeaders, ghErrorStatus("unauthorized", status, "GitHub authentication failed (HTTP 401)")
		case 403:
			return nil, responseHeaders, ghErrorStatus("forbidden", status, "GitHub authorization failed (HTTP 403)")
		case 404:
			return nil, responseHeaders, ghErrorStatus("not_found", status, "GitHub resource was not found (HTTP 404)")
		case 422:
			return nil, responseHeaders, ghErrorStatus("unprocessable", status, "GitHub rejected the request (HTTP 422): %s", detail)
		}
		return nil, responseHeaders, ghErrorStatus("http_error", status, "GitHub API returned HTTP %d: %s", status, detail)
	}
	return nil, nil, lastError
}

func ghBackoff(attempt int) time.Duration {
	seconds := 1 << attempt
	if seconds > 8 {
		seconds = 8
	}
	return time.Duration(seconds) * time.Second
}

func (g *GitHub) get(path string, params url.Values) (any, error) {
	data, _, err := g.request("GET", path, params, nil, map[int]bool{200: true}, nil)
	return data, err
}

func (g *GitHub) getWithHeaders(path string, params url.Values) (any, map[string]string, error) {
	return g.request("GET", path, params, nil, map[int]bool{200: true}, nil)
}

// ---------------------------------------------------------------------------
// Credentials

// VerifyCredentials verifies the token's documented repository capabilities.
func (g *GitHub) VerifyCredentials(probeStatusSHA string) (M, error) {
	userValue, userHeaders, err := g.getWithHeaders("/user", nil)
	if err != nil {
		return nil, err
	}
	user, ok := userValue.(map[string]any)
	if !ok {
		return nil, ghError("invalid_credentials", "GitHub /user response is invalid")
	}
	login, err := ghValidateLogin(user["login"])
	if err != nil {
		return nil, ghError("invalid_credentials", "GitHub /user response is invalid")
	}
	repoValue, err := g.get("/repos/"+g.owner+"/"+g.repo, nil)
	if err != nil {
		return nil, err
	}
	repo, ok := repoValue.(map[string]any)
	if !ok {
		return nil, ghError("invalid_credentials", "GitHub repository response is invalid")
	}
	if !strings.EqualFold(Str(repo["full_name"]), g.repository) {
		return nil, ghError("wrong_repository", "GitHub token resolved to a different repository")
	}
	permissions := M{}
	if raw, present := repo["permissions"].(map[string]any); present {
		for _, key := range []string{"admin", "maintain", "push", "triage", "pull"} {
			if value, exists := raw[key]; exists {
				permissions[key] = Bool(value)
			}
		}
	}
	isPrivate := Bool(repo["private"])
	scopesHeader := ghHeader(userHeaders, "X-OAuth-Scopes")
	scopes := []string{}
	tokenKind := "fine-grained-or-unknown"
	statusWrite := "inferred"
	if scopesHeader != "" {
		seen := map[string]bool{}
		for _, item := range strings.Split(scopesHeader, ",") {
			item = strings.TrimSpace(item)
			if item != "" && !seen[item] {
				seen[item] = true
				scopes = append(scopes, item)
			}
		}
		sort.Strings(scopes)
		allowed := map[string]bool{"repo": true, "repo:status": true}
		if !isPrivate {
			allowed["public_repo"] = true
		}
		hasScope := false
		for _, scope := range scopes {
			if allowed[scope] {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return nil, ghError("missing_status_scope", "classic token lacks commit-status write scope (repo, public_repo, or repo:status)")
		}
		statusWrite = "verified-by-scope"
		tokenKind = "classic"
	} else {
		if !Bool(permissions["admin"]) && !Bool(permissions["push"]) {
			return nil, ghError("missing_repo_write", "fine-grained token lacks push/admin repository permission")
		}
	}
	defaultBranch := Str(repo["default_branch"])
	if _, _, err = g.request("GET", "/repos/"+g.owner+"/"+g.repo+"/pulls", url.Values{
		"state": {"open"}, "base": {ifEmpty(defaultBranch, "main")}, "per_page": {"1"},
	}, nil, map[int]bool{200: true}, nil); err != nil {
		return nil, err
	}
	if defaultBranch != "" {
		branchValue, branchErr := g.get("/repos/"+g.owner+"/"+g.repo+"/git/ref/heads/"+ghBranchPath(defaultBranch), nil)
		if branchErr != nil {
			return nil, branchErr
		}
		if branch, isMap := branchValue.(map[string]any); isMap {
			if object, isObj := branch["object"].(map[string]any); isObj {
				if sha, isStr := object["sha"].(string); isStr && ghSHARE.MatchString(sha) {
					if _, _, statusErr := g.request("GET", "/repos/"+g.owner+"/"+g.repo+"/commits/"+sha+"/statuses", nil, nil, map[int]bool{200: true}, nil); statusErr != nil {
						return nil, statusErr
					}
				}
			}
		}
	}
	if probeStatusSHA != "" {
		if !ghSHARE.MatchString(probeStatusSHA) {
			return nil, ghError("invalid_probe_sha", "credential probe SHA is invalid")
		}
		if _, err = g.CreateCommitStatus(probeStatusSHA, "pending", "credential capability probe", "change-guard/credential-probe", ""); err != nil {
			return nil, err
		}
		statusWrite = "verified-by-write"
	}
	return M{
		"status":         "ok",
		"login":          login,
		"repository":     g.repository,
		"private":        isPrivate,
		"token_kind":     tokenKind,
		"scopes":         scopes,
		"permissions":    permissions,
		"statuses_write": statusWrite,
		"default_branch": nullableString(defaultBranch),
	}, nil
}

func ifEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// ---------------------------------------------------------------------------
// Pull requests

// GetPullRequest reads one pull request identity.
func (g *GitHub) GetPullRequest(number int64) (PullRequestInfo, error) {
	if number < 1 {
		return PullRequestInfo{}, ghError("invalid_pr", "pull request number is invalid")
	}
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/pulls/%d", g.owner, g.repo, number), nil)
	if err != nil {
		return PullRequestInfo{}, err
	}
	return ghNormalizePullRequest(data)
}

// ListOpenPullRequests pages all open pull requests targeting baseBranch.
func (g *GitHub) ListOpenPullRequests(baseBranch string, perPage, maxPages int) ([]PullRequestInfo, error) {
	branch, err := ghValidateBranch(baseBranch)
	if err != nil {
		return nil, err
	}
	if perPage == 0 {
		perPage = ghMaxPRPerPage
	}
	if maxPages == 0 {
		maxPages = ghMaxPRPages
	}
	if perPage < 1 || perPage > ghMaxPRPerPage {
		return nil, ghError("invalid_pagination", "pull request page size is invalid")
	}
	if maxPages < 1 || maxPages > ghMaxPRPages {
		return nil, ghError("invalid_pagination", "pull request page limit is invalid")
	}
	results := []PullRequestInfo{}
	for page := 1; page <= maxPages; page++ {
		data, getErr := g.get(fmt.Sprintf("/repos/%s/%s/pulls", g.owner, g.repo), url.Values{
			"state":     {"open"},
			"base":      {branch},
			"sort":      {"created"},
			"direction": {"asc"},
			"per_page":  {strconv.Itoa(perPage)},
			"page":      {strconv.Itoa(page)},
		})
		if getErr != nil {
			return nil, getErr
		}
		items, ok := data.([]any)
		if !ok {
			return nil, ghError("invalid_response", "GitHub pull request listing is not a list")
		}
		if len(items) > perPage {
			return nil, ghError("invalid_response", "GitHub returned more pull requests than requested")
		}
		for _, item := range items {
			info, infoErr := ghNormalizePullRequest(item)
			if infoErr != nil {
				return nil, infoErr
			}
			if info.BaseRef != branch || info.State != "open" {
				continue
			}
			results = append(results, info)
		}
		if len(items) < perPage {
			break
		}
	}
	return results, nil
}

// GetBranchHead reads the exact current commit of a branch.
func (g *GitHub) GetBranchHead(branch string) (string, error) {
	validated, err := ghValidateBranch(branch)
	if err != nil {
		return "", err
	}
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", g.owner, g.repo, ghBranchPath(validated)), nil)
	if err != nil {
		return "", err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return "", ghError("invalid_response", "GitHub branch response is invalid")
	}
	rawObject, ok := object["object"].(map[string]any)
	if !ok {
		return "", ghError("invalid_response", "GitHub branch response is invalid")
	}
	return ghValidateSHA(rawObject["sha"], "branch head")
}

func ghNormalizePullRequest(data any) (PullRequestInfo, error) {
	object, ok := data.(map[string]any)
	if !ok {
		return PullRequestInfo{}, ghError("invalid_response", "GitHub pull request response is invalid")
	}
	number, ok := ghInt(object["number"])
	if !ok || number < 1 {
		return PullRequestInfo{}, ghError("invalid_response", "GitHub pull request has no valid number")
	}
	head := asM(object["head"])
	base := asM(object["base"])
	headRepo := asM(head["repo"])
	baseRepo := asM(base["repo"])
	headSHA, err := ghValidateSHA(head["sha"], "pull request head")
	if err != nil {
		return PullRequestInfo{}, err
	}
	baseSHA, err := ghValidateSHA(base["sha"], "pull request base")
	if err != nil {
		return PullRequestInfo{}, err
	}
	user := asM(object["user"])
	info := PullRequestInfo{
		Number:   number,
		Title:    sanitizeText(Str(object["title"]), 300),
		Author:   truncateRunes(Str(user["login"]), 100),
		State:    Str(object["state"]),
		Draft:    Bool(object["draft"]),
		HeadSHA:  headSHA,
		HeadRef:  truncateRunes(Str(head["ref"]), 255),
		HeadRepo: truncateRunes(Str(headRepo["full_name"]), 200),
		BaseSHA:  baseSHA,
		BaseRef:  truncateRunes(Str(base["ref"]), 255),
		BaseRepo: truncateRunes(Str(baseRepo["full_name"]), 200),
		RawURL:   "",
	}
	if created, ok := ghParseTime(object["created_at"]); ok {
		info.CreatedAt = created
	}
	if updated, ok := ghParseTime(object["updated_at"]); ok {
		info.UpdatedAt = updated
	}
	if rawURL, isStr := object["html_url"].(string); isStr {
		info.RawURL = rawURL
	}
	return info, nil
}

func asM(value any) M {
	if object, ok := value.(map[string]any); ok && object != nil {
		return object
	}
	return M{}
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

// ---------------------------------------------------------------------------
// Trees / blobs

func (g *GitHub) commitTreeSHA(sha string) (string, error) {
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/git/commits/%s", g.owner, g.repo, sha), nil)
	if err != nil {
		return "", err
	}
	tree := asM(asM(data)["tree"])
	return ghValidateSHA(tree["sha"], "commit tree")
}

func (g *GitHub) listTreeEntries(treeSHA string) (map[string]TreeEntry, error) {
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/git/trees/%s", g.owner, g.repo, treeSHA), url.Values{"recursive": {"1"}})
	if err != nil {
		return nil, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, ghError("invalid_tree", "Git tree response is invalid")
	}
	if Bool(object["truncated"]) {
		return nil, ghError("tree_truncated", "GitHub truncated the recursive tree; refusing an incomplete candidate")
	}
	rawEntries, ok := object["tree"].([]any)
	if !ok {
		return nil, ghError("invalid_tree", "Git tree response has no entries")
	}
	if len(rawEntries) > ghMaxTreeEntries {
		return nil, ghError("tree_too_large", "Git tree has too many entries")
	}
	entries := map[string]TreeEntry{}
	for _, raw := range rawEntries {
		item, ok := raw.(map[string]any)
		if !ok {
			return nil, ghError("invalid_tree", "Git tree contains a non-object entry")
		}
		path, pathErr := normalizeRepoPath(item["path"])
		if pathErr != nil {
			return nil, pathErr
		}
		mode := fmt.Sprint(item["mode"])
		kind := fmt.Sprint(item["type"])
		sha := Str(item["sha"])
		size, _ := ghInt(item["size"])
		if _, exists := entries[path]; exists {
			return nil, ghError("duplicate_path", "Git tree contains duplicate path %q", path)
		}
		if kind == "commit" || mode == "160000" {
			return nil, ghError("submodule_not_permitted", "submodule is not permitted: %q", path)
		}
		if mode == "120000" || kind == "symlink" {
			return nil, ghError("symlink_not_permitted", "symlink is not permitted: %q", path)
		}
		if kind == "tree" {
			if mode != "040000" && mode != "40000" {
				return nil, ghError("invalid_mode", "directory has an unsafe mode: %q", path)
			}
			entries[path] = TreeEntry{Path: path, Mode: leftPad(mode, 6, '0'), Kind: "tree", SHA: sha, Size: 0}
			continue
		}
		if kind != "blob" {
			return nil, ghError("invalid_type", "unsupported Git tree entry type %q for %q", kind, path)
		}
		if mode != "100644" && mode != "100755" {
			return nil, ghError("invalid_mode", "blob has an unsafe mode %q: %q", mode, path)
		}
		if _, shaErr := ghValidateSHA(sha, fmt.Sprintf("blob sha for %s", path)); shaErr != nil {
			return nil, shaErr
		}
		if size < 0 {
			return nil, ghError("invalid_size", "blob size is invalid for %q", path)
		}
		entries[path] = TreeEntry{Path: path, Mode: mode, Kind: "blob", SHA: sha, Size: size}
	}
	return entries, nil
}

func leftPad(value string, width int, fill rune) string {
	if len(value) >= width {
		return value
	}
	return strings.Repeat(string(fill), width-len(value)) + value
}

func (g *GitHub) fetchBlob(sha string, size, limit int64) ([]byte, error) {
	if size > limit {
		return nil, &GitHubError{
			Message: fmt.Sprintf("Git blob %s exceeds the per-file size limit", sha[:minInt(12, len(sha))]),
			Code:    "blob_too_large",
			Details: M{"size": size, "limit": limit},
		}
	}
	if cached, ok := g.blobCache[sha]; ok {
		return cached, nil
	}
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/git/blobs/%s", g.owner, g.repo, sha), nil)
	if err != nil {
		return nil, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, ghError("invalid_blob", "Git blob response is invalid")
	}
	if Str(object["encoding"]) != "base64" {
		return nil, ghError("invalid_blob", "Git blob encoding is not base64")
	}
	content, ok := object["content"].(string)
	if !ok {
		return nil, ghError("invalid_blob", "Git blob has no content")
	}
	// GitHub wraps blob base64 at fixed line lengths. Strip only transport
	// whitespace; strict validation still rejects bad data.
	var stripped strings.Builder
	for _, char := range content {
		if !unicode.IsSpace(char) {
			stripped.WriteRune(char)
		}
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(stripped.String())
	if decodeErr != nil {
		return nil, ghError("invalid_blob", "Git blob content is not valid base64")
	}
	if int64(len(raw)) > limit {
		return nil, ghError("blob_too_large", "Git blob exceeded the per-file size limit")
	}
	if expected, ok := ghInt(object["size"]); ok && expected != int64(len(raw)) {
		return nil, ghError("invalid_blob", "Git blob size does not match its response")
	}
	if int64(len(raw)) != size {
		return nil, ghError("invalid_blob", "Git blob size does not match the tree entry")
	}
	header := fmt.Sprintf(ghGitBlobHeaderFmt, len(raw))
	digest := sha1.New()
	_, _ = digest.Write([]byte(header))
	_, _ = digest.Write(raw)
	gitSHA := hex.EncodeToString(digest.Sum(nil))
	if gitSHA != sha {
		return nil, ghError("blob_corrupt", "Git blob content does not match its tree object id")
	}
	if len(g.blobCache) < ghMaxBlobCacheEntries {
		g.blobCache[sha] = raw
	}
	return raw, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FetchTreeSnapshot fetches and validates one commit tree.
func (g *GitHub) FetchTreeSnapshot(sha string, includeArgo bool) (TreeSnapshot, error) {
	sha, err := ghValidateSHA(sha, "commit sha")
	if err != nil {
		return TreeSnapshot{}, err
	}
	treeSHA, err := g.commitTreeSHA(sha)
	if err != nil {
		return TreeSnapshot{}, err
	}
	entries, err := g.listTreeEntries(treeSHA)
	if err != nil {
		return TreeSnapshot{}, err
	}
	rendererEntries := make([]TreeEntry, 0)
	for _, entry := range entries {
		if entry.Kind == "blob" && isRendererPath(entry.Path) {
			rendererEntries = append(rendererEntries, entry)
		}
	}
	if len(rendererEntries) > ghMaxRenderFiles {
		return TreeSnapshot{}, ghError("renderer_too_large", "renderer tree contains too many files")
	}
	sort.Slice(rendererEntries, func(i, j int) bool { return rendererEntries[i].Path < rendererEntries[j].Path })
	rendererFiles := map[string][]byte{}
	var rendererBytes int64
	for _, entry := range rendererEntries {
		raw, blobErr := g.fetchBlob(entry.SHA, entry.Size, ghMaxRenderFileBytes)
		if blobErr != nil {
			return TreeSnapshot{}, blobErr
		}
		rendererBytes += int64(len(raw))
		if rendererBytes > ghMaxRenderTotalBytes {
			return TreeSnapshot{}, ghError("renderer_too_large", "renderer tree exceeds the total size limit")
		}
		rendererFiles[entry.Path] = raw
	}

	argoFiles := map[string][]byte{}
	var argoBytes int64
	if includeArgo {
		argoEntries := make([]TreeEntry, 0)
		for _, entry := range entries {
			if entry.Kind == "blob" && isArgoPath(entry.Path) {
				argoEntries = append(argoEntries, entry)
			}
		}
		if len(argoEntries) > ghMaxArgoFiles {
			return TreeSnapshot{}, ghError("argo_tree_too_large", "too many Argo/deployment manifest files")
		}
		sort.Slice(argoEntries, func(i, j int) bool { return argoEntries[i].Path < argoEntries[j].Path })
		for _, entry := range argoEntries {
			raw, blobErr := g.fetchBlob(entry.SHA, entry.Size, ghMaxArgoFileBytes)
			if blobErr != nil {
				return TreeSnapshot{}, blobErr
			}
			argoBytes += int64(len(raw))
			if argoBytes > ghMaxArgoTotalBytes {
				return TreeSnapshot{}, ghError("argo_tree_too_large", "Argo manifest set exceeds the total size limit")
			}
			argoFiles[entry.Path] = raw
		}
	}

	return TreeSnapshot{
		SHA:           sha,
		TreeSHA:       treeSHA,
		Entries:       entries,
		RendererFiles: rendererFiles,
		ArgoFiles:     argoFiles,
		TreeDigest:    ghTreeDigest(entries),
		EntryCount:    len(entries),
		RendererBytes: rendererBytes,
		ArgoBytes:     argoBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// Candidate

// FetchPullRequestCandidate fetches the exact current-base/head pair.
func (g *GitHub) FetchPullRequestCandidate(number int64, allowFork bool) (PullRequestCandidate, error) {
	pr, err := g.GetPullRequest(number)
	if err != nil {
		return PullRequestCandidate{}, err
	}
	if pr.State != "open" {
		return PullRequestCandidate{}, ghError("pr_not_open", "pull request is not open")
	}
	if pr.BaseRef != g.baseBranch {
		return PullRequestCandidate{}, ghError("wrong_base_branch", "pull request does not target the configured base branch")
	}
	if !strings.EqualFold(pr.BaseRepo, g.repository) {
		return PullRequestCandidate{}, ghError("wrong_base_repo", "pull request base repository is not the configured repository")
	}
	if !strings.EqualFold(pr.HeadRepo, g.repository) && !allowFork {
		return PullRequestCandidate{}, ghError("fork_not_allowed", "fork pull requests are not evaluated by this guard")
	}
	currentBase, err := g.GetBranchHead(pr.BaseRef)
	if err != nil {
		return PullRequestCandidate{}, err
	}
	baseSnapshot, err := g.FetchTreeSnapshot(currentBase, true)
	if err != nil {
		return PullRequestCandidate{}, err
	}
	headSnapshot, err := g.FetchTreeSnapshot(pr.HeadSHA, true)
	if err != nil {
		return PullRequestCandidate{}, err
	}
	changedPaths, changedCount, truncated := ghDiffEntries(baseSnapshot.Entries, headSnapshot.Entries)
	argo := analyzeArgo(baseSnapshot, headSnapshot, changedPaths)
	return PullRequestCandidate{
		PullRequest:       pr,
		BaseSHA:           currentBase,
		BaseSnapshot:      baseSnapshot,
		HeadSnapshot:      headSnapshot,
		ChangedPaths:      changedPaths,
		ChangedCount:      changedCount,
		TreeDiffTruncated: truncated,
		Argo:              argo,
		PRBaseSHA:         pr.BaseSHA,
	}, nil
}

func ghDiffEntries(base, head map[string]TreeEntry) ([]string, int, bool) {
	union := map[string]bool{}
	for path := range base {
		union[path] = true
	}
	for path := range head {
		union[path] = true
	}
	ordered := make([]string, 0, len(union))
	for path := range union {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	paths := make([]string, 0)
	seen := 0
	truncated := false
	for _, path := range ordered {
		oldEntry, oldOK := base[path]
		newEntry, newOK := head[path]
		if (oldOK && oldEntry.Kind == "tree") || (newOK && newEntry.Kind == "tree") {
			continue
		}
		if oldOK && newOK && oldEntry.Mode == newEntry.Mode && oldEntry.Kind == newEntry.Kind && oldEntry.SHA == newEntry.SHA {
			continue
		}
		if !oldOK || !newOK || oldEntry.SHA != newEntry.SHA || oldEntry.Mode != newEntry.Mode {
			seen++
			if len(paths) < ghMaxTreeDiffPathRetention {
				paths = append(paths, path)
			} else {
				truncated = true
			}
		}
	}
	priority := func(path string) (int, string) {
		lowered := strings.ToLower(path)
		if strings.HasPrefix(lowered, ghDeploymentRelatedPrefix) || strings.HasSuffix(lowered, "/application.yaml") || strings.HasSuffix(lowered, "/project.yaml") {
			return 0, path
		}
		if strings.HasPrefix(lowered, ghChartPathPrefix) {
			return 1, path
		}
		if isDeploymentPath(path) {
			return 2, path
		}
		return 3, path
	}
	sort.SliceStable(paths, func(i, j int) bool {
		leftRank, leftPath := priority(paths[i])
		rightRank, rightPath := priority(paths[j])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return leftPath < rightPath
	})
	return paths, seen, truncated
}

// ---------------------------------------------------------------------------
// Argo CD analysis

func ghYAMLDocuments(raw []byte, label string) ([]any, error) {
	if int64(len(raw)) > ghMaxArgoFileBytes {
		return nil, fmt.Errorf("%s is too large", label)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%s is not UTF-8", label)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	documents := make([]any, 0)
	for {
		var document any
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s is not valid YAML", label)
		}
		if document == nil {
			continue
		}
		documents = append(documents, ghNormalizeYAML(document))
		if len(documents) > 50 {
			return nil, fmt.Errorf("%s has too many YAML documents", label)
		}
	}
	return documents, nil
}

func ghNormalizeYAML(value any) any {
	switch node := value.(type) {
	case map[string]any:
		out := M{}
		for key, child := range node {
			out[key] = ghNormalizeYAML(child)
		}
		return out
	case map[any]any:
		out := M{}
		for key, child := range node {
			out[fmt.Sprint(key)] = ghNormalizeYAML(child)
		}
		return out
	case []any:
		out := make([]any, len(node))
		for index, child := range node {
			out[index] = ghNormalizeYAML(child)
		}
		return out
	default:
		return value
	}
}

func ghArgoIdentity(document M) (M, bool) {
	kind, kindOK := document["kind"].(string)
	metadata := asM(document["metadata"])
	name, nameOK := metadata["name"].(string)
	if !kindOK || !nameOK || kind == "" || name == "" {
		return nil, false
	}
	namespace := Str(metadata["namespace"])
	return M{"kind": kind, "namespace": namespace, "name": name}, true
}

func ghArgoSources(document M) []string {
	spec := asM(document["spec"])
	sources := make([]any, 0)
	if source, ok := spec["source"].(map[string]any); ok {
		sources = append(sources, source)
	}
	if list, ok := spec["sources"].([]any); ok {
		for _, item := range list {
			if source, isMap := item.(map[string]any); isMap {
				sources = append(sources, source)
			}
		}
	}
	normalized := make([]string, 0)
	limit := len(sources)
	if limit > 20 {
		limit = 20
	}
	for _, raw := range sources[:limit] {
		source := asM(raw)
		normalized = append(normalized, Hash(M{
			"repoURL":        truncateRunes(Str(source["repoURL"]), 1000),
			"path":           truncateRunes(Str(source["path"]), 1000),
			"chart":          truncateRunes(Str(source["chart"]), 300),
			"targetRevision": truncateRunes(Str(source["targetRevision"]), 300),
			"ref":            truncateRunes(Str(source["ref"]), 100),
		}))
	}
	return normalized
}

func ghArgoDocDigest(document M) string {
	return Hash(document)
}

func analyzeArgo(baseSnapshot, headSnapshot TreeSnapshot, changedPaths []string) ArgoAnalysis {
	changed := make([]string, 0)
	for _, path := range changedPaths {
		if isArgoPath(path) {
			changed = append(changed, path)
		}
	}
	changedLower := make([]string, len(changed))
	for index, path := range changed {
		changedLower[index] = strings.ToLower(path)
	}
	pathSaysApp := false
	pathSaysProject := false
	for _, path := range changedLower {
		if strings.HasSuffix(path, "/application.yaml") || strings.HasSuffix(path, "/application.yml") ||
			strings.HasSuffix(path, "/applicationset.yaml") || strings.HasSuffix(path, "/applicationset.yml") {
			pathSaysApp = true
		}
		if strings.HasSuffix(path, "/project.yaml") || strings.HasSuffix(path, "/project.yml") {
			pathSaysProject = true
		}
	}
	sourceChanged := false
	appChanged := pathSaysApp
	projectChanged := pathSaysProject
	manifestError := false
	applications := 0

	load := func(snapshot TreeSnapshot) map[string]M {
		result := map[string]M{}
		paths := make([]string, 0, len(snapshot.ArgoFiles))
		for path := range snapshot.ArgoFiles {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			if !isArgoPath(path) {
				continue
			}
			documents, err := ghYAMLDocuments(snapshot.ArgoFiles[path], path)
			if err != nil {
				manifestError = true
				continue
			}
			for _, raw := range documents {
				document, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				kind := Str(document["kind"])
				if kind != "Application" && kind != "AppProject" && kind != "ApplicationSet" {
					continue
				}
				identity, ok := ghArgoIdentity(document)
				if !ok {
					manifestError = true
					continue
				}
				key := Str(identity["kind"]) + "\x00" + Str(identity["namespace"]) + "\x00" + Str(identity["name"])
				result[key] = document
				if kind == "Application" {
					applications++
				}
			}
		}
		return result
	}

	baseDocs := load(baseSnapshot)
	headDocs := load(headSnapshot)
	keys := map[string]bool{}
	for key := range baseDocs {
		keys[key] = true
	}
	for key := range headDocs {
		keys[key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		oldDocument, oldOK := baseDocs[key]
		newDocument, newOK := headDocs[key]
		if !oldOK || !newOK {
			if oldOK {
				if Str(oldDocument["kind"]) == "AppProject" {
					projectChanged = true
				} else {
					appChanged = true
				}
			}
			if newOK {
				if Str(newDocument["kind"]) == "AppProject" {
					projectChanged = true
				} else {
					appChanged = true
				}
			}
			continue
		}
		kind := Str(oldDocument["kind"])
		if kind == "AppProject" {
			if ghArgoDocDigest(oldDocument) != ghArgoDocDigest(newDocument) {
				projectChanged = true
			}
			continue
		}
		if ghArgoDocDigest(oldDocument) != ghArgoDocDigest(newDocument) {
			appChanged = true
		}
		oldSources := ghArgoSources(oldDocument)
		newSources := ghArgoSources(newDocument)
		if strings.Join(oldSources, "\n") != strings.Join(newSources, "\n") {
			sourceChanged = true
		}
	}
	changedCopy := changed
	if len(changedCopy) > 200 {
		changedCopy = changedCopy[:200]
	}
	return ArgoAnalysis{
		ArgoSourceChanged:      sourceChanged,
		ArgoApplicationChanged: appChanged,
		ArgoProjectChanged:     projectChanged,
		ArgoManifestError:      manifestError,
		ArgoChangedPaths:       changedCopy,
		Applications:           applications,
	}
}

// ---------------------------------------------------------------------------
// Statuses / comments / identity

// CreateCommitStatus publishes one commit status through the statuses endpoint.
func (g *GitHub) CreateCommitStatus(sha, state, description, context, targetURL string) (M, error) {
	sha, err := ghValidateSHA(sha, "commit sha")
	if err != nil {
		return nil, err
	}
	if !ghStatusStates[state] {
		return nil, ghError("invalid_status_state", "commit status state is invalid")
	}
	sanitizedContext, err := ghSanitizeStatusContext(context)
	if err != nil {
		return nil, err
	}
	body := M{
		"state":       state,
		"description": ghSanitizeStatusDescription(description),
		"context":     sanitizedContext,
	}
	if targetURL != "" {
		parsed, parseErr := url.Parse(targetURL)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return nil, ghError("invalid_target_url", "status target URL must be a plain HTTPS URL")
		}
		body["target_url"] = targetURL
	}
	data, _, err := g.request("POST", fmt.Sprintf("/repos/%s/%s/statuses/%s", g.owner, g.repo, sha), nil, body, map[int]bool{201: true}, nil)
	if err != nil {
		return nil, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, ghError("invalid_response", "GitHub status response is invalid")
	}
	return object, nil
}

// ListIssueComments pages PR/issue comments in reverse creation order.
func (g *GitHub) ListIssueComments(number int64) ([]M, error) {
	if number < 1 {
		return nil, ghError("invalid_pr", "pull request number is invalid")
	}
	comments := []M{}
	for page := 1; page <= ghMaxCommentPages; page++ {
		data, err := g.get(fmt.Sprintf("/repos/%s/%s/issues/%d/comments", g.owner, g.repo, number), url.Values{
			"sort":      {"created"},
			"direction": {"desc"},
			"per_page":  {"100"},
			"page":      {strconv.Itoa(page)},
		})
		if err != nil {
			return nil, err
		}
		items, ok := data.([]any)
		if !ok {
			return nil, ghError("invalid_response", "GitHub comment listing is not a list")
		}
		if len(items) > 100 {
			return nil, ghError("invalid_response", "GitHub returned more comments than requested")
		}
		for _, item := range items {
			if comment, isMap := item.(map[string]any); isMap {
				comments = append(comments, comment)
			}
		}
		if len(comments) >= ghMaxComments {
			break
		}
		if len(items) < 100 {
			break
		}
	}
	if len(comments) > ghMaxComments {
		comments = comments[:ghMaxComments]
	}
	return comments, nil
}

// CreateIssueComment posts a sanitized report comment.
func (g *GitHub) CreateIssueComment(number int64, body string) (M, error) {
	if number < 1 {
		return nil, ghError("invalid_pr", "pull request number is invalid")
	}
	if strings.TrimSpace(body) == "" {
		return nil, ghError("invalid_comment", "comment body is empty")
	}
	if len([]byte(body)) > ghMaxCommentBytes {
		return nil, ghError("comment_too_large", "comment body is too large")
	}
	text := sanitizeText(body, ghMaxCommentBytes)
	if text == "" {
		return nil, ghError("invalid_comment", "comment body is empty after sanitization")
	}
	data, _, err := g.request("POST", fmt.Sprintf("/repos/%s/%s/issues/%d/comments", g.owner, g.repo, number), nil, M{"body": text}, map[int]bool{201: true}, nil)
	if err != nil {
		return nil, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, ghError("invalid_response", "GitHub comment response is invalid")
	}
	return object, nil
}

// GetRepositoryIdentity returns the current owner identity and rejects a
// rename/transfer to a different repository.
func (g *GitHub) GetRepositoryIdentity() (M, error) {
	data, err := g.get(fmt.Sprintf("/repos/%s/%s", g.owner, g.repo), nil)
	if err != nil {
		return nil, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return nil, ghError("invalid_response", "GitHub repository response is invalid")
	}
	fullName := Str(object["full_name"])
	if !strings.EqualFold(fullName, g.repository) {
		return nil, ghError("repository_identity_changed", "configured repository no longer resolves to the same owner/name")
	}
	owner := asM(object["owner"])
	ownerLogin := Str(owner["login"])
	if ownerLogin == "" {
		return nil, ghError("invalid_response", "GitHub repository response has no owner login")
	}
	return M{
		"full_name":      fullName,
		"owner_login":    ownerLogin,
		"owner_type":     nullableString(Str(owner["type"])),
		"default_branch": nullableString(Str(object["default_branch"])),
	}, nil
}

// GetUserPermission reads a collaborator's current repository permission.
func (g *GitHub) GetUserPermission(login string) (string, error) {
	validated, err := ghValidateLogin(login)
	if err != nil {
		return "", err
	}
	data, err := g.get(fmt.Sprintf("/repos/%s/%s/collaborators/%s/permission", g.owner, g.repo, ghQuotePathSegment(validated)), nil)
	if err != nil {
		return "", err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return "", ghError("invalid_response", "GitHub permission response is invalid")
	}
	permission := Str(object["permission"])
	if permission == "" {
		permission = Str(object["role_name"])
	}
	return permission, nil
}

// ---------------------------------------------------------------------------
// Chart pin / workflow helpers shared with merge and daemon

// ChartDigestFromFiles digests the exact Git blob bytes under charts/demo/.
func ChartDigestFromFiles(files map[string][]byte) (string, error) {
	if files == nil {
		return ChartDigestFromFiles(map[string][]byte{})
	}
	hashes := M{}
	for path, content := range files {
		if !strings.HasPrefix(path, ghChartPathPrefix) {
			continue
		}
		relative := strings.TrimPrefix(path, ghChartPathPrefix)
		parts := strings.Split(relative, "/")
		if relative == "" {
			return "", ghError("invalid_chart_path", "chart path is not a clean relative path")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return "", ghError("invalid_chart_path", "chart path is not a clean relative path")
			}
		}
		sum := sha256.Sum256(content)
		hashes[relative] = hex.EncodeToString(sum[:])
	}
	return Hash(hashes), nil
}

// IsWorkflowPath reports whether a repository path is part of the CI workflow
// tree. Workflow content must be identical on base and head.
func IsWorkflowPath(path any) bool {
	text, ok := path.(string)
	if !ok {
		return false
	}
	lowered := strings.ToLower(text)
	return lowered == strings.TrimSuffix(ghWorkflowPathPrefix, "/") || strings.HasPrefix(lowered, ghWorkflowPathPrefix)
}

// WorkflowTreeSignature returns the path/mode/kind/blob-id signature of the
// workflow tree entries.
func WorkflowTreeSignature(entries map[string]TreeEntry) map[string][]string {
	signature := map[string][]string{}
	for path, entry := range entries {
		if !IsWorkflowPath(path) {
			continue
		}
		signature[path] = []string{entry.Mode, entry.Kind, entry.SHA}
	}
	return signature
}

func ghWorkflowSignatureEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for path, value := range left {
		other, ok := right[path]
		if !ok || len(other) != len(value) {
			return false
		}
		for index := range value {
			if value[index] != other[index] {
				return false
			}
		}
	}
	return true
}

func ghChangedWorkflowPaths(left, right map[string][]string) []string {
	union := map[string]bool{}
	for path := range left {
		union[path] = true
	}
	for path := range right {
		union[path] = true
	}
	changed := make([]string, 0)
	for path := range union {
		oldValue, oldOK := left[path]
		newValue, newOK := right[path]
		if oldOK && newOK && len(oldValue) == len(newValue) && oldValue[0] == newValue[0] && oldValue[1] == newValue[1] && oldValue[2] == newValue[2] {
			continue
		}
		changed = append(changed, path)
	}
	sort.Strings(changed)
	return changed
}

func ghDigit(value string) bool { return ghDigitRE.MatchString(value) }
