package guard

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const ghTestToken = "ghp_1234567890abcdefghijklmnop"

type ghTestCall struct {
	Method string
	Path   string
	Query  string
	Body   []byte
}

type ghTestResponse struct {
	Status  int
	Body    string
	Headers map[string]string
}

type ghTestServer struct {
	mu      sync.Mutex
	server  *httptest.Server
	calls   []ghTestCall
	static  map[string]ghTestResponse
	queues  map[string][]ghTestResponse
	dynamic map[string]func(*http.Request) ghTestResponse
}

func newGHTestServer(t *testing.T) *ghTestServer {
	t.Helper()
	fake := &ghTestServer{
		static:  map[string]ghTestResponse{},
		queues:  map[string][]ghTestResponse{},
		dynamic: map[string]func(*http.Request) ghTestResponse{},
	}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 4<<20))
		key := request.Method + " " + request.URL.Path
		fake.mu.Lock()
		fake.calls = append(fake.calls, ghTestCall{Method: request.Method, Path: request.URL.Path, Query: request.URL.RawQuery, Body: body})
		response, hasStatic := fake.static[key]
		if dynamic, ok := fake.dynamic[key]; ok {
			fake.mu.Unlock()
			response = dynamic(request)
			writeGHTestResponse(writer, response)
			return
		}
		if queue := fake.queues[key]; len(queue) > 0 {
			response = queue[0]
			fake.queues[key] = queue[1:]
			hasStatic = true
		}
		fake.mu.Unlock()
		if !hasStatic {
			writeGHTestResponse(writer, ghTestResponse{Status: 404, Body: `{"message":"not found"}`})
			return
		}
		writeGHTestResponse(writer, response)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func writeGHTestResponse(writer http.ResponseWriter, response ghTestResponse) {
	status := response.Status
	if status == 0 {
		status = 200
	}
	for key, value := range response.Headers {
		writer.Header().Set(key, value)
	}
	if _, exists := response.Headers["Content-Type"]; !exists {
		writer.Header().Set("Content-Type", "application/json")
	}
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, response.Body)
}

func (s *ghTestServer) route(method, path string, status int, body any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.static[method+" "+path] = ghTestResponse{Status: status, Body: ghTestJSON(body)}
}

func (s *ghTestServer) routeRaw(method, path string, response ghTestResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.static[method+" "+path] = response
}

func (s *ghTestServer) queue(method, path string, responses ...ghTestResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queues[method+" "+path] = responses
}

func (s *ghTestServer) handle(method, path string, handler func(*http.Request) ghTestResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dynamic[method+" "+path] = handler
}

func (s *ghTestServer) callCount(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, call := range s.calls {
		if call.Method == method && call.Path == path {
			count++
		}
	}
	return count
}

func (s *ghTestServer) lastCall(method, path string) (ghTestCall, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := len(s.calls) - 1; index >= 0; index-- {
		if s.calls[index].Method == method && s.calls[index].Path == path {
			return s.calls[index], true
		}
	}
	return ghTestCall{}, false
}

func ghTestJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func (s *ghTestServer) github(t *testing.T, overrides M) *GitHub {
	t.Helper()
	t.Setenv("GH_TEST_TOKEN", ghTestToken)
	config := M{
		"repository":       "o/r",
		"github_token_env": "GH_TEST_TOKEN",
		"use_proxy_env":    false,
		"github_retries":   float64(0),
	}
	for key, value := range overrides {
		config[key] = value
	}
	client := &http.Client{
		Transport: s.server.Client().Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	github, err := ghNewGitHubWith(config, s.server.URL, client)
	if err != nil {
		t.Fatalf("new github: %v", err)
	}
	return github
}

func ghTestBlobSHA(data []byte) string {
	digest := sha1.New()
	_, _ = fmt.Fprintf(digest, "blob %d\x00", len(data))
	_, _ = digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil))
}

func ghTestTreeEntries(files map[string][]byte) []M {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	entries := make([]M, 0, len(paths))
	for _, path := range paths {
		data := files[path]
		entries = append(entries, M{
			"path": path, "mode": "100644", "type": "blob",
			"sha": ghTestBlobSHA(data), "size": float64(len(data)),
		})
	}
	return entries
}

// installTreeRoutes installs commit, tree, and wrapped-base64 blob routes.
func installTreeRoutes(s *ghTestServer, commitSHA, treeSHA string, entries []M, files map[string][]byte, wrap bool) {
	s.route("GET", "/repos/o/r/git/commits/"+commitSHA, 200, M{"tree": M{"sha": treeSHA}})
	s.route("GET", "/repos/o/r/git/trees/"+treeSHA, 200, M{"tree": entries, "truncated": false})
	for _, raw := range entries {
		entry := asM(raw)
		if Str(entry["type"]) != "blob" {
			continue
		}
		data := files[Str(entry["path"])]
		content := base64.StdEncoding.EncodeToString(data)
		if wrap {
			var lines []string
			for len(content) > 40 {
				lines = append(lines, content[:40])
				content = content[40:]
			}
			lines = append(lines, content)
			content = strings.Join(lines, "\r\n")
		}
		s.route("GET", "/repos/o/r/git/blobs/"+Str(entry["sha"]), 200, M{
			"encoding": "base64", "content": content, "size": float64(len(data)),
		})
	}
}

func ghTestPRPayload(number int64, headSHA, baseSHA, base, headRepo, state string) M {
	return M{
		"number":     number,
		"title":      "Change",
		"state":      state,
		"draft":      false,
		"user":       M{"login": "alice"},
		"head":       M{"sha": headSHA, "ref": "feature", "repo": M{"full_name": headRepo}},
		"base":       M{"sha": baseSHA, "ref": base, "repo": M{"full_name": "o/r"}},
		"created_at": "2026-01-01T00:00:00Z",
		"updated_at": "2026-01-01T00:00:00Z",
	}
}

func ghTestSnapshot(files map[string][]byte, argo map[string][]byte, entries map[string]TreeEntry) TreeSnapshot {
	return TreeSnapshot{
		SHA:           strings.Repeat("a", 40),
		TreeSHA:       strings.Repeat("d", 40),
		Entries:       entries,
		RendererFiles: files,
		ArgoFiles:     argo,
		TreeDigest:    "e",
		EntryCount:    len(entries),
	}
}

func TestGitHubPathNormalization(t *testing.T) {
	for _, bad := range []string{"../x", "a/../b", "/abs", "a//b", "a/", `a\b`, "", "a/\x00b"} {
		if _, err := normalizeRepoPath(bad); err == nil {
			t.Fatalf("expected path %q to be rejected", bad)
		}
	}
	good, err := normalizeRepoPath("charts/demo/templates/x.yaml")
	if err != nil || good != "charts/demo/templates/x.yaml" {
		t.Fatalf("valid path rejected: %v %q", err, good)
	}
}

func TestGitHubTokenNeverAppearsInErrors(t *testing.T) {
	fake := newGHTestServer(t)
	fake.routeRaw("GET", "/user", ghTestResponse{Status: 500, Body: "boom"})
	github := fake.github(t, M{})
	_, err := github.get("/user", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), ghTestToken) {
		t.Fatalf("error leaked token: %v", err)
	}
	if !ghIsCode(err, "server_error") {
		t.Fatalf("unexpected code: %v", err)
	}
}

func TestGitHubPaginationAndExactBaseFilter(t *testing.T) {
	fake := newGHTestServer(t)
	fake.handle("GET", "/repos/o/r/pulls", func(request *http.Request) ghTestResponse {
		page := request.URL.Query().Get("page")
		if request.URL.Query().Get("base") != "main" {
			t.Errorf("base filter not sent: %s", request.URL.RawQuery)
		}
		if page == "1" {
			return ghTestResponse{Status: 200, Body: ghTestJSON([]any{
				ghTestPRPayload(1, strings.Repeat("a", 40), strings.Repeat("b", 40), "main", "o/r", "open"),
				ghTestPRPayload(2, strings.Repeat("c", 40), strings.Repeat("b", 40), "other", "o/r", "open"),
			})}
		}
		if page == "2" {
			return ghTestResponse{Status: 200, Body: ghTestJSON([]any{
				ghTestPRPayload(3, strings.Repeat("d", 40), strings.Repeat("b", 40), "main", "o/r", "open"),
			})}
		}
		return ghTestResponse{Status: 200, Body: "[]"}
	})
	github := fake.github(t, M{})
	results, err := github.ListOpenPullRequests("main", 2, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Number != 1 || results[1].Number != 3 {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestGitHubSnapshotMaterializesOnlyRendererPaths(t *testing.T) {
	fake := newGHTestServer(t)
	chart := []byte("apiVersion: v2\nname: demo\n")
	values := []byte("replicaCount: 2\n")
	files := map[string][]byte{"charts/demo/Chart.yaml": chart, "gitops/demo/values.yaml": values, "README.md": []byte("x")}
	entries := ghTestTreeEntries(files)
	installTreeRoutes(fake, strings.Repeat("a", 40), strings.Repeat("c", 40), entries, files, true)
	github := fake.github(t, M{})
	snapshot, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.RendererFiles) != 2 || string(snapshot.RendererFiles["charts/demo/Chart.yaml"]) != string(chart) {
		t.Fatalf("unexpected renderer files: %+v", snapshot.RendererFiles)
	}
	if _, exists := snapshot.RendererFiles["README.md"]; exists {
		t.Fatal("non-renderer file materialised")
	}
	root := t.TempDir()
	written, err := snapshot.Materialize(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 || written[0] != "charts/demo/Chart.yaml" || written[1] != "gitops/demo/values.yaml" {
		t.Fatalf("unexpected writes: %v", written)
	}
	if _, err = os.Stat(filepath.Join(root, "README.md")); !os.IsNotExist(err) {
		t.Fatal("README.md should not exist")
	}
	if _, err = snapshot.Materialize(root); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestGitHubTreeSecurityRejections(t *testing.T) {
	cases := []struct {
		name    string
		entries []M
		code    string
	}{
		{"traversal", []M{{"path": "../escape", "mode": "100644", "type": "blob", "sha": strings.Repeat("a", 40), "size": 1}}, "path_traversal"},
		{"symlink", []M{{"path": "link", "mode": "120000", "type": "blob", "sha": strings.Repeat("a", 40), "size": 1}}, "symlink_not_permitted"},
		{"submodule", []M{{"path": "sub", "mode": "160000", "type": "commit", "sha": strings.Repeat("a", 40)}}, "submodule_not_permitted"},
		{"duplicate", []M{
			{"path": "dup", "mode": "100644", "type": "blob", "sha": strings.Repeat("a", 40), "size": 1},
			{"path": "dup", "mode": "100644", "type": "blob", "sha": strings.Repeat("b", 40), "size": 1},
		}, "duplicate_path"},
		{"unsafe mode", []M{{"path": "x", "mode": "100600", "type": "blob", "sha": strings.Repeat("a", 40), "size": 1}}, "invalid_mode"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newGHTestServer(t)
			installTreeRoutes(fake, strings.Repeat("a", 40), strings.Repeat("c", 40), test.entries, nil, false)
			github := fake.github(t, M{})
			_, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true)
			if err == nil || !ghIsCode(err, test.code) {
				t.Fatalf("expected %s, got %v", test.code, err)
			}
		})
	}
}

func TestGitHubTreeTruncatedAndOversizedAreRejected(t *testing.T) {
	fake := newGHTestServer(t)
	fake.route("GET", "/repos/o/r/git/commits/"+strings.Repeat("a", 40), 200, M{"tree": M{"sha": strings.Repeat("c", 40)}})
	fake.route("GET", "/repos/o/r/git/trees/"+strings.Repeat("c", 40), 200, M{"tree": []any{}, "truncated": true})
	github := fake.github(t, M{})
	if _, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true); !ghIsCode(err, "tree_truncated") {
		t.Fatalf("expected tree_truncated, got %v", err)
	}

	fake = newGHTestServer(t)
	entries := []M{{"path": "charts/demo/Chart.yaml", "mode": "100644", "type": "blob", "sha": strings.Repeat("a", 40), "size": float64(3 * 1024 * 1024)}}
	installTreeRoutes(fake, strings.Repeat("a", 40), strings.Repeat("c", 40), entries, nil, false)
	github = fake.github(t, M{})
	if _, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true); !ghIsCode(err, "blob_too_large") {
		t.Fatalf("expected blob_too_large, got %v", err)
	}
}

func TestGitHubBlobExactGitSHAAfterWrappedBase64(t *testing.T) {
	data := []byte("replicas: 3\n# wrapped base64 transport\n")
	fake := newGHTestServer(t)
	entries := []M{{"path": "gitops/demo/values.yaml", "mode": "100644", "type": "blob", "sha": ghTestBlobSHA(data), "size": float64(len(data))}}
	installTreeRoutes(fake, strings.Repeat("a", 40), strings.Repeat("c", 40), entries, map[string][]byte{"gitops/demo/values.yaml": data}, true)
	github := fake.github(t, M{})
	snapshot, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true)
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.RendererFiles["gitops/demo/values.yaml"]) != string(data) {
		t.Fatalf("blob bytes changed: %q", snapshot.RendererFiles["gitops/demo/values.yaml"])
	}

	// Same bytes, but the tree entry claims a different object id: reject.
	fake = newGHTestServer(t)
	entries = []M{{"path": "gitops/demo/values.yaml", "mode": "100644", "type": "blob", "sha": strings.Repeat("0", 40), "size": float64(len(data))}}
	installTreeRoutes(fake, strings.Repeat("a", 40), strings.Repeat("c", 40), entries, map[string][]byte{"gitops/demo/values.yaml": data}, true)
	github = fake.github(t, M{})
	if _, err := github.FetchTreeSnapshot(strings.Repeat("a", 40), true); !ghIsCode(err, "blob_corrupt") {
		t.Fatalf("expected blob_corrupt, got %v", err)
	}
}

func TestGitHubClassicAndFineGrainedCredentials(t *testing.T) {
	baseRoutes := func(fake *ghTestServer, scopes string, private bool, permissions M, probe bool) {
		headers := map[string]string{}
		if scopes != "" {
			headers["X-OAuth-Scopes"] = scopes
		}
		fake.routeRaw("GET", "/user", ghTestResponse{Status: 200, Headers: headers, Body: ghTestJSON(M{"login": "guard"})})
		fake.route("GET", "/repos/o/r", 200, M{"full_name": "o/r", "private": private, "default_branch": "main", "permissions": permissions})
		fake.route("GET", "/repos/o/r/pulls", 200, []any{})
		fake.route("GET", "/repos/o/r/git/ref/heads/main", 200, M{"object": M{"sha": strings.Repeat("c", 40)}})
		fake.route("GET", "/repos/o/r/commits/"+strings.Repeat("c", 40)+"/statuses", 200, []any{})
		if probe {
			fake.route("POST", "/repos/o/r/statuses/"+strings.Repeat("c", 40), 201, M{"id": 7})
		}
	}

	fake := newGHTestServer(t)
	baseRoutes(fake, "repo,read:user", true, M{"push": true, "admin": false}, false)
	result, err := fake.github(t, M{}).VerifyCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if result["token_kind"] != "classic" || result["statuses_write"] != "verified-by-scope" {
		t.Fatalf("unexpected result: %+v", result)
	}

	fake = newGHTestServer(t)
	baseRoutes(fake, "read:user", true, M{"push": true}, false)
	if _, err = fake.github(t, M{}).VerifyCredentials(""); !ghIsCode(err, "missing_status_scope") {
		t.Fatalf("expected missing scope, got %v", err)
	}

	fake = newGHTestServer(t)
	baseRoutes(fake, "", false, M{"push": true}, true)
	result, err = fake.github(t, M{}).VerifyCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if result["statuses_write"] != "inferred" {
		t.Fatalf("unexpected inferred result: %+v", result)
	}
	probed, err := fake.github(t, M{}).VerifyCredentials(strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if probed["statuses_write"] != "verified-by-write" {
		t.Fatalf("probe did not verify write: %+v", probed)
	}

	fake = newGHTestServer(t)
	baseRoutes(fake, "public_repo", true, M{"push": true}, false)
	if _, err = fake.github(t, M{}).VerifyCredentials(""); !ghIsCode(err, "missing_status_scope") {
		t.Fatalf("private repo accepted public_repo scope: %v", err)
	}
}

func TestGitHubRetryRedirectRateLimitAndBounds(t *testing.T) {
	fake := newGHTestServer(t)
	fake.queue("GET", "/user",
		ghTestResponse{Status: 500, Body: "boom"},
		ghTestResponse{Status: 200, Body: `{"login":"x"}`})
	github := fake.github(t, M{"github_retries": float64(1)})
	github.sleep = func(time.Duration) {}
	value, err := github.get("/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	if asM(value)["login"] != "x" || fake.callCount("GET", "/user") != 2 {
		t.Fatalf("retry did not succeed: %v", value)
	}

	fake = newGHTestServer(t)
	fake.routeRaw("GET", "/user", ghTestResponse{Status: 302, Headers: map[string]string{"Location": "https://evil.invalid"}})
	if _, err = fake.github(t, M{}).get("/user", nil); !ghIsCode(err, "redirect_refused") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}

	fake = newGHTestServer(t)
	fake.routeRaw("GET", "/user", ghTestResponse{Status: 403, Body: "rate limited", Headers: map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     fmt.Sprint(time.Now().Unix() + 3600),
	}})
	if _, err = fake.github(t, M{"github_retries": float64(1)}).get("/user", nil); !ghIsCode(err, "rate_limited") {
		t.Fatalf("expected rate_limited, got %v", err)
	}

	fake = newGHTestServer(t)
	fake.routeRaw("GET", "/user", ghTestResponse{Status: 200, Body: strings.Repeat("x", 10000)})
	if _, err = fake.github(t, M{"github_max_response_bytes": float64(4096)}).get("/user", nil); !ghIsCode(err, "response_too_large") {
		t.Fatalf("expected response_too_large, got %v", err)
	}

	fake = newGHTestServer(t)
	fake.routeRaw("GET", "/user", ghTestResponse{Status: 200, Body: "not-json"})
	if _, err = fake.github(t, M{}).get("/user", nil); !ghIsCode(err, "invalid_json") {
		t.Fatalf("expected invalid_json, got %v", err)
	}
}

func TestGitHubStatusPayloadAndExactApproval(t *testing.T) {
	fake := newGHTestServer(t)
	fake.route("POST", "/repos/o/r/statuses/"+strings.Repeat("a", 40), 201, M{"id": 1})
	github := fake.github(t, M{})
	if _, err := github.CreateCommitStatus(strings.Repeat("a", 40), "pending", "review required", "change-guard/release", ""); err != nil {
		t.Fatal(err)
	}
	call, ok := fake.lastCall("POST", "/repos/o/r/statuses/"+strings.Repeat("a", 40))
	if !ok {
		t.Fatal("status request missing")
	}
	var body M
	var err error
	if err = json.Unmarshal(call.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["state"] != "pending" || body["context"] != "change-guard/release" {
		t.Fatalf("unexpected status body: %+v", body)
	}
	if _, err = github.CreateCommitStatus(strings.Repeat("a", 40), "success", "x", "ctx", "http://insecure"); !ghIsCode(err, "invalid_target_url") {
		t.Fatalf("expected insecure URL refusal, got %v", err)
	}
	if id, ok := parseApprovalBody("/guard approve ev-0123456789abcdef"); !ok || id != "ev-0123456789abcdef" {
		t.Fatalf("exact approval not parsed: %q %v", id, ok)
	}
	for _, body := range []string{
		"label: approved",
		"/guard approve",
		"/guard approve ev-1 extra",
		"please /guard approve ev-0123456789abcdef",
		"/guard approve ev-0123456789abcdef\nmore",
	} {
		if _, ok := parseApprovalBody(body); ok {
			t.Fatalf("approval body %q should be rejected", body)
		}
	}
}

func TestGitHubPermissionAndIdentity(t *testing.T) {
	fake := newGHTestServer(t)
	fake.route("GET", "/repos/o/r/collaborators/alice/permission", 200, M{"permission": "write"})
	value, err := fake.github(t, M{}).GetUserPermission("alice")
	if err != nil || value != "write" {
		t.Fatalf("permission: %q %v", value, err)
	}
	if _, err = fake.github(t, M{}).GetUserPermission("../bad"); err == nil {
		t.Fatal("invalid login accepted")
	}

	fake = newGHTestServer(t)
	fake.route("GET", "/repos/o/r/collaborators/alice/permission", 403, M{"message": "Resource not accessible by personal access token"})
	if _, err = fake.github(t, M{}).GetUserPermission("alice"); !ghIsCode(err, "forbidden") {
		t.Fatalf("expected fail-closed forbidden, got %v", err)
	}

	userRepo := M{"full_name": "o/r", "default_branch": "main", "owner": M{"login": "alice", "type": "User"}}
	fake = newGHTestServer(t)
	fake.route("GET", "/repos/o/r", 200, userRepo)
	identity, err := fake.github(t, M{}).GetRepositoryIdentity()
	if err != nil || identity["owner_login"] != "alice" || identity["owner_type"] != "User" {
		t.Fatalf("identity: %+v %v", identity, err)
	}

	moved := M{"full_name": "someone-else/r", "default_branch": "main", "owner": M{"login": "alice", "type": "User"}}
	fake = newGHTestServer(t)
	fake.route("GET", "/repos/o/r", 200, moved)
	if _, err = fake.github(t, M{}).GetRepositoryIdentity(); !ghIsCode(err, "repository_identity_changed") {
		t.Fatalf("expected transfer detection, got %v", err)
	}
}

func TestArgoAnalysisSignals(t *testing.T) {
	app := func(repoURL string) []byte {
		return []byte("apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: demo\n  namespace: argocd\nspec:\n  source:\n    repoURL: " + repoURL + "\n    path: gitops/demo\n    targetRevision: main\n")
	}
	path := "gitops/argocd/application.yaml"
	entry := TreeEntry{Path: path, Mode: "100644", Kind: "blob", SHA: strings.Repeat("a", 40)}
	base := ghTestSnapshot(nil, map[string][]byte{path: app("https://github.com/o/r")}, map[string]TreeEntry{path: entry})
	head := ghTestSnapshot(nil, map[string][]byte{path: app("https://github.com/evil/r")}, map[string]TreeEntry{path: entry})
	result := analyzeArgo(base, head, []string{path})
	if !result.ArgoSourceChanged || !result.ArgoApplicationChanged || result.ArgoManifestError {
		t.Fatalf("unexpected source analysis: %+v", result)
	}

	projectPath := "gitops/argocd/project.yaml"
	project := func(description string) []byte {
		return []byte("apiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata:\n  name: demo\nspec:\n  description: " + description + "\n")
	}
	projectEntry := TreeEntry{Path: projectPath, Mode: "100644", Kind: "blob", SHA: strings.Repeat("b", 40)}
	base = ghTestSnapshot(nil, map[string][]byte{projectPath: project("old")}, map[string]TreeEntry{projectPath: projectEntry})
	head = ghTestSnapshot(nil, map[string][]byte{projectPath: project("new")}, map[string]TreeEntry{projectPath: projectEntry})
	result = analyzeArgo(base, head, []string{projectPath})
	if !result.ArgoProjectChanged || result.ArgoSourceChanged {
		t.Fatalf("unexpected project analysis: %+v", result)
	}

	brokenPath := "gitops/argocd/application.yaml"
	base = ghTestSnapshot(nil, nil, map[string]TreeEntry{})
	head = ghTestSnapshot(nil, map[string][]byte{brokenPath: []byte("kind: [broken")}, map[string]TreeEntry{})
	result = analyzeArgo(base, head, []string{brokenPath})
	if !result.ArgoManifestError {
		t.Fatalf("invalid manifest not reported: %+v", result)
	}
}

func TestChartDigestUsesRawBlobBytesOnly(t *testing.T) {
	chart := []byte("apiVersion: v2\n")
	first, err := ChartDigestFromFiles(map[string][]byte{
		"charts/demo/Chart.yaml":  chart,
		"gitops/demo/values.yaml": []byte("replicas: 1\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ChartDigestFromFiles(map[string][]byte{
		"charts/demo/Chart.yaml":  chart,
		"gitops/demo/values.yaml": []byte("replicas: 2\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("values.yaml must not participate in the chart pin")
	}
	lf, _ := ChartDigestFromFiles(map[string][]byte{"charts/demo/Chart.yaml": []byte("a\n")})
	crlf, _ := ChartDigestFromFiles(map[string][]byte{"charts/demo/Chart.yaml": []byte("a\r\n")})
	if lf == crlf {
		t.Fatal("CRLF was silently normalized")
	}
}
