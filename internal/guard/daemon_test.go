package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dtNow  int64 = 1_800_000_000
	dtHead       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dtBase       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// dtFakeGitHub is a deliberately small, deterministic daemon API double. It
// models only the state the daemon is allowed to read from GitHub; no network
// or credentials are involved.
type dtFakeGitHub struct {
	pr              PullRequestInfo
	prs             []PullRequestInfo
	baseSHA         string
	candidate       PullRequestCandidate
	comments        []M
	owner           M
	ownerErr        error
	permission      string
	permissionErr   error
	verifyErr       error
	statusErr       error
	statuses        []M
	permissionCalls []string
	identityCalls   int
	now             int64
}

func dtPR(state string, draft bool, number int64) PullRequestInfo {
	return PullRequestInfo{
		Number: number, Title: "Change demo", Author: "alice", State: state, Draft: draft,
		HeadSHA: dtHead, HeadRef: "feature", HeadRepo: "o/r",
		BaseSHA: dtBase, BaseRef: "main", BaseRepo: "o/r",
	}
}

func dtCandidate(pr PullRequestInfo) PullRequestCandidate {
	return PullRequestCandidate{
		PullRequest: pr,
		BaseSHA:     dtBase,
		BaseSnapshot: TreeSnapshot{
			SHA: dtBase, TreeSHA: strings.Repeat("d", 40),
			Entries: map[string]TreeEntry{}, RendererFiles: map[string][]byte{},
			TreeDigest: strings.Repeat("e", 64),
		},
		HeadSnapshot: TreeSnapshot{
			SHA: pr.HeadSHA, TreeSHA: strings.Repeat("d", 40),
			Entries: map[string]TreeEntry{}, RendererFiles: map[string][]byte{},
			TreeDigest: strings.Repeat("e", 64),
		},
		ChangedPaths: []string{}, ChangedCount: 0, PRBaseSHA: dtBase,
	}
}

func newDTFake(pr PullRequestInfo) *dtFakeGitHub {
	return &dtFakeGitHub{
		pr:        pr,
		prs:       []PullRequestInfo{pr},
		baseSHA:   dtBase,
		candidate: dtCandidate(pr),
		now:       dtNow,
	}
}

func (f *dtFakeGitHub) VerifyCredentials(string) (M, error) {
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return M{
		"status": "ok", "login": "guard", "repository": "o/r", "private": false,
		"token_kind": "fine-grained", "scopes": []any{}, "permissions": M{"push": true},
		"statuses_write": "inferred", "default_branch": "main",
	}, nil
}

func (f *dtFakeGitHub) ListOpenPullRequests(string, int, int) ([]PullRequestInfo, error) {
	return append([]PullRequestInfo(nil), f.prs...), nil
}

func (f *dtFakeGitHub) GetPullRequest(int64) (PullRequestInfo, error) { return f.pr, nil }

func (f *dtFakeGitHub) GetBranchHead(string) (string, error) { return f.baseSHA, nil }

func (f *dtFakeGitHub) FetchPullRequestCandidate(int64, bool) (PullRequestCandidate, error) {
	return f.candidate, nil
}

func (f *dtFakeGitHub) ListIssueComments(int64) ([]M, error) {
	return append([]M(nil), f.comments...), nil
}

func (f *dtFakeGitHub) GetRepositoryIdentity() (M, error) {
	f.identityCalls++
	if f.ownerErr != nil {
		return nil, f.ownerErr
	}
	return f.owner, nil
}

func (f *dtFakeGitHub) GetUserPermission(login string) (string, error) {
	f.permissionCalls = append(f.permissionCalls, login)
	if f.permissionErr != nil {
		return "", f.permissionErr
	}
	return f.permission, nil
}

func (f *dtFakeGitHub) CreateCommitStatus(sha, state, description, context, targetURL string) (M, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	f.statuses = append(f.statuses, M{
		"sha": sha, "state": state, "description": description,
		"context": context, "target_url": targetURL,
	})
	return M{"id": len(f.statuses)}, nil
}

func (f *dtFakeGitHub) CreateIssueComment(int64, string) (M, error) {
	return M{"id": 99}, nil
}

func dtConfig(t *testing.T, overrides M) M {
	t.Helper()
	config := M{
		"repository": "o/r", "base_branch": "main", "status_context": "change-guard/release",
		"state_dir": t.TempDir(), "poll_seconds": float64(30),
		"evidence_ttl_seconds": float64(300), "approvers": []any{"alice"},
		"namespace": "demo", "deployment": "demo", "report_comment": false,
		"use_proxy_env": false, "approved_chart_digest": []any{Hash(M{})},
	}
	for key, value := range overrides {
		config[key] = value
	}
	validated, err := daemonValidateConfig(config)
	if err != nil {
		t.Fatalf("validate daemon config: %v", err)
	}
	return validated
}

func dtEvaluation(decision string, findings []M, now int64) M {
	values := make([]any, len(findings))
	for index, finding := range findings {
		values[index] = finding
	}
	return M{
		"decision": decision, "findings": values, "changes": []any{},
		"render_digest": strings.Repeat("1", 64), "old_render_digest": strings.Repeat("2", 64),
		"evaluated_at": now, "expires_at": now + 300, "rule_version": RuleVersion,
	}
}

func dtEvidence(now int64) M {
	return M{
		"collected_at": now, "errors": []any{}, "nodes": []any{}, "pods": []any{},
		"deployment": M{"name": "demo", "namespace": "demo", "replicas": 1, "ready_replicas": 1, "images": []any{}},
		"metrics":    M{"request_rate": 0.5, "error_ratio": 0.01, "p95_seconds": 0.2, "alerts": []any{}},
		"capacity":   M{},
	}
}

func dtRender(string, M) ([]M, error) {
	return []M{{
		"kind": "Deployment", "metadata": M{"name": "demo", "namespace": "demo"},
		"spec": M{"template": M{"spec": M{"containers": []any{}}}},
	}}, nil
}

func dtNewDaemon(t *testing.T, fake *dtFakeGitHub, overrides M, decision string, findings []M) *guardDaemon {
	t.Helper()
	config := dtConfig(t, overrides)
	daemon, err := newGuardDaemonWith(config, fake, nil)
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.now = func() int64 { return fake.now }
	daemon.sleep = func(_ time.Duration) {}
	daemon.render = dtRender
	daemon.collect = func(M) M { return dtEvidence(fake.now) }
	daemon.analyze = func(M, M) M {
		return M{"status": "ok", "model": "test", "summary": "ok", "additional_risks": []any{}, "citations": []any{}}
	}
	daemon.evaluate = func([]M, []M, M, M, M, M) M { return dtEvaluation(decision, findings, fake.now) }
	return daemon
}

func dtApprovalComment(evaluationID, login, association string, created int64) M {
	stamp := ghISOUTC(created)
	return M{
		"id": 42, "body": "/guard approve " + evaluationID,
		"user": M{"login": login}, "author_association": association,
		"created_at": stamp, "updated_at": stamp,
		"html_url": "https://example.invalid/approval",
	}
}

func dtReSign(report M) M {
	clone := Clone(report)
	delete(clone, "report_digest")
	clone["report_digest"] = Hash(clone)
	return clone
}

func dtLastStatus(fake *dtFakeGitHub) M {
	if len(fake.statuses) == 0 {
		return M{}
	}
	return fake.statuses[len(fake.statuses)-1]
}

func dtPRResult(t *testing.T, summary M) M {
	t.Helper()
	prs := Arr(summary["prs"])
	if len(prs) != 1 {
		t.Fatalf("expected one PR result, got %#v", summary)
	}
	return asM(prs[0])
}

func TestDaemonStateLockIsKernelLifetimeAndLeavesLockFile(t *testing.T) {
	root := t.TempDir()
	store, err := newStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a file stranded by a previous O_EXCL implementation or a crash.
	if err = os.WriteFile(store.lockPath, []byte("12345\n"), 0600); err != nil {
		t.Fatal(err)
	}
	release, err := store.lock()
	if err != nil {
		t.Fatalf("a stale lock file must not block the kernel lock: %v", err)
	}
	if _, err = store.lock(); err == nil {
		t.Fatal("second concurrent lock unexpectedly succeeded")
	} else {
		var busy *DaemonBusyError
		if !errors.As(err, &busy) {
			t.Fatalf("expected DaemonBusyError, got %T %v", err, err)
		}
	}
	release()
	if content, readErr := os.ReadFile(store.lockPath); readErr != nil || string(content) != "12345\n" {
		t.Fatalf("lock acquisition rewrote the existing lock file: %q %v", content, readErr)
	}

	// Releasing must make the lock immediately available again and must not
	// unlink the path; unlinking is what breaks flock identity between waiters.
	again, err := store.lock()
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	again()
	if _, err = os.Stat(store.lockPath); err != nil {
		t.Fatalf("lock file was removed on release: %v", err)
	}
	direct, err := daemonPlatformLock(store.lockPath)
	if err != nil {
		t.Fatalf("direct platform lock after release: %v", err)
	}
	if err = daemonPlatformUnlock(direct); err != nil {
		t.Fatalf("direct platform unlock: %v", err)
	}
}

func TestDaemonPassPendingThenSuccessAndReusesCache(t *testing.T) {
	fake := newDTFake(dtPR("open", false, 7))
	daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
	first := daemon.runOnce()
	if Str(first["status"]) != "ok" {
		t.Fatalf("first poll failed: %#v", first)
	}
	if len(fake.statuses) != 2 || Str(fake.statuses[0]["state"]) != "pending" || Str(fake.statuses[1]["state"]) != "success" {
		t.Fatalf("unexpected status sequence: %#v", fake.statuses)
	}
	result := dtPRResult(t, first)
	evaluationID := Str(result["evaluation_id"])
	if evaluationID == "" {
		t.Fatal("missing evaluation id")
	}
	if _, err := os.Stat(filepath.Join(daemon.store.reportsDir, evaluationID+".json")); err != nil {
		t.Fatalf("report was not persisted: %v", err)
	}
	statusCount := len(fake.statuses)
	second := daemon.runOnce()
	if Str(second["status"]) != "ok" || !Bool(dtPRResult(t, second)["reused"]) {
		t.Fatalf("valid cached report was not reused: %#v", second)
	}
	if len(fake.statuses) != statusCount {
		t.Fatalf("reused report republished a status: %#v", fake.statuses)
	}
}

func TestDaemonHeadOrBaseChangeInvalidatesCache(t *testing.T) {
	for _, change := range []string{"head", "base"} {
		t.Run(change, func(t *testing.T) {
			fake := newDTFake(dtPR("open", false, 7))
			daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
			first := daemon.runOnce()
			firstID := Str(dtPRResult(t, first)["evaluation_id"])
			if firstID == "" {
				t.Fatal("missing first evaluation")
			}
			switch change {
			case "head":
				fake.pr.HeadSHA = strings.Repeat("c", 40)
				fake.candidate.PullRequest.HeadSHA = fake.pr.HeadSHA
				fake.candidate.HeadSnapshot.SHA = fake.pr.HeadSHA
			case "base":
				fake.pr.BaseSHA = strings.Repeat("c", 40)
				fake.baseSHA = fake.pr.BaseSHA
				fake.candidate.BaseSHA = fake.baseSHA
				fake.candidate.PRBaseSHA = fake.baseSHA
				fake.candidate.BaseSnapshot.SHA = fake.baseSHA
			}
			fake.now++
			second := daemon.runOnce()
			result := dtPRResult(t, second)
			if Bool(result["reused"]) {
				t.Fatalf("%s change reused a stale report: %#v", change, result)
			}
			if Str(result["evaluation_id"]) == firstID {
				t.Fatalf("%s change reused the old evaluation id", change)
			}
			if state := Str(dtLastStatus(fake)["state"]); state != "success" {
				t.Fatalf("%s change did not publish a fresh success: %#v", change, fake.statuses)
			}
		})
	}
}

func TestDaemonExpiredReportIsReevaluated(t *testing.T) {
	fake := newDTFake(dtPR("open", false, 7))
	daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
	first := daemon.runOnce()
	firstID := Str(dtPRResult(t, first)["evaluation_id"])
	fake.now += 300
	second := daemon.runOnce()
	result := dtPRResult(t, second)
	if Bool(result["reused"]) {
		t.Fatal("expired report was reused")
	}
	if Str(result["evaluation_id"]) == firstID {
		t.Fatal("expired report kept the same evaluation id")
	}
	if state := Str(dtLastStatus(fake)["state"]); state != "success" {
		t.Fatalf("fresh evaluation did not reach success: %#v", fake.statuses)
	}
}

func TestDaemonWorkflowChangeAndChartPinControlStatus(t *testing.T) {
	t.Run("workflow path is a hard block", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.candidate = dtCandidate(fake.pr)
		fake.candidate.ChangedPaths = []string{".github/workflows/ci.yml"}
		fake.candidate.ChangedCount = 1
		daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
		first := daemon.runOnce()
		result := dtPRResult(t, first)
		if Str(result["decision"]) != "BLOCK" || Str(dtLastStatus(fake)["state"]) != "failure" {
			t.Fatalf("workflow path did not hard-block: %#v %#v", result, fake.statuses)
		}
		report, err := daemon.store.readReport(Str(result["evaluation_id"]))
		if err != nil {
			t.Fatal(err)
		}
		if !dtHasRule(report, "WORKFLOW_CHANGE_BLOCKED") || !Bool(report["workflow_changed"]) {
			t.Fatalf("workflow block not recorded: %#v", report)
		}
	})

	t.Run("workflow tree signature blocks without path list", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.candidate = dtCandidate(fake.pr)
		fake.candidate.BaseSnapshot.Entries = map[string]TreeEntry{
			".github/workflows/ci.yml": {Path: ".github/workflows/ci.yml", Mode: "100644", Kind: "blob", SHA: strings.Repeat("1", 40)},
		}
		fake.candidate.HeadSnapshot.Entries = map[string]TreeEntry{
			".github/workflows/ci.yml": {Path: ".github/workflows/ci.yml", Mode: "100644", Kind: "blob", SHA: strings.Repeat("2", 40)},
		}
		daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
		result := dtPRResult(t, daemon.runOnce())
		if Str(result["decision"]) != "BLOCK" {
			t.Fatalf("workflow tree change was not blocked: %#v", result)
		}
		report, err := daemon.store.readReport(Str(result["evaluation_id"]))
		if err != nil {
			t.Fatal(err)
		}
		if !dtHasRule(report, "WORKFLOW_CHANGE_BLOCKED") {
			t.Fatalf("workflow block not recorded: %#v", report)
		}
		paths := Arr(asM(report["context"])["workflow_paths"])
		if len(paths) != 1 || Str(paths[0]) != ".github/workflows/ci.yml" {
			t.Fatalf("workflow path missing from context: %#v", paths)
		}
	})

	t.Run("chart pin mismatch blocks and missing pin errors", func(t *testing.T) {
		files := map[string][]byte{"charts/demo/Chart.yaml": []byte("apiVersion: v2\nname: demo\n")}
		digest, err := ChartDigestFromFiles(files)
		if err != nil {
			t.Fatal(err)
		}

		fake := newDTFake(dtPR("open", false, 7))
		fake.candidate = dtCandidate(fake.pr)
		fake.candidate.HeadSnapshot.RendererFiles = files
		daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
		result := dtPRResult(t, daemon.runOnce())
		if Str(result["decision"]) != "BLOCK" || Str(dtLastStatus(fake)["state"]) != "failure" {
			t.Fatalf("chart mismatch was not blocked: %#v %#v", result, fake.statuses)
		}

		fake = newDTFake(dtPR("open", false, 7))
		fake.candidate = dtCandidate(fake.pr)
		fake.candidate.HeadSnapshot.RendererFiles = files
		daemon = dtNewDaemon(t, fake, M{"approved_chart_digest": []any{}}, "PASS", nil)
		result = dtPRResult(t, daemon.runOnce())
		if Str(result["decision"]) != "ERROR" || Str(dtLastStatus(fake)["state"]) != "error" {
			t.Fatalf("missing chart pin was not an error: %#v %#v", result, fake.statuses)
		}

		fake = newDTFake(dtPR("open", false, 7))
		fake.candidate = dtCandidate(fake.pr)
		fake.candidate.HeadSnapshot.RendererFiles = files
		daemon = dtNewDaemon(t, fake, M{"approved_chart_digest": []any{digest}}, "PASS", nil)
		result = dtPRResult(t, daemon.runOnce())
		if Str(result["decision"]) != "PASS" || Str(dtLastStatus(fake)["state"]) != "success" {
			t.Fatalf("matching chart pin did not pass: %#v %#v", result, fake.statuses)
		}
	})
}

func dtHasRule(report M, ruleID string) bool {
	for _, raw := range Arr(report["findings"]) {
		if Str(asM(raw)["rule_id"]) == ruleID {
			return true
		}
	}
	return false
}

func TestDaemonReviewRequiresExactAllowlistedCurrentOwnerApproval(t *testing.T) {
	fake := newDTFake(dtPR("open", false, 7))
	fake.owner = M{"owner_login": "alice", "owner_type": "User", "full_name": "o/r"}
	fake.permission = "read"
	daemon := dtNewDaemon(t, fake, M{}, "REVIEW", nil)

	first := daemon.runOnce()
	evaluationID := Str(dtPRResult(t, first)["evaluation_id"])
	if evaluationID == "" || Str(dtLastStatus(fake)["state"]) != "pending" {
		t.Fatalf("REVIEW did not wait for approval: %#v %#v", first, fake.statuses)
	}
	if fake.identityCalls != 0 || len(fake.permissionCalls) != 0 {
		t.Fatalf("approval APIs called without an approval comment: %d %v", fake.identityCalls, fake.permissionCalls)
	}

	fake.comments = []M{dtApprovalComment(evaluationID, "alice", "OWNER", dtNow+1)}
	second := daemon.runOnce()
	result := dtPRResult(t, second)
	if Str(dtLastStatus(fake)["state"]) != "success" {
		t.Fatalf("exact owner approval did not succeed: %#v", fake.statuses)
	}
	if Str(asM(result["approval"])["permission"]) != ghOwnerApprovalPermission {
		t.Fatalf("unexpected approval permission: %#v", result["approval"])
	}
	if len(fake.permissionCalls) != 0 {
		t.Fatalf("owner approval unnecessarily used the permission API: %v", fake.permissionCalls)
	}
	if fake.identityCalls != 2 {
		t.Fatalf("owner identity should be rechecked before success, calls=%d", fake.identityCalls)
	}
}

func TestDaemonApprovalAllowlistTimestampAndPermissionFailClosed(t *testing.T) {
	t.Run("wrong login prefix and old comment are ignored", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.owner = M{"owner_login": "alice", "owner_type": "User"}
		daemon := dtNewDaemon(t, fake, M{}, "REVIEW", nil)
		evaluationID := Str(dtPRResult(t, daemon.runOnce())["evaluation_id"])
		wrongLogin := dtApprovalComment(evaluationID, "mallory", "OWNER", dtNow+1)
		prefix := dtApprovalComment(evaluationID, "alice", "OWNER", dtNow+1)
		prefix["body"] = "prefix /guard approve " + evaluationID
		old := dtApprovalComment(evaluationID, "alice", "OWNER", dtNow-10)
		fake.comments = []M{wrongLogin, prefix, old}
		result := dtPRResult(t, daemon.runOnce())
		if Str(dtLastStatus(fake)["state"]) != "pending" || len(fake.permissionCalls) != 0 {
			t.Fatalf("invalid approvals were accepted: %#v %v", fake.statuses, fake.permissionCalls)
		}
		if Str(result["approval"]) != "" {
			t.Fatalf("unexpected approval result: %#v", result["approval"])
		}
	})

	t.Run("non owner permission error fails closed", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.owner = M{"owner_login": "org", "owner_type": "Organization"}
		fake.permissionErr = errors.New("Resource not accessible by personal access token")
		daemon := dtNewDaemon(t, fake, M{}, "REVIEW", nil)
		evaluationID := Str(dtPRResult(t, daemon.runOnce())["evaluation_id"])
		fake.comments = []M{dtApprovalComment(evaluationID, "alice", "MEMBER", dtNow+1)}
		result := dtPRResult(t, daemon.runOnce())
		if Str(dtLastStatus(fake)["state"]) != "pending" {
			t.Fatalf("forbidden permission unexpectedly approved: %#v", fake.statuses)
		}
		if len(fake.permissionCalls) != 1 || fake.permissionCalls[0] != "alice" {
			t.Fatalf("permission API not consulted exactly once: %v", fake.permissionCalls)
		}
		if !strings.Contains(Str(result["approval_error"]), "cannot verify current write permission") {
			t.Fatalf("permission error was not surfaced: %#v", result)
		}
	})

	t.Run("owner identity error fails closed", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.ownerErr = errors.New("repository identity changed")
		daemon := dtNewDaemon(t, fake, M{}, "REVIEW", nil)
		evaluationID := Str(dtPRResult(t, daemon.runOnce())["evaluation_id"])
		fake.comments = []M{dtApprovalComment(evaluationID, "alice", "OWNER", dtNow+1)}
		result := dtPRResult(t, daemon.runOnce())
		if Str(dtLastStatus(fake)["state"]) != "pending" {
			t.Fatalf("owner identity error unexpectedly approved: %#v", fake.statuses)
		}
		if !strings.Contains(Str(result["approval_error"]), "cannot verify current repository owner") {
			t.Fatalf("identity error was not surfaced: %#v", result)
		}
	})
}

func TestDaemonCachedReportReuseRejectsForgedWorkflowPass(t *testing.T) {
	fake := newDTFake(dtPR("open", false, 7))
	daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
	first := daemon.runOnce()
	report, err := daemon.store.readReport(Str(dtPRResult(t, first)["evaluation_id"]))
	if err != nil {
		t.Fatal(err)
	}

	control := Clone(report)
	control["evaluation_id"] = "ev-" + strings.Repeat("c", 24)
	control = dtReSign(control)
	if _, _, err = daemon.store.writeReport(control); err != nil {
		t.Fatal(err)
	}
	controlEntry := M{"evaluation_id": control["evaluation_id"], "head_sha": dtHead, "base_sha": dtBase}
	if cached, _ := daemon.loadValidCached(controlEntry, fake.pr, dtBase, dtNow); cached == nil {
		t.Fatal("re-signed control report should be reusable")
	}

	forged := Clone(report)
	forged["evaluation_id"] = "ev-" + strings.Repeat("f", 24)
	forged["changed_paths"] = []any{".github/workflows/ci.yml"}
	context := asM(forged["context"])
	context["workflow_changed"] = true
	forged["context"] = context
	forged = dtReSign(forged)
	if _, _, err = daemon.store.writeReport(forged); err != nil {
		t.Fatal(err)
	}
	forgedEntry := M{"evaluation_id": forged["evaluation_id"], "head_sha": dtHead, "base_sha": dtBase}
	if cached, _ := daemon.loadValidCached(forgedEntry, fake.pr, dtBase, dtNow); cached != nil {
		t.Fatalf("forged workflow PASS report was reused: %#v", cached)
	}
}

func TestDaemonCachedReportInvalidatedByPolicyChange(t *testing.T) {
	root := t.TempDir()
	fake := newDTFake(dtPR("open", false, 7))
	firstDaemon := dtNewDaemon(t, fake, M{"state_dir": root}, "PASS", nil)
	first := firstDaemon.runOnce()
	firstID := Str(dtPRResult(t, first)["evaluation_id"])

	upgraded := dtNewDaemon(t, fake, M{"state_dir": root, "max_error_ratio": 0.01}, "PASS", nil)
	second := upgraded.runOnce()
	result := dtPRResult(t, second)
	if Bool(result["reused"]) {
		t.Fatal("policy change reused a report bound to the old policy")
	}
	if Str(result["evaluation_id"]) == firstID {
		t.Fatal("policy change kept the old evaluation id")
	}
}

func TestDaemonPolicyDigestTracksPolicyNotRuntimePaths(t *testing.T) {
	base := dtConfig(t, M{})
	baseline, err := daemonPolicyDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{
		"state_dir":         filepath.Join(t.TempDir(), "other"),
		"poll_seconds":      float64(60),
		"github_token_file": "/etc/change-guard/other-token",
		"merge_deploy_key":  "/etc/change-guard/other-key",
		"report_comment":    true,
	} {
		changed := dtConfig(t, M{key: value})
		digest, digestErr := daemonPolicyDigest(changed)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		if digest != baseline {
			t.Fatalf("%s changed the policy binding unexpectedly", key)
		}
	}
	for key, value := range map[string]any{
		"approved_chart_digest":      []any{strings.Repeat("0", 64)},
		"require_digest":             false,
		"max_error_ratio":            0.01,
		"max_p95_seconds":            0.2,
		"deepseek_timeout_seconds":   float64(31),
		"postdeploy_timeout_seconds": float64(301),
	} {
		changed := dtConfig(t, M{key: value})
		digest, digestErr := daemonPolicyDigest(changed)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		if digest == baseline {
			t.Fatalf("%s did not change the policy binding", key)
		}
	}
}

func TestDaemonCredentialFailureAndClosedRevocation(t *testing.T) {
	t.Run("credential failure publishes no status", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		fake.verifyErr = errors.New("bad token")
		daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
		result := daemon.runOnce()
		if Str(result["status"]) != "error" || !strings.Contains(Str(result["error"]), "credential verification failed") {
			t.Fatalf("credential failure not reported: %#v", result)
		}
		if len(fake.statuses) != 0 {
			t.Fatalf("status published before credential verification: %#v", fake.statuses)
		}
	})

	t.Run("closed PR revokes the previous status", func(t *testing.T) {
		fake := newDTFake(dtPR("open", false, 7))
		daemon := dtNewDaemon(t, fake, M{}, "PASS", nil)
		if result := daemon.runOnce(); Str(result["status"]) != "ok" {
			t.Fatalf("initial evaluation failed: %#v", result)
		}
		fake.prs = []PullRequestInfo{}
		result := daemon.runOnce()
		if Str(result["status"]) != "ok" || N(result, "closed_invalidated") != 1 {
			t.Fatalf("closed PR was not invalidated: %#v", result)
		}
		last := dtLastStatus(fake)
		if Str(last["state"]) != "error" || !strings.Contains(Str(last["description"]), "closed or merged") {
			t.Fatalf("closed PR left a stale success: %#v", fake.statuses)
		}
	})
}

func TestDaemonBlockAndErrorStatusMapping(t *testing.T) {
	cases := []struct {
		decision string
		state    string
		severity string
	}{
		{"BLOCK", "failure", "BLOCK"},
		{"ERROR", "error", "ERROR"},
	}
	for _, test := range cases {
		t.Run(test.decision, func(t *testing.T) {
			fake := newDTFake(dtPR("open", false, 7))
			findings := []M{{"rule_id": "R", "severity": test.severity, "field": "x", "message": "no"}}
			daemon := dtNewDaemon(t, fake, M{}, test.decision, findings)
			result := dtPRResult(t, daemon.runOnce())
			if Str(result["state"]) != test.state || Str(dtLastStatus(fake)["state"]) != test.state {
				t.Fatalf("%s mapped to wrong status: %#v %#v", test.decision, result, fake.statuses)
			}
		})
	}
}
