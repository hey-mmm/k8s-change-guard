package guard

// Explicit, trusted merge command; closes the stale green-status failure mode.
//
// GitHub update rules allow only the repository deploy key to update main. This
// command is invoked by an operator, never by the model or an untrusted PR. It
// checks the current immutable report, approval, CI and exact Git parents,
// proves that GitHub's synthetic merge tree equals the evaluated head tree,
// then performs an exact-lease fast-forward push of that head commit. No
// checkout, candidate hook, or candidate program runs in the credentialed
// process.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	mergeDefaultRequiredCI = "Test, lint, render"
	mergeDefaultFetchDepth = 128
	mergeMaxFetchDepth     = 10000
	mergeMaxCheckRunBytes  = 2 * 1024 * 1024
	mergeHookPath          = "/dev/null"
)

var (
	mergeSSHProxyRE = regexp.MustCompile(`\A[0-9.]+:[0-9]+\z`)
	mergeUnsafeRE   = regexp.MustCompile(`[^A-Za-z0-9_@%+=:,./-]`)
	mergeAPIBaseURL = "https://api.github.com"
	mergeHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

// MergeRefused is a fail-closed merge refusal.
type MergeRefused struct{ Message string }

func (e *MergeRefused) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeText(e.Message, 1200)
}

func mergeRefuse(format string, args ...any) error {
	return &MergeRefused{Message: fmt.Sprintf(format, args...)}
}

type mergeAPI interface {
	API(method, path string, body any) (any, error)
}

type mergeTreeFetcher interface {
	FetchTreeSnapshot(sha string, includeArgo bool) (TreeSnapshot, error)
}

type mergeGitHub interface {
	mergeAPI
	mergeTreeFetcher
}

// mergeValidatePolicyBinding refuses a report produced by another
// guard/rule/policy generation.
func mergeValidatePolicyBinding(report, expected M) error {
	if report == nil || expected == nil {
		return mergeRefuse("report policy binding is invalid")
	}
	if N(report, "schema_version") != daemonSchemaVersion {
		return mergeRefuse("report schema version does not match the running guard")
	}
	actual, ok := report["policy_binding"].(map[string]any)
	if !ok || Hash(actual) != Hash(expected) {
		return mergeRefuse("report policy binding does not match the running guard/rule/policy")
	}
	if Str(report["guard_version"]) != Str(expected["guard_version"]) {
		return mergeRefuse("report guard version does not match the running guard")
	}
	if Str(report["rule_version"]) != Str(expected["rule_version"]) {
		return mergeRefuse("report rule version does not match the running rule engine")
	}
	if Str(report["policy_digest"]) != Str(expected["policy_digest"]) {
		return mergeRefuse("report policy digest does not match the current policy configuration")
	}
	return nil
}

// mergeValidateReport validates the immutable report against live GitHub state.
func mergeValidateReport(report M, pr PullRequestInfo, baseSHA string, now int64, minRemaining int64, policyBinding M) error {
	if report == nil {
		return mergeRefuse("evaluation report is unavailable")
	}
	if Str(report["head_sha"]) != pr.HeadSHA || Str(report["base_sha"]) != baseSHA {
		return mergeRefuse("report head/base no longer matches GitHub")
	}
	if pr.State != "open" || pr.Draft {
		return mergeRefuse("PR must be open and ready for review")
	}
	if N(report, "pull_request", "number") != float64(pr.Number) {
		return mergeRefuse("report belongs to a different PR")
	}
	decision := Str(report["decision"])
	if decision != "PASS" && decision != "REVIEW" {
		return mergeRefuse("BLOCK/ERROR cannot be merged")
	}
	evaluatedAt, evaluatedOK := daemonTime(report["evaluated_at"])
	if !evaluatedOK {
		evaluatedAt = now + 1
	}
	if evaluatedAt > now {
		return mergeRefuse("report evaluation time is in the future")
	}
	expiresAt, expiresOK := daemonTime(report["expires_at"])
	if !expiresOK {
		expiresAt = 0
	}
	if expiresAt-now < minRemaining {
		return mergeRefuse("report expired or insufficient validity remains for push")
	}
	if !daemonReportDigestMatches(report) {
		return mergeRefuse("report digest mismatch")
	}
	if policyBinding != nil {
		if err := mergeValidatePolicyBinding(report, policyBinding); err != nil {
			return err
		}
	}
	return nil
}

// mergeValidateCI requires the latest GitHub Actions check run to be
// successful. When expectedHeadSHA is supplied, a check run claiming a
// different head (or omitting head_sha) is rejected.
func mergeValidateCI(payload M, requiredName, expectedHeadSHA string) error {
	if payload == nil {
		return mergeRefuse("CI check-run payload is invalid")
	}
	runs, ok := payload["check_runs"].([]any)
	if !ok {
		return mergeRefuse("CI check-run payload is invalid")
	}
	matches := []M{}
	for _, raw := range runs {
		run, isMap := raw.(map[string]any)
		if !isMap {
			continue
		}
		if Str(run["name"]) != requiredName {
			continue
		}
		app := asM(run["app"])
		if Str(app["slug"]) != "github-actions" {
			continue
		}
		if expectedHeadSHA != "" && Str(run["head_sha"]) != expectedHeadSHA {
			continue
		}
		matches = append(matches, run)
	}
	if len(matches) == 0 {
		return mergeRefuse("required GitHub Actions CI check is missing for the evaluated head")
	}
	latest := matches[0]
	latestID := int64(0)
	if id, ok := ghInt(latest["id"]); ok {
		latestID = id
	}
	for _, run := range matches[1:] {
		id, ok := ghInt(run["id"])
		if !ok {
			id = 0
		}
		if id > latestID {
			latest = run
			latestID = id
		}
	}
	if Str(latest["status"]) != "completed" || Str(latest["conclusion"]) != "success" {
		return mergeRefuse("required GitHub Actions CI is not successful")
	}
	return nil
}

// mergeValidateWorkflowSnapshots requires base/head workflow tree content to be
// identical, independent of the report decision.
func mergeValidateWorkflowSnapshots(baseSnapshot, headSnapshot TreeSnapshot) (map[string][]string, error) {
	baseSignature := WorkflowTreeSignature(baseSnapshot.Entries)
	headSignature := WorkflowTreeSignature(headSnapshot.Entries)
	if !ghWorkflowSignatureEqual(baseSignature, headSignature) {
		changed := ghChangedWorkflowPaths(baseSignature, headSignature)
		if len(changed) > 10 {
			changed = changed[:10]
		}
		return nil, mergeRefuse(".github/workflows tree differs between base and head: %s", strings.Join(changed, ", "))
	}
	return baseSignature, nil
}

// mergeVerifyBaseHeadWorkflows re-fetches both trees and rejects any workflow
// difference.
func mergeVerifyBaseHeadWorkflows(github mergeTreeFetcher, baseSHA, headSHA string) (TreeSnapshot, TreeSnapshot, error) {
	baseSnapshot, err := github.FetchTreeSnapshot(baseSHA, false)
	if err != nil {
		return TreeSnapshot{}, TreeSnapshot{}, mergeRefuse("cannot verify base/head workflow trees: %s", daemonSafeText(err, 800))
	}
	headSnapshot, err := github.FetchTreeSnapshot(headSHA, false)
	if err != nil {
		return TreeSnapshot{}, TreeSnapshot{}, mergeRefuse("cannot verify base/head workflow trees: %s", daemonSafeText(err, 800))
	}
	if _, err = mergeValidateWorkflowSnapshots(baseSnapshot, headSnapshot); err != nil {
		return TreeSnapshot{}, TreeSnapshot{}, err
	}
	return baseSnapshot, headSnapshot, nil
}

// mergeValidateChartPin independently verifies the candidate chart bytes
// against the operator-approved pin.
func mergeValidateChartPin(config M, report M, headSnapshot TreeSnapshot) (string, error) {
	approved, err := daemonNormalizedDigestList(config["approved_chart_digest"], "approved_chart_digest")
	if err != nil || len(approved) == 0 {
		return "", mergeRefuse("approved_chart_digest is not configured; refusing merge")
	}
	files := headSnapshot.RendererFiles
	if files == nil {
		return "", mergeRefuse("head chart files are unavailable")
	}
	actual, err := ChartDigestFromFiles(files)
	if err != nil {
		return "", mergeRefuse("cannot digest candidate chart: %s", daemonSafeText(err, 500))
	}
	if Str(report["chart_digest"]) != actual {
		return "", mergeRefuse("report chart digest does not match the GitHub head tree")
	}
	if !containsString(approved, actual) {
		return "", mergeRefuse("candidate charts/demo digest is not operator-approved")
	}
	return actual, nil
}

// mergeValidateSyntheticMerge proves GitHub's synthetic merge tree is exactly
// the evaluated head tree with parents [base, head].
func mergeValidateSyntheticMerge(github mergeAPI, repository string, pullRequest M, baseSHA, headSHA string) (M, error) {
	if !daemonSHARegex.MatchString(headSHA) {
		return nil, mergeRefuse("evaluated head SHA is invalid")
	}
	rawSHA := Str(pullRequest["merge_commit_sha"])
	if !daemonSHARegex.MatchString(rawSHA) {
		return nil, mergeRefuse("GitHub synthetic merge commit is unavailable")
	}
	prefix := "/repos/" + repository
	syntheticValue, err := github.API("GET", prefix+"/git/commits/"+rawSHA, nil)
	if err != nil {
		return nil, mergeRefuse("cannot read GitHub synthetic merge commit: %s", daemonSafeText(err, 500))
	}
	headValue, err := github.API("GET", prefix+"/git/commits/"+headSHA, nil)
	if err != nil {
		return nil, mergeRefuse("cannot read evaluated head commit: %s", daemonSafeText(err, 500))
	}
	synthetic, ok := syntheticValue.(map[string]any)
	if !ok {
		return nil, mergeRefuse("GitHub commit response is invalid")
	}
	headCommit, ok := headValue.(map[string]any)
	if !ok {
		return nil, mergeRefuse("GitHub commit response is invalid")
	}
	rawParents, ok := synthetic["parents"].([]any)
	if !ok || len(rawParents) != 2 {
		return nil, mergeRefuse("synthetic merge commit parents are invalid")
	}
	parents := make([]string, 0, 2)
	for _, raw := range rawParents {
		parent, isMap := raw.(map[string]any)
		sha, isStr := parent["sha"].(string)
		if !isMap || !isStr {
			return nil, mergeRefuse("synthetic merge commit parents are invalid")
		}
		parents = append(parents, sha)
	}
	if len(parents) != 2 || parents[0] != baseSHA || parents[1] != headSHA {
		return nil, mergeRefuse("synthetic merge commit parents do not match evaluated head/base")
	}
	syntheticTreeSHA := Str(asM(synthetic["tree"])["sha"])
	headTreeSHA := Str(asM(headCommit["tree"])["sha"])
	if !daemonSHARegex.MatchString(syntheticTreeSHA) || !daemonSHARegex.MatchString(headTreeSHA) {
		return nil, mergeRefuse("GitHub commit tree is invalid")
	}
	if syntheticTreeSHA != headTreeSHA {
		return nil, mergeRefuse("synthetic merge tree does not equal the evaluated head tree; fast-forward unsafe")
	}
	return M{
		"synthetic_sha":      rawSHA,
		"synthetic_tree_sha": syntheticTreeSHA,
		"head_tree_sha":      headTreeSHA,
		"parents":            parents,
	}, nil
}

// mergeFetchCheckRuns reads check runs for sha from the public GitHub API.
func mergeFetchCheckRuns(repository, sha string) (M, error) {
	if !daemonSHARegex.MatchString(sha) {
		return nil, mergeRefuse("CI lookup SHA is invalid")
	}
	requestURL := mergeAPIBaseURL + "/repos/" + repository + "/commits/" + sha + "/check-runs?per_page=100"
	request, err := http.NewRequestWithContext(context.Background(), "GET", requestURL, nil)
	if err != nil {
		return nil, mergeRefuse("public CI check lookup failed")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "change-guard")
	response, err := mergeHTTPClient.Do(request)
	if err != nil {
		return nil, mergeRefuse("public CI check lookup failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, mergeRefuse("public CI check lookup failed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, mergeMaxCheckRunBytes+1))
	if err != nil || len(raw) > mergeMaxCheckRunBytes {
		return nil, mergeRefuse("public CI check lookup failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload any
	if err = decoder.Decode(&payload); err != nil {
		return nil, mergeRefuse("public CI check payload is invalid")
	}
	object, ok := payload.(map[string]any)
	if !ok {
		return nil, mergeRefuse("public CI check payload is invalid")
	}
	runs, ok := object["check_runs"].([]any)
	if !ok {
		return nil, mergeRefuse("public CI check payload is invalid")
	}
	if total, ok := ghInt(object["total_count"]); ok && total > int64(len(runs)) {
		return nil, mergeRefuse("public CI check-run response is incomplete")
	}
	return object, nil
}

// mergeValidateHeadCI validates GitHub Actions checks bound to headSHA.
func mergeValidateHeadCI(repository, headSHA, requiredName string) (M, error) {
	payload, err := mergeFetchCheckRuns(repository, headSHA)
	if err != nil {
		return nil, err
	}
	if err = mergeValidateCI(payload, requiredName, headSHA); err != nil {
		return nil, err
	}
	return payload, nil
}

func mergeFetchDepth(config M) (int, error) {
	raw, exists := config["merge_fetch_depth"]
	if !exists {
		return mergeDefaultFetchDepth, nil
	}
	depth, ok := daemonIntStrict(raw)
	if !ok || depth < 1 || depth > mergeMaxFetchDepth {
		return 0, mergeRefuse("merge_fetch_depth must be an integer between 1 and 10000")
	}
	return int(depth), nil
}

// mergeFastForwardPushArgv builds the exact-head, exact-lease push command.
func mergeFastForwardPushArgv(repository, baseSHA, headSHA string) []string {
	return []string{
		"push",
		"--force-with-lease=refs/heads/main:" + baseSHA,
		"ssh://git@ssh.github.com:443/" + repository + ".git",
		headSHA + ":refs/heads/main",
	}
}

type mergeGitResult struct {
	Stdout string
	Stderr string
	Code   int
}

var mergeGitRunner = mergeRunGitProcess

func mergeAllowedEnv(name string) bool {
	switch strings.ToUpper(name) {
	case "PATH", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "LANG",
		"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP":
		return true
	}
	return false
}

func mergeShellQuote(args []string) string {
	quoted := make([]string, len(args))
	for index, arg := range args {
		if arg != "" && !mergeUnsafeRE.MatchString(arg) {
			quoted[index] = arg
			continue
		}
		quoted[index] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func mergeRunGitProcess(argv []string, cwd string, config M, timeout time.Duration) (mergeGitResult, error) {
	env := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if mergeAllowedEnv(name) {
			env = append(env, entry)
		}
	}
	env = append(env,
		"HOME="+cwd,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_SSH_VARIANT=ssh",
	)
	deployKey := CfgString(config, "merge_deploy_key", "")
	knownHosts := CfgString(config, "merge_known_hosts", "")
	sshArgs := []string{
		"ssh", "-i", deployKey,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-p", "443",
	}
	if raw, exists := config["merge_ssh_proxy"]; exists && raw != nil && fmt.Sprint(raw) != "" {
		proxy := fmt.Sprint(raw)
		if !mergeSSHProxyRE.MatchString(proxy) {
			return mergeGitResult{}, mergeRefuse("invalid trusted SSH proxy configuration")
		}
		sshArgs = append(sshArgs, "-o", "ProxyCommand=nc -X connect -x "+proxy+" %h %p")
	}
	env = append(env, "GIT_SSH_COMMAND="+mergeShellQuote(sshArgs))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	commandArgs := append([]string{"-c", "core.hooksPath=" + mergeHookPath}, argv...)
	command := exec.CommandContext(ctx, "git", commandArgs...)
	command.Dir = cwd
	command.Env = env
	command.Stdin = nil
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return mergeGitResult{Stdout: stdout.String(), Stderr: stderr.String(), Code: 124}, mergeRefuse("trusted git operation timed out")
	}
	if err != nil {
		var exitError *exec.ExitError
		if ok := asExitError(err, &exitError); ok {
			return mergeGitResult{Stdout: stdout.String(), Stderr: stderr.String(), Code: exitError.ExitCode()}, nil
		}
		return mergeGitResult{Stdout: stdout.String(), Stderr: stderr.String(), Code: 1}, mergeRefuse("trusted git operation could not start")
	}
	return mergeGitResult{Stdout: stdout.String(), Stderr: stderr.String(), Code: 0}, nil
}

func asExitError(err error, target **exec.ExitError) bool {
	if exit, ok := err.(*exec.ExitError); ok {
		*target = exit
		return true
	}
	return false
}

func mergeGit(argv []string, cwd string, config M, timeout time.Duration) (string, error) {
	result, err := mergeGitRunner(argv, cwd, config, timeout)
	if err != nil {
		return "", err
	}
	if result.Code != 0 {
		// Git may echo URLs but this command never uses token-bearing URLs.
		stderr := result.Stderr
		if len(stderr) > 1000 {
			stderr = stderr[len(stderr)-1000:]
		}
		return "", mergeRefuse("trusted git operation failed: %s", sanitizeText(stderr, 1000))
	}
	return strings.TrimSpace(result.Stdout), nil
}

func mergeGitReturnCode(argv []string, cwd string, config M, timeout time.Duration) (int, error) {
	result, err := mergeGitRunner(argv, cwd, config, timeout)
	if err != nil {
		return 0, err
	}
	return result.Code, nil
}

// mergeVerifyLocalFastForward verifies the fetched head tree and, when not
// shallow-limited, ancestry from the exact current base.
func mergeVerifyLocalFastForward(directory string, config M, repository, baseSHA, headSHA, expectedHeadTree string) (M, error) {
	depth, err := mergeFetchDepth(config)
	if err != nil {
		return nil, err
	}
	url := "https://github.com/" + repository + ".git"
	if _, err = mergeGit([]string{"fetch", "--no-tags", "--depth=" + strconv.Itoa(depth), url, headSHA}, directory, config, 45*time.Second); err != nil {
		return nil, err
	}
	if _, err = mergeGit([]string{"fetch", "--no-tags", "--depth=" + strconv.Itoa(depth), url, baseSHA}, directory, config, 45*time.Second); err != nil {
		return nil, err
	}
	localHead, err := mergeGit([]string{"rev-parse", headSHA + "^{commit}"}, directory, config, 45*time.Second)
	if err != nil {
		return nil, err
	}
	if localHead != headSHA {
		return nil, mergeRefuse("fetched Git head does not match the evaluated head")
	}
	localTree, err := mergeGit([]string{"rev-parse", headSHA + "^{tree}"}, directory, config, 45*time.Second)
	if err != nil {
		return nil, err
	}
	if localTree != expectedHeadTree {
		return nil, mergeRefuse("fetched Git head tree does not match the GitHub head tree")
	}
	localBase, err := mergeGit([]string{"rev-parse", baseSHA + "^{commit}"}, directory, config, 45*time.Second)
	if err != nil {
		return nil, err
	}
	if localBase != baseSHA {
		return nil, mergeRefuse("fetched Git base does not match the current main")
	}
	ancestorStatus, err := mergeGitReturnCode([]string{"merge-base", "--is-ancestor", baseSHA, headSHA}, directory, config, 45*time.Second)
	if err != nil {
		return nil, err
	}
	var baseAncestor any
	switch ancestorStatus {
	case 0:
		baseAncestor = true
	case 1:
		shallow, shallowErr := mergeGit([]string{"rev-parse", "--is-shallow-repository"}, directory, config, 45*time.Second)
		if shallowErr != nil {
			return nil, shallowErr
		}
		if strings.TrimSpace(shallow) != "true" {
			return nil, mergeRefuse("Git base is not an ancestor of the evaluated head")
		}
		// The GitHub compare API already proved merge_base == base. A shallow
		// local fetch may not contain enough graph edges to re-prove it.
		baseAncestor = nil
	default:
		return nil, mergeRefuse("local Git base-ancestor check failed")
	}
	return M{"head_tree_sha": localTree, "base_ancestor": baseAncestor}, nil
}

func mergePushFastForward(directory string, config M, repository, baseSHA, headSHA string) ([]string, error) {
	argv := mergeFastForwardPushArgv(repository, baseSHA, headSHA)
	if _, err := mergeGit(argv, directory, config, 12*time.Second); err != nil {
		return nil, err
	}
	return argv, nil
}

func mergeBuildRecord(number int64, headSHA, baseSHA string, synthetic, local, report M, now int64) M {
	rollbackCommand := "git revert " + headSHA
	return M{
		"result":                "MERGED",
		"strategy":              "fast-forward",
		"pr":                    number,
		"head_sha":              headSHA,
		"evaluated_head":        headSHA,
		"base_sha":              baseSHA,
		"merge_sha":             headSHA,
		"synthetic_merge_sha":   synthetic["synthetic_sha"],
		"synthetic_tree_sha":    synthetic["synthetic_tree_sha"],
		"head_tree_sha":         local["head_tree_sha"],
		"base_ancestor":         local["base_ancestor"],
		"evaluation_id":         report["evaluation_id"],
		"decision":              report["decision"],
		"merged_at":             now,
		"evidence_expires_at":   report["expires_at"],
		"github_merge_api_used": false,
		"rollback": M{
			"strategy": "git-revert",
			"commit":   headSHA,
			"mainline": nil,
			// The commit on main is a normal single-parent head commit, so a
			// rollback is a plain revert with no -m/--mainline.
			"command": rollbackCommand,
		},
	}
}

// MergeRelease performs the explicit constrained release merge of one exact
// evaluated head SHA. It never calls the GitHub merge API.
func MergeRelease(config M, number int, evaluationID string) (M, error) {
	if number < 1 {
		return nil, mergeRefuse("invalid PR number")
	}
	if !daemonApprovalIDRE.MatchString(evaluationID) {
		return nil, mergeRefuse("invalid evaluation id")
	}
	if CfgString(config, "base_branch", "main") != "main" {
		return nil, mergeRefuse("this merger only targets main")
	}
	for _, key := range []string{"merge_deploy_key", "merge_known_hosts"} {
		path := CfgString(config, key, "")
		if path == "" {
			return nil, mergeRefuse("missing trusted merge configuration: %s", key)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, mergeRefuse("missing trusted merge configuration: %s", key)
		}
	}
	daemon, err := newGuardDaemon(config)
	if err != nil {
		return nil, mergeRefuse("%s", daemonSafeText(err, 500))
	}
	if daemon.concrete == nil {
		return nil, mergeRefuse("trusted GitHub client is unavailable")
	}
	github := daemon.concrete
	release, err := daemon.store.lock()
	if err != nil {
		return nil, err
	}
	defer release()
	index, err := daemon.store.loadIndex()
	if err != nil {
		return nil, err
	}
	entry := asM(daemonEnsurePRMap(index)[strconv.Itoa(number)])
	recordedID := Str(entry["evaluation_id"])
	if recordedID != "" && recordedID != evaluationID {
		return nil, mergeRefuse("explicit evaluation id is not the recorded evaluation for this PR")
	}
	report, err := daemon.store.readReport(evaluationID)
	if err != nil {
		return nil, mergeRefuse("cannot read evaluation report: %s", daemonSafeText(err, 500))
	}
	if Str(report["evaluation_id"]) != evaluationID {
		return nil, mergeRefuse("evaluation report id mismatch")
	}
	pr, err := github.GetPullRequest(int64(number))
	if err != nil {
		return nil, mergeRefuse("cannot read pull request: %s", daemonSafeText(err, 500))
	}
	base, err := github.GetBranchHead("main")
	if err != nil {
		return nil, mergeRefuse("cannot read main: %s", daemonSafeText(err, 500))
	}
	binding, err := daemonCurrentPolicyBinding(daemon.config)
	if err != nil {
		return nil, mergeRefuse("cannot compute policy binding: %s", daemonSafeText(err, 500))
	}
	if err = mergeValidateReport(report, pr, base, time.Now().Unix(), 20, binding); err != nil {
		return nil, err
	}
	if Str(report["decision"]) == "REVIEW" {
		approval, approvalError := daemon.resolveApproval(report, pr)
		if approval == nil {
			return nil, mergeRefuse("current REVIEW approval missing: %s", daemonFirstNonEmpty(approvalError, "not approved"))
		}
	}

	// Re-fetch the Git trees independently. A forged/incorrect PASS report is
	// still refused when a workflow blob differs between base and head. The
	// candidate chart pin is re-verified from the same raw blobs.
	reportedPaths := Arr(report["changed_paths"])
	for _, raw := range reportedPaths {
		if IsWorkflowPath(raw) {
			return nil, mergeRefuse("report records a .github/workflows change; refusing merge")
		}
	}
	if Bool(report["workflow_changed"]) {
		return nil, mergeRefuse("report records a .github/workflows change; refusing merge")
	}
	_, headSnapshot, err := mergeVerifyBaseHeadWorkflows(github, base, pr.HeadSHA)
	if err != nil {
		return nil, err
	}
	if _, err = mergeValidateChartPin(daemon.config, report, headSnapshot); err != nil {
		return nil, err
	}
	repository := CfgString(daemon.config, "repository", "")
	prefix := "/repos/" + repository
	compareValue, err := github.API("GET", prefix+"/compare/"+base+"..."+pr.HeadSHA, nil)
	if err != nil {
		return nil, mergeRefuse("cannot compare base/head: %s", daemonSafeText(err, 500))
	}
	compare, ok := compareValue.(map[string]any)
	if !ok || Str(asM(compare["merge_base_commit"])["sha"]) != base {
		return nil, mergeRefuse("update PR with current main before merging")
	}
	rawPRValue, err := github.API("GET", prefix+"/pulls/"+strconv.Itoa(number), nil)
	if err != nil {
		return nil, mergeRefuse("cannot read pull request merge commit: %s", daemonSafeText(err, 500))
	}
	rawPR, ok := rawPRValue.(map[string]any)
	if !ok {
		return nil, mergeRefuse("pull request response is invalid")
	}
	synthetic, err := mergeValidateSyntheticMerge(github, repository, rawPR, base, pr.HeadSHA)
	if err != nil {
		return nil, err
	}
	requiredCI := CfgString(daemon.config, "merge_required_ci", mergeDefaultRequiredCI)
	if _, err = mergeValidateHeadCI(repository, pr.HeadSHA, requiredCI); err != nil {
		return nil, err
	}

	temporary, err := os.MkdirTemp("", "change-guard-merge-")
	if err != nil {
		return nil, mergeRefuse("cannot create merge workspace")
	}
	defer os.RemoveAll(temporary)
	if _, err = mergeGit([]string{"init", "--bare", "."}, temporary, daemon.config, 45*time.Second); err != nil {
		return nil, mergeRefuse("cannot initialise bare merge repository: %s", daemonSafeText(err, 500))
	}
	local, err := mergeVerifyLocalFastForward(temporary, daemon.config, repository, base, pr.HeadSHA, Str(synthetic["head_tree_sha"]))
	if err != nil {
		return nil, err
	}
	fresh, err := github.GetPullRequest(int64(number))
	if err != nil {
		return nil, mergeRefuse("cannot re-read pull request: %s", daemonSafeText(err, 500))
	}
	currentBase, err := github.GetBranchHead("main")
	if err != nil {
		return nil, mergeRefuse("cannot re-read main: %s", daemonSafeText(err, 500))
	}
	if err = mergeValidateReport(report, fresh, currentBase, time.Now().Unix(), 15, binding); err != nil {
		return nil, err
	}
	if Str(report["decision"]) == "REVIEW" {
		if approval, _ := daemon.resolveApproval(report, fresh); approval == nil {
			return nil, mergeRefuse("approval was revoked before push")
		}
	}
	if _, err = github.CreateCommitStatus(pr.HeadSHA, "success",
		fmt.Sprintf("Fresh %s %s", Str(report["decision"]), Str(report["evaluation_id"])),
		CfgString(daemon.config, "status_context", "change-guard/release"), ""); err != nil {
		return nil, mergeRefuse("cannot publish fresh status before push: %s", daemonSafeText(err, 500))
	}
	if err = mergeValidateReport(report, fresh, currentBase, time.Now().Unix(), 13, binding); err != nil {
		return nil, err
	}
	// The compare API proved base is an ancestor of head, so this is a
	// fast-forward. The exact lease still prevents a concurrent main update
	// between validation and push.
	if _, err = mergePushFastForward(temporary, daemon.config, repository, base, pr.HeadSHA); err != nil {
		return nil, err
	}
	record := mergeBuildRecord(int64(number), pr.HeadSHA, base, synthetic, local, report, time.Now().Unix())
	output := filepath.Join(CfgString(daemon.config, "state_dir", ""), "merges")
	if err = os.MkdirAll(output, 0700); err != nil {
		return nil, mergeRefuse("cannot create merge record directory")
	}
	path := filepath.Join(output, pr.HeadSHA+".json")
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, mergeRefuse("merge record is not JSON serializable")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, mergeRefuse("cannot create merge record")
	}
	if _, err = file.Write(append(encoded, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return nil, mergeRefuse("cannot write merge record")
	}
	return record, nil
}

func daemonFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
