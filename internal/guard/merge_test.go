package guard

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	mtHead      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mtBase      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mtSynthetic = "cccccccccccccccccccccccccccccccccccccccc"
	mtTree      = "1111111111111111111111111111111111111111"
	mtCIToken   = "ghs_synthetic_ci_token_0123456789"
)

func mtPR() PullRequestInfo {
	return PullRequestInfo{Number: 3, HeadSHA: mtHead, BaseSHA: mtBase, State: "open"}
}

func mtSign(report M) M {
	clone := Clone(report)
	delete(clone, "report_digest")
	clone["report_digest"] = Hash(clone)
	return clone
}

func mtReport() M {
	return mtSign(M{
		"schema_version": daemonSchemaVersion,
		"evaluation_id":  "ev-" + strings.Repeat("a", 24),
		"head_sha":       mtHead,
		"base_sha":       mtBase,
		"pull_request":   M{"number": 3},
		"decision":       "PASS",
		"evaluated_at":   900,
		"expires_at":     1200,
		"changed_paths":  []any{},
		"chart_digest":   Hash(M{}),
	})
}

func mtConfig() M {
	return M{
		"repository": "o/r", "base_branch": "main", "status_context": "change-guard/release",
		"namespace": "demo", "deployment": "demo", "approvers": []any{"alice"},
		"approved_chart_digest": []any{Hash(M{})},
	}
}

func mtBoundReport(config M) (M, M) {
	binding, err := daemonCurrentPolicyBinding(config)
	if err != nil {
		panic(err)
	}
	report := mtReport()
	report["guard_version"] = binding["guard_version"]
	report["rule_version"] = binding["rule_version"]
	report["policy_binding"] = binding
	report["policy_digest"] = binding["policy_digest"]
	return mtSign(report), binding
}

func mtRefused(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s was accepted", label)
	}
	var refused *MergeRefused
	if !errors.As(err, &refused) {
		t.Fatalf("%s failed with wrong error type %T: %v", label, err, err)
	}
}

func mtSnapshot(entries map[string]TreeEntry) TreeSnapshot {
	return TreeSnapshot{Entries: entries}
}

func mtCheck(id int, name, app, status, conclusion, head string) M {
	return M{
		"id": id, "name": name, "app": M{"slug": app},
		"status": status, "conclusion": conclusion, "head_sha": head,
	}
}

type mtCommitAPI struct {
	commits map[string]M
	err     error
}

type mtCommitAPIWithPath struct {
	mtCommitAPI
}

func (f *mtCommitAPIWithPath) API(_ string, path string, _ any) (any, error) {
	if f.err != nil {
		return nil, f.err
	}
	sha := path
	if index := strings.LastIndex(path, "/"); index >= 0 {
		sha = path[index+1:]
	}
	return f.commits[sha], nil
}

type mtTreeFetcher struct {
	snapshots map[string]TreeSnapshot
	err       error
	calls     []string
}

func (f *mtTreeFetcher) FetchTreeSnapshot(sha string, includeArgo bool) (TreeSnapshot, error) {
	f.calls = append(f.calls, sha)
	if f.err != nil {
		return TreeSnapshot{}, f.err
	}
	return f.snapshots[sha], nil
}

func TestMergeReportValidationHeadBaseDecisionTTLAndTamper(t *testing.T) {
	base := mtBase
	t.Run("current report is valid", func(t *testing.T) {
		if err := mergeValidateReport(mtReport(), mtPR(), base, 1000, 20, nil); err != nil {
			t.Fatalf("valid report refused: %v", err)
		}
	})
	t.Run("head update invalidates", func(t *testing.T) {
		pr := mtPR()
		pr.HeadSHA = strings.Repeat("d", 40)
		mtRefused(t, "head update", mergeValidateReport(mtReport(), pr, base, 1000, 20, nil))
	})
	t.Run("base update invalidates", func(t *testing.T) {
		mtRefused(t, "base update", mergeValidateReport(mtReport(), mtPR(), strings.Repeat("d", 40), 1000, 20, nil))
	})
	t.Run("closed draft and wrong PR are refused", func(t *testing.T) {
		closed := mtPR()
		closed.State = "closed"
		mtRefused(t, "closed PR", mergeValidateReport(mtReport(), closed, base, 1000, 20, nil))
		draft := mtPR()
		draft.Draft = true
		mtRefused(t, "draft PR", mergeValidateReport(mtReport(), draft, base, 1000, 20, nil))
		wrong := mtPR()
		wrong.Number = 99
		mtRefused(t, "wrong PR", mergeValidateReport(mtReport(), wrong, base, 1000, 20, nil))
	})
	t.Run("block and error are refused", func(t *testing.T) {
		for _, decision := range []string{"BLOCK", "ERROR"} {
			report := mtReport()
			report["decision"] = decision
			report = mtSign(report)
			mtRefused(t, decision, mergeValidateReport(report, mtPR(), base, 1000, 20, nil))
		}
	})
	t.Run("expiry requires remaining validity for the push", func(t *testing.T) {
		for _, now := range []int64{1200, 1201, 1190} {
			mtRefused(t, "expired/nearly expired report", mergeValidateReport(mtReport(), mtPR(), base, now, 20, nil))
		}
		if err := mergeValidateReport(mtReport(), mtPR(), base, 1180, 20, nil); err != nil {
			t.Fatalf("report with exactly the required validity was refused: %v", err)
		}
	})
	t.Run("future evaluation time is refused", func(t *testing.T) {
		report := mtReport()
		report["evaluated_at"] = 1100
		report = mtSign(report)
		mtRefused(t, "future evaluation", mergeValidateReport(report, mtPR(), base, 1000, 20, nil))
	})
	t.Run("tampering with a signed report is refused", func(t *testing.T) {
		report := mtReport()
		report["expires_at"] = 5000
		mtRefused(t, "tampered expires_at", mergeValidateReport(report, mtPR(), base, 1000, 20, nil))
	})
	t.Run("missing report and timestamps fail closed", func(t *testing.T) {
		mtRefused(t, "nil report", mergeValidateReport(nil, mtPR(), base, 1000, 20, nil))
		report := mtReport()
		delete(report, "expires_at")
		report = mtSign(report)
		mtRefused(t, "missing expiry", mergeValidateReport(report, mtPR(), base, 1000, 20, nil))
	})
}

func TestMergePolicyBindingRejectsVersionRuleAndPolicyGeneration(t *testing.T) {
	config := mtConfig()
	report, binding := mtBoundReport(config)
	if err := mergeValidateReport(report, mtPR(), mtBase, 1000, 20, binding); err != nil {
		t.Fatalf("bound current report refused: %v", err)
	}
	unbound := mtReport()
	mtRefused(t, "unbound report", mergeValidatePolicyBinding(unbound, binding))

	for _, field := range []string{"guard_version", "rule_version", "policy_digest"} {
		expected := Clone(binding)
		expected[field] = "different-generation"
		mtRefused(t, field+" mismatch", mergeValidatePolicyBinding(report, expected))
	}
	extra := Clone(binding)
	extra["unexpected"] = true
	mtRefused(t, "policy binding mismatch", mergeValidatePolicyBinding(report, extra))

	schemaMismatch := Clone(report)
	schemaMismatch["schema_version"] = daemonSchemaVersion + 1
	mtRefused(t, "schema generation mismatch", mergeValidatePolicyBinding(schemaMismatch, binding))

	changedConfig := mtConfig()
	changedConfig["max_error_ratio"] = 0.01
	changedBinding, err := daemonCurrentPolicyBinding(changedConfig)
	if err != nil {
		t.Fatal(err)
	}
	mtRefused(t, "changed policy config", mergeValidatePolicyBinding(report, changedBinding))
	mtRefused(t, "changed policy at merge report validation", mergeValidateReport(report, mtPR(), mtBase, 1000, 20, changedBinding))
}

func TestMergeCIUsesLatestGitHubActionsRunBoundToHead(t *testing.T) {
	name := mergeDefaultRequiredCI
	t.Run("successful latest run is accepted", func(t *testing.T) {
		payload := M{"check_runs": []any{
			mtCheck(1, name, "github-actions", "completed", "success", mtHead),
		}}
		if err := mergeValidateCI(payload, name, mtHead); err != nil {
			t.Fatalf("valid CI refused: %v", err)
		}
	})
	t.Run("newer failure cannot be hidden by an older success", func(t *testing.T) {
		payload := M{"check_runs": []any{
			mtCheck(1, name, "github-actions", "completed", "success", mtHead),
			mtCheck(2, name, "github-actions", "completed", "failure", mtHead),
		}}
		mtRefused(t, "newer CI failure", mergeValidateCI(payload, name, mtHead))
	})
	t.Run("newer success wins regardless of payload order", func(t *testing.T) {
		payload := M{"check_runs": []any{
			mtCheck(2, name, "github-actions", "completed", "success", mtHead),
			mtCheck(1, name, "github-actions", "completed", "failure", mtHead),
		}}
		if err := mergeValidateCI(payload, name, mtHead); err != nil {
			t.Fatalf("latest successful check refused: %v", err)
		}
	})
	t.Run("missing forged pending or wrong head runs are refused", func(t *testing.T) {
		cases := []struct {
			name    string
			payload M
		}{
			{"empty", M{"check_runs": []any{}}},
			{"wrong app", M{"check_runs": []any{mtCheck(1, name, "not-github-actions", "completed", "success", mtHead)}}},
			{"pending", M{"check_runs": []any{mtCheck(1, name, "github-actions", "in_progress", "", mtHead)}}},
			{"wrong head", M{"check_runs": []any{mtCheck(1, name, "github-actions", "completed", "success", mtSynthetic)}}},
			{"missing head", M{"check_runs": []any{mtCheck(1, name, "github-actions", "completed", "success", "")}}},
			{"wrong name", M{"check_runs": []any{mtCheck(1, "other", "github-actions", "completed", "success", mtHead)}}},
		}
		for _, test := range cases {
			mtRefused(t, test.name+" CI", mergeValidateCI(test.payload, name, mtHead))
		}
		mtRefused(t, "nil CI payload", mergeValidateCI(nil, name, mtHead))
		mtRefused(t, "invalid check_runs type", mergeValidateCI(M{"check_runs": "not-a-list"}, name, mtHead))
	})
}

func TestMergeHeadCILookupIsBoundToHeadSHAAndRejectsIncomplete(t *testing.T) {
	oldBaseURL, oldClient := mergeAPIBaseURL, mergeHTTPClient
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("per_page") != "100" {
			t.Errorf("unexpected check-run page size: %s", request.URL.RawQuery)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/o/r/commits/" + mtHead + "/check-runs":
			_, _ = fmt.Fprintf(writer, `{"total_count":1,"check_runs":[{"id":1,"name":%q,"app":{"slug":"github-actions"},"status":"completed","conclusion":"success","head_sha":%q}]}`, mergeDefaultRequiredCI, mtHead)
		case "/repos/o/r/commits/" + mtSynthetic + "/check-runs":
			_, _ = fmt.Fprintf(writer, `{"total_count":1,"check_runs":[{"id":1,"name":%q,"app":{"slug":"github-actions"},"status":"completed","conclusion":"success","head_sha":%q}]}`, mergeDefaultRequiredCI, mtHead)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	mergeAPIBaseURL = server.URL
	mergeHTTPClient = server.Client()
	t.Cleanup(func() {
		mergeAPIBaseURL = oldBaseURL
		mergeHTTPClient = oldClient
	})

	if _, err := mergeValidateHeadCI("o/r", mtHead, mergeDefaultRequiredCI); err != nil {
		t.Fatalf("head-bound CI lookup failed: %v", err)
	}
	// A payload that claims a different head is not replayable even from the
	// head endpoint.
	mtRefused(t, "CI replay for another head", func() error {
		_, err := mergeValidateHeadCI("o/r", mtSynthetic, mergeDefaultRequiredCI)
		return err
	}())

	mergeHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		recorder.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(recorder, `{"total_count":2,"check_runs":[{"id":1,"name":%q,"app":{"slug":"github-actions"},"status":"completed","conclusion":"success","head_sha":%q}]}`, mergeDefaultRequiredCI, mtHead)
		return recorder.Result(), nil
	})}
	mtRefused(t, "incomplete CI page", func() error {
		_, err := mergeValidateHeadCI("o/r", mtHead, mergeDefaultRequiredCI)
		return err
	}())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestMergeHeadCILookupAuthenticatesAndFailsClosed(t *testing.T) {
	oldBaseURL, oldClient := mergeAPIBaseURL, mergeHTTPClient
	t.Cleanup(func() {
		mergeAPIBaseURL = oldBaseURL
		mergeHTTPClient = oldClient
	})

	t.Run("bearer token is sent on the head check-run request", func(t *testing.T) {
		var authorization string
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			authorization = request.Header.Get("Authorization")
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"total_count":1,"check_runs":[{"id":1,"name":%q,"app":{"slug":"github-actions"},"status":"completed","conclusion":"success","head_sha":%q}]}`, mergeDefaultRequiredCI, mtHead)
		}))
		t.Cleanup(server.Close)
		mergeAPIBaseURL = server.URL
		mergeHTTPClient = server.Client()

		if _, err := mergeValidateHeadCI("o/r", mtHead, mergeDefaultRequiredCI, mtCIToken); err != nil {
			t.Fatalf("authenticated CI lookup failed: %v", err)
		}
		if authorization != "Bearer "+mtCIToken {
			t.Fatalf("CI lookup did not send the expected bearer credential")
		}
	})

	t.Run("403 stays fail closed and errors do not leak the token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if got := request.Header.Get("Authorization"); got != "Bearer "+mtCIToken {
				t.Errorf("forbidden request missed the bearer credential")
			}
			writer.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(writer, "denied for %s", mtCIToken)
		}))
		t.Cleanup(server.Close)
		mergeAPIBaseURL = server.URL
		mergeHTTPClient = server.Client()

		err := func() error {
			_, err := mergeValidateHeadCI("o/r", mtHead, mergeDefaultRequiredCI, mtCIToken)
			return err
		}()
		mtRefused(t, "403 CI lookup", err)
		if strings.Contains(err.Error(), mtCIToken) {
			t.Fatalf("CI lookup error leaked the bearer credential")
		}
	})
}

func TestMergeHeadCILookupRefusesRedirectWithoutForwardingToken(t *testing.T) {
	oldBaseURL, oldClient := mergeAPIBaseURL, mergeHTTPClient
	t.Cleanup(func() {
		mergeAPIBaseURL = oldBaseURL
		mergeHTTPClient = oldClient
	})

	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetHits++
		if request.Header.Get("Authorization") != "" {
			t.Error("redirect target received an Authorization header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"total_count":1,"check_runs":[]}`)
	}))
	t.Cleanup(target.Close)

	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer "+mtCIToken {
			t.Errorf("redirecting CI request missed the bearer credential")
		}
		http.Redirect(writer, request, target.URL+"/stolen", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	mergeAPIBaseURL = redirect.URL
	// Deliberately use a client with its default redirect policy. Production
	// CI requests must still refuse redirects and must never forward the token.
	mergeHTTPClient = redirect.Client()

	err := func() error {
		_, err := mergeValidateHeadCI("o/r", mtHead, mergeDefaultRequiredCI, mtCIToken)
		return err
	}()
	mtRefused(t, "redirected CI lookup", err)
	if targetHits != 0 {
		t.Fatalf("CI lookup followed a redirect %d time(s)", targetHits)
	}
	if strings.Contains(err.Error(), mtCIToken) {
		t.Fatalf("redirect refusal leaked the bearer credential")
	}
}

func TestMergeResolveEvaluationIDUsesCurrentRecordedReport(t *testing.T) {
	recorded := "ev-" + strings.Repeat("a", 24)
	oldID := "ev-" + strings.Repeat("b", 24)
	index := func(id any) M {
		return M{"prs": M{"3": M{"evaluation_id": id}}}
	}

	if got, err := mergeResolveEvaluationID(index(recorded), 3, ""); err != nil || got != recorded {
		t.Fatalf("omitted id did not select the recorded report: %q %v", got, err)
	}
	if got, err := mergeResolveEvaluationID(index(recorded), 3, recorded); err != nil || got != recorded {
		t.Fatalf("matching explicit id was refused: %q %v", got, err)
	}

	mtRefused(t, "explicit old evaluation id", func() error {
		_, err := mergeResolveEvaluationID(index(recorded), 3, oldID)
		return err
	}())
	mtRefused(t, "empty recorded evaluation id", func() error {
		_, err := mergeResolveEvaluationID(index(nil), 3, "")
		return err
	}())
	if got, err := mergeResolveEvaluationID(index(nil), 3, recorded); err == nil || got != "" {
		t.Fatalf("missing recorded report allowed an explicit unindexed id: %q %v", got, err)
	}
	for _, invalid := range []string{"../bad", "ev-not-hex", "", "ev-" + strings.Repeat("a", 15)} {
		mtRefused(t, "invalid recorded evaluation id", func() error {
			_, err := mergeResolveEvaluationID(index(invalid), 3, "")
			return err
		}())
	}
	mtRefused(t, "path traversal explicit evaluation id", func() error {
		_, err := mergeResolveEvaluationID(index(recorded), 3, "../bad")
		return err
	}())
	mtRefused(t, "missing PR record", func() error {
		_, err := mergeResolveEvaluationID(index(recorded), 4, "")
		return err
	}())
}

func TestMergeWorkflowSnapshotsAreRefetchedAndMustMatch(t *testing.T) {
	path := ".github/workflows/ci.yml"
	baseEntry := TreeEntry{Path: path, Mode: "100644", Kind: "blob", SHA: strings.Repeat("1", 40)}
	changedEntry := TreeEntry{Path: path, Mode: "100644", Kind: "blob", SHA: strings.Repeat("2", 40)}
	otherPath := "README.md"
	otherEntry := TreeEntry{Path: otherPath, Mode: "100644", Kind: "blob", SHA: strings.Repeat("9", 40)}

	t.Run("identical workflow content is accepted", func(t *testing.T) {
		if _, err := mergeValidateWorkflowSnapshots(
			mtSnapshot(map[string]TreeEntry{path: baseEntry}),
			mtSnapshot(map[string]TreeEntry{path: baseEntry}),
		); err != nil {
			t.Fatalf("identical workflows refused: %v", err)
		}
	})
	t.Run("changed workflow blob is refused", func(t *testing.T) {
		mtRefused(t, "changed workflow blob", func() error {
			_, err := mergeValidateWorkflowSnapshots(
				mtSnapshot(map[string]TreeEntry{path: baseEntry}),
				mtSnapshot(map[string]TreeEntry{path: changedEntry}),
			)
			return err
		}())
	})
	t.Run("added workflow file is refused", func(t *testing.T) {
		added := TreeEntry{Path: ".github/workflows/evil.yml", Mode: "100644", Kind: "blob", SHA: strings.Repeat("3", 40)}
		mtRefused(t, "added workflow", func() error {
			_, err := mergeValidateWorkflowSnapshots(
				mtSnapshot(map[string]TreeEntry{path: baseEntry}),
				mtSnapshot(map[string]TreeEntry{path: baseEntry, added.Path: added}),
			)
			return err
		}())
	})
	t.Run("non workflow differences do not matter", func(t *testing.T) {
		if _, err := mergeValidateWorkflowSnapshots(
			mtSnapshot(map[string]TreeEntry{path: baseEntry, otherPath: otherEntry}),
			mtSnapshot(map[string]TreeEntry{path: baseEntry, otherPath: TreeEntry{Path: otherPath, Mode: "100644", Kind: "blob", SHA: strings.Repeat("8", 40)}}),
		); err != nil {
			t.Fatalf("non-workflow difference refused: %v", err)
		}
	})
	t.Run("independent refetch refuses a forged workflow pass", func(t *testing.T) {
		fetcher := &mtTreeFetcher{snapshots: map[string]TreeSnapshot{
			mtBase: mtSnapshot(map[string]TreeEntry{path: baseEntry}),
			mtHead: mtSnapshot(map[string]TreeEntry{path: changedEntry}),
		}}
		mtRefused(t, "refetched workflow mismatch", func() error {
			_, _, err := mergeVerifyBaseHeadWorkflows(fetcher, mtBase, mtHead)
			return err
		}())
		if len(fetcher.calls) != 2 {
			t.Fatalf("expected two independent tree fetches, got %v", fetcher.calls)
		}
	})
	t.Run("tree fetch errors fail closed", func(t *testing.T) {
		fetcher := &mtTreeFetcher{err: errors.New("github unavailable")}
		mtRefused(t, "tree fetch error", func() error {
			_, _, err := mergeVerifyBaseHeadWorkflows(fetcher, mtBase, mtHead)
			return err
		}())
	})
}

func TestMergeChartPinIsReverifiedFromHeadBlobs(t *testing.T) {
	files := map[string][]byte{
		"charts/demo/Chart.yaml":                []byte("apiVersion: v2\n"),
		"charts/demo/templates/deployment.yaml": []byte("kind: Deployment\n"),
		"gitops/demo/values.yaml":               []byte("replicas: 1\n"),
	}
	digest, err := ChartDigestFromFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	config := mtConfig()
	config["approved_chart_digest"] = []any{digest}
	report := mtReport()
	report["chart_digest"] = digest
	report = mtSign(report)
	snapshot := TreeSnapshot{RendererFiles: files}
	if actual, err := mergeValidateChartPin(config, report, snapshot); err != nil || actual != digest {
		t.Fatalf("valid chart pin refused: %q %v", actual, err)
	}

	badApproved := M{}
	for key, value := range config {
		badApproved[key] = value
	}
	badApproved["approved_chart_digest"] = []any{strings.Repeat("0", 64)}
	mtRefused(t, "unapproved digest", func() error {
		_, err := mergeValidateChartPin(badApproved, report, snapshot)
		return err
	}())

	badReport := mtReport()
	badReport["chart_digest"] = strings.Repeat("0", 64)
	badReport = mtSign(badReport)
	mtRefused(t, "report/head chart mismatch", func() error {
		_, err := mergeValidateChartPin(config, badReport, snapshot)
		return err
	}())

	missing := M{}
	for key, value := range config {
		missing[key] = value
	}
	missing["approved_chart_digest"] = []any{}
	mtRefused(t, "missing approved pin", func() error {
		_, err := mergeValidateChartPin(missing, report, snapshot)
		return err
	}())

	invalid := M{}
	for key, value := range config {
		invalid[key] = value
	}
	invalid["approved_chart_digest"] = []any{"not-a-digest"}
	mtRefused(t, "invalid approved pin", func() error {
		_, err := mergeValidateChartPin(invalid, report, snapshot)
		return err
	}())

	mtRefused(t, "missing head chart files", func() error {
		_, err := mergeValidateChartPin(config, report, TreeSnapshot{RendererFiles: nil})
		return err
	}())
}

func TestMergeSyntheticTreeMustEqualEvaluatedHead(t *testing.T) {
	headCommit := M{"sha": mtHead, "tree": M{"sha": mtTree}, "parents": []any{M{"sha": mtBase}}}
	goodSynthetic := M{"sha": mtSynthetic, "tree": M{"sha": mtTree}, "parents": []any{M{"sha": mtBase}, M{"sha": mtHead}}}
	goodAPI := &mtCommitAPIWithPath{mtCommitAPI: mtCommitAPI{commits: map[string]M{
		mtSynthetic: goodSynthetic,
		mtHead:      headCommit,
	}}}
	result, err := mergeValidateSyntheticMerge(goodAPI, "o/r", M{"merge_commit_sha": mtSynthetic}, mtBase, mtHead)
	if err != nil {
		t.Fatalf("valid synthetic merge refused: %v", err)
	}
	if Str(result["synthetic_sha"]) != mtSynthetic || Str(result["head_tree_sha"]) != mtTree {
		t.Fatalf("unexpected synthetic result: %#v", result)
	}

	badTree := M{"sha": mtSynthetic, "tree": M{"sha": strings.Repeat("2", 40)}, "parents": []any{M{"sha": mtBase}, M{"sha": mtHead}}}
	badTreeAPI := &mtCommitAPIWithPath{mtCommitAPI: mtCommitAPI{commits: map[string]M{
		mtSynthetic: badTree,
		mtHead:      headCommit,
	}}}
	mtRefused(t, "synthetic tree mismatch", func() error {
		_, err := mergeValidateSyntheticMerge(badTreeAPI, "o/r", M{"merge_commit_sha": mtSynthetic}, mtBase, mtHead)
		return err
	}())

	wrongParents := M{"sha": mtSynthetic, "tree": M{"sha": mtTree}, "parents": []any{M{"sha": mtHead}, M{"sha": mtBase}}}
	wrongParentsAPI := &mtCommitAPIWithPath{mtCommitAPI: mtCommitAPI{commits: map[string]M{
		mtSynthetic: wrongParents,
		mtHead:      headCommit,
	}}}
	mtRefused(t, "synthetic parent order", func() error {
		_, err := mergeValidateSyntheticMerge(wrongParentsAPI, "o/r", M{"merge_commit_sha": mtSynthetic}, mtBase, mtHead)
		return err
	}())

	for _, mergeSHA := range []string{"", "not-a-sha"} {
		mtRefused(t, "invalid synthetic sha", func() error {
			_, err := mergeValidateSyntheticMerge(goodAPI, "o/r", M{"merge_commit_sha": mergeSHA}, mtBase, mtHead)
			return err
		}())
	}
	failingAPI := &mtCommitAPIWithPath{mtCommitAPI: mtCommitAPI{err: errors.New("github unavailable")}}
	mtRefused(t, "synthetic commit lookup error", func() error {
		_, err := mergeValidateSyntheticMerge(failingAPI, "o/r", M{"merge_commit_sha": mtSynthetic}, mtBase, mtHead)
		return err
	}())
}

func TestMergeFastForwardPushUsesEvaluatedHeadAndExactLease(t *testing.T) {
	argv := mergeFastForwardPushArgv("o/r", mtBase, mtHead)
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--force-with-lease=refs/heads/main:"+mtBase) {
		t.Fatalf("exact base lease missing: %v", argv)
	}
	if argv[len(argv)-1] != mtHead+":refs/heads/main" {
		t.Fatalf("push does not target evaluated head: %v", argv)
	}
	if strings.Contains(joined, "refs/heads/main:"+mtHead) {
		t.Fatalf("lease must be the evaluated base, not the head: %v", argv)
	}

	oldRunner := mergeGitRunner
	t.Cleanup(func() { mergeGitRunner = oldRunner })
	var gotArgv []string
	var gotTimeout time.Duration
	mergeGitRunner = func(callArgv []string, _ string, _ M, timeout time.Duration) (mergeGitResult, error) {
		gotArgv = append([]string(nil), callArgv...)
		gotTimeout = timeout
		return mergeGitResult{Code: 0}, nil
	}
	returned, err := mergePushFastForward(t.TempDir(), M{}, "o/r", mtBase, mtHead)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if strings.Join(returned, "\x00") != strings.Join(argv, "\x00") || strings.Join(gotArgv, "\x00") != strings.Join(argv, "\x00") {
		t.Fatalf("unexpected push argv: returned=%v got=%v", returned, gotArgv)
	}
	if gotTimeout != 12*time.Second {
		t.Fatalf("push timeout changed: %v", gotTimeout)
	}
}

func TestMergeRecordPointsAtHeadAndUsesPlainRevert(t *testing.T) {
	report := M{"evaluation_id": "ev-" + strings.Repeat("d", 24), "decision": "PASS", "expires_at": 1200}
	record := mergeBuildRecord(3, mtHead, mtBase,
		M{"synthetic_sha": mtSynthetic, "synthetic_tree_sha": mtTree},
		M{"head_tree_sha": mtTree, "base_ancestor": true}, report, 1000)
	if Str(record["strategy"]) != "fast-forward" || Str(record["merge_sha"]) != mtHead ||
		Str(record["evaluated_head"]) != mtHead || Str(record["synthetic_merge_sha"]) != mtSynthetic {
		t.Fatalf("unexpected merge record: %#v", record)
	}
	if Bool(record["github_merge_api_used"]) {
		t.Fatal("merge record claims the GitHub merge API was used")
	}
	rollback := asM(record["rollback"])
	if Str(rollback["commit"]) != mtHead || rollback["mainline"] != nil {
		t.Fatalf("unexpected rollback: %#v", rollback)
	}
	command := Str(rollback["command"])
	if !strings.Contains(command, mtHead) || strings.Contains(command, " -m") || strings.Contains(command, "--mainline") {
		t.Fatalf("rollback is not a plain revert of head: %q", command)
	}
}

func TestMergeLocalFastForwardVerifiesTreeAndAncestry(t *testing.T) {
	oldRunner := mergeGitRunner
	t.Cleanup(func() { mergeGitRunner = oldRunner })

	run := func(t *testing.T, treeSHA string, ancestorCode int, shallow string, expectedTree string) (M, error) {
		t.Helper()
		mergeGitRunner = func(argv []string, _ string, _ M, _ time.Duration) (mergeGitResult, error) {
			if len(argv) == 0 {
				return mergeGitResult{Code: 1}, nil
			}
			switch argv[0] {
			case "fetch":
				return mergeGitResult{Code: 0}, nil
			case "rev-parse":
				switch argv[1] {
				case mtHead + "^{commit}":
					return mergeGitResult{Stdout: mtHead, Code: 0}, nil
				case mtHead + "^{tree}":
					return mergeGitResult{Stdout: treeSHA, Code: 0}, nil
				case mtBase + "^{commit}":
					return mergeGitResult{Stdout: mtBase, Code: 0}, nil
				case "--is-shallow-repository":
					return mergeGitResult{Stdout: shallow, Code: 0}, nil
				}
			case "merge-base":
				return mergeGitResult{Code: ancestorCode}, nil
			}
			return mergeGitResult{Code: 1}, nil
		}
		return mergeVerifyLocalFastForward(t.TempDir(), M{}, "o/r", mtBase, mtHead, expectedTree)
	}

	t.Run("matching tree and ancestor accepted", func(t *testing.T) {
		local, err := run(t, mtTree, 0, "false", mtTree)
		if err != nil {
			t.Fatalf("valid local fast-forward refused: %v", err)
		}
		if Str(local["head_tree_sha"]) != mtTree || local["base_ancestor"] != true {
			t.Fatalf("unexpected local proof: %#v", local)
		}
	})
	t.Run("local tree mismatch is refused", func(t *testing.T) {
		mtRefused(t, "local tree mismatch", func() error {
			_, err := run(t, strings.Repeat("9", 40), 0, "false", mtTree)
			return err
		}())
	})
	t.Run("non ancestor non shallow head is refused", func(t *testing.T) {
		mtRefused(t, "non ancestor", func() error {
			_, err := run(t, mtTree, 1, "false", mtTree)
			return err
		}())
	})
	t.Run("shallow graph cannot disprove ancestor but is marked unknown", func(t *testing.T) {
		local, err := run(t, mtTree, 1, "true", mtTree)
		if err != nil {
			t.Fatalf("shallow exact head refused: %v", err)
		}
		if local["base_ancestor"] != nil {
			t.Fatalf("shallow ancestry should be unknown, got %#v", local["base_ancestor"])
		}
	})
	t.Run("invalid fetch depth fails before git mutation", func(t *testing.T) {
		config := M{"merge_fetch_depth": 0}
		mtRefused(t, "invalid fetch depth", func() error {
			_, err := mergeVerifyLocalFastForward(t.TempDir(), config, "o/r", mtBase, mtHead, mtTree)
			return err
		}())
	})
}

func TestMergeReleaseRequiresTrustedMergeConfiguration(t *testing.T) {
	config := M{
		"repository": "o/r", "base_branch": "main",
		"state_dir": t.TempDir(), "evidence_ttl_seconds": 300,
		"approved_chart_digest": []any{Hash(M{})},
	}
	mtRefused(t, "missing deploy key", func() error {
		_, err := MergeRelease(config, 3, "ev-"+strings.Repeat("a", 24))
		return err
	}())
	mtRefused(t, "non-main base", func() error {
		_, err := MergeRelease(M{"base_branch": "release"}, 3, "ev-"+strings.Repeat("a", 24))
		return err
	}())
	mtRefused(t, "invalid PR number", func() error {
		_, err := MergeRelease(config, 0, "ev-"+strings.Repeat("a", 24))
		return err
	}())
	mtRefused(t, "invalid evaluation id", func() error {
		_, err := MergeRelease(config, 3, "../bad")
		return err
	}())
}
