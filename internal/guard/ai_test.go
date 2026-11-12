package guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const aiTestTokenEnv = "CG_TEST_DEEPSEEK_TOKEN"

func aiTestKnowledgeDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.Abs(filepath.Join("..", "..", "knowledge"))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func aiTestConfig(t *testing.T, directory string) M {
	t.Helper()
	return M{
		"deepseek_url":             aiDefaultDeepSeekURL,
		"deepseek_model":           "deepseek-chat",
		"deepseek_token_env":       aiTestTokenEnv,
		"deepseek_timeout_seconds": 5,
		"knowledge_dir":            directory,
	}
}

func aiTestModelContent(t *testing.T, summary string, risks, citations []M) string {
	t.Helper()
	raw, err := json.Marshal(M{
		"summary":          summary,
		"additional_risks": aiMapsAny(risks),
		"citations":        aiMapsAny(citations),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func aiTestStubCompletion(t *testing.T, fn func([]M, aiSettings, string) (string, error)) {
	t.Helper()
	previous := aiRequestCompletion
	aiRequestCompletion = fn
	t.Cleanup(func() { aiRequestCompletion = previous })
}

func aiTestCopyKnowledge(t *testing.T) string {
	t.Helper()
	source := aiTestKnowledgeDir(t)
	destination := filepath.Join(t.TempDir(), "knowledge")
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return destination
}

func aiTestFirstCase(t *testing.T, report M) aiCase {
	t.Helper()
	cases, err := aiRetrieveCases(report, aiTestKnowledgeDir(t), true, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("expected at least one retrieved case")
	}
	return cases[0]
}

func TestVerifyKnowledgeProvenance(t *testing.T) {
	knowledge, err := VerifyKnowledge(aiTestKnowledgeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	sources := Obj(knowledge["sources"])
	if len(sources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(sources))
	}
	cases := Arr(knowledge["cases"])
	if len(cases) < 10 {
		t.Fatalf("expected at least 10 cases, got %d", len(cases))
	}
	for id, raw := range sources {
		source := Obj(raw)
		if !aiHex64RE.MatchString(Str(source["sha256"])) {
			t.Fatalf("source %s has invalid hash", id)
		}
		if !aiCommitRE.MatchString(Str(source["source_commit"])) {
			t.Fatalf("source %s has invalid commit", id)
		}
		if !strings.HasPrefix(Str(source["path"]), "docs/") {
			t.Fatalf("source %s path is not from docs/", id)
		}
	}
	root := Str(knowledge["root"])
	for _, raw := range cases {
		item := Obj(raw)
		source := Obj(item["source"])
		snapshot := filepath.Join(root, filepath.FromSlash(Str(source["snapshot"])))
		content, err := os.ReadFile(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(aiSplitLines(string(content)), "\n"), Str(item["excerpt"])) {
			t.Fatalf("case %s excerpt is not present in snapshot", Str(item["id"]))
		}
		if Str(item["source_sha256"]) != Str(source["sha256"]) {
			t.Fatalf("case %s source hash mismatch", Str(item["id"]))
		}
		if Num(item["line_end"]) < Num(item["line_start"]) {
			t.Fatalf("case %s has inverted line range", Str(item["id"]))
		}
	}
}

func TestVerifyKnowledgeUsesConfiguredDefaultDirectory(t *testing.T) {
	t.Setenv("CHANGE_GUARD_KNOWLEDGE_DIR", aiTestKnowledgeDir(t))
	knowledge, err := VerifyKnowledge("")
	if err != nil {
		t.Fatal(err)
	}
	if len(Arr(knowledge["cases"])) < 10 {
		t.Fatal("default knowledge directory did not load cases")
	}
}

func TestVerifyKnowledgeRejectsTampering(t *testing.T) {
	t.Run("snapshot", func(t *testing.T) {
		directory := aiTestCopyKnowledge(t)
		path := filepath.Join(directory, "sources", "fault-review.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, []byte("\nTAMPER\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKnowledge(directory); err == nil {
			t.Fatal("tampered snapshot was accepted")
		}
	})
	t.Run("case excerpt", func(t *testing.T) {
		directory := aiTestCopyKnowledge(t)
		path := filepath.Join(directory, "cases", "http500-fault.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var item M
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		item["excerpt"] = Str(item["excerpt"]) + " altered"
		raw, err = json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKnowledge(directory); err == nil {
			t.Fatal("tampered case excerpt was accepted")
		}
	})
}

func TestRetrievalFindsRelevantTrustedCases(t *testing.T) {
	report := M{
		"decision": "REVIEW",
		"findings": []any{
			M{"rule_id": "FAULT_INJECTION", "message": "DEMO_STARTUP_FAIL=true causes CrashLoop startup failure"},
			M{"rule_id": "HIGH_P95_LATENCY", "message": "p95 latency 3000ms"},
		},
	}
	cases, err := aiRetrieveCases(report, aiTestKnowledgeDir(t), true, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("expected retrieval results")
	}
	ids := map[string]bool{}
	for _, item := range cases {
		ids[item.ID] = true
		if !strings.HasPrefix(item.SourcePath, "docs/") {
			t.Fatalf("case %s has untrusted source", item.ID)
		}
		if !aiHex64RE.MatchString(item.SourceSHA256) {
			t.Fatalf("case %s has invalid source hash", item.ID)
		}
	}
	if !ids["startup-failure-release-protection"] && !ids["startup-max-unavailable-protection"] &&
		!ids["latency-3000-fault"] {
		t.Fatalf("retrieval missed relevant cases: %v", ids)
	}
}

func TestRetrievalDeterministicAndBounded(t *testing.T) {
	report := M{"findings": []any{
		M{"rule_id": "CAPACITY_INSUFFICIENT", "message": "surge and worker capacity"},
	}}
	first, err := aiRetrieveCases(report, aiTestKnowledgeDir(t), true, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := aiRetrieveCases(report, aiTestKnowledgeDir(t), true, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) > 3 {
		t.Fatal("retrieval exceeded limit")
	}
	for index := range first {
		if first[index].ID != second[index].ID {
			t.Fatal("retrieval is not deterministic")
		}
	}
	found := false
	for _, item := range first {
		if strings.Contains(strings.ToLower(item.Title), "worker") ||
			strings.Contains(strings.ToLower(item.Title), "capacity") {
			found = true
		}
	}
	if !found {
		t.Fatalf("capacity retrieval missed relevant title: %+v", first)
	}
}

func TestAnalyzeSuccessEnrichesCitations(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{
		"decision": "REVIEW",
		"findings": []any{
			M{"rule_id": "FAULT_INJECTION", "message": "DEMO_ERROR_RATE=1 webhook http500"},
		},
	}
	item := aiTestFirstCase(t, report)
	quote := strings.Split(item.Excerpt, "\n")[0]
	if aiRuneLen(quote) > 80 {
		quote = aiRunePrefix(quote, 80)
	}
	content := aiTestModelContent(t, "The release appears to request deliberate fault injection.",
		[]M{{"title": "Fault injection", "detail": "DEMO_ERROR_RATE is non-zero."}},
		[]M{{"case_id": item.ID, "quote": quote}})
	var capturedSettings aiSettings
	aiTestStubCompletion(t, func(_ []M, settings aiSettings, _ string) (string, error) {
		capturedSettings = settings
		return content, nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
	if Str(result["model"]) != "deepseek-chat" {
		t.Fatalf("unexpected model: %v", result["model"])
	}
	risks := Arr(result["additional_risks"])
	if len(risks) != 1 || Str(Obj(risks[0])["severity"]) != "REVIEW" {
		t.Fatalf("unexpected risks: %v", result["additional_risks"])
	}
	citations := Arr(result["citations"])
	if len(citations) != 1 {
		t.Fatalf("unexpected citations: %v", result["citations"])
	}
	citation := Obj(citations[0])
	if Str(citation["source"]) != item.Source.Path ||
		Str(citation["source_sha256"]) != item.Source.SHA256 ||
		Str(citation["source_commit"]) != item.Source.SourceCommit ||
		!strings.HasPrefix(Str(citation["snapshot"]), "sources/") {
		t.Fatalf("citation provenance was not enriched: %v", citation)
	}
	if capturedSettings.TotalTimeout != 10 {
		t.Fatalf("expected default total timeout 10, got %d", capturedSettings.TotalTimeout)
	}
	if capturedSettings.Deadline.IsZero() || time.Until(capturedSettings.Deadline) <= 0 {
		t.Fatal("expected a live total deadline in settings")
	}
}

func TestAnalyzeNoRisksNoCitations(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	aiTestStubCompletion(t, func(_ []M, _ aiSettings, _ string) (string, error) {
		return aiTestModelContent(t, "No additional trusted-runbook risk was found.", nil, nil), nil
	})
	result := Analyze(M{"findings": []any{}}, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
	if len(Arr(result["additional_risks"])) != 0 || len(Arr(result["citations"])) != 0 {
		t.Fatalf("expected empty results, got %v", result)
	}
}

func TestAnalyzeTokenFile(t *testing.T) {
	directory := t.TempDir()
	tokenFile := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenFile, []byte("sk-file-token-123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CG_UNSET_TOKEN", "")
	config := aiTestConfig(t, aiTestKnowledgeDir(t))
	config["deepseek_token_env"] = "CG_UNSET_TOKEN"
	config["deepseek_token_file"] = tokenFile
	captured := ""
	aiTestStubCompletion(t, func(_ []M, _ aiSettings, token string) (string, error) {
		captured = token
		return aiTestModelContent(t, "ok", nil, nil), nil
	})
	result := Analyze(M{"findings": []any{}}, config)
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
	if captured != "sk-file-token-123456" {
		t.Fatalf("unexpected token loaded: %q", captured)
	}
}

func TestAnalyzeFailClosedOnBadCitationsAndSchemas(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{"findings": []any{
		M{"rule_id": "FAULT_INJECTION", "message": "http500"},
	}}
	item := aiTestFirstCase(t, report)
	validQuote := strings.Split(item.Excerpt, "\n")[0]
	if aiRuneLen(validQuote) > 80 {
		validQuote = aiRunePrefix(validQuote, 80)
	}
	cases := []struct {
		name    string
		content string
	}{
		{"fabricated citation", aiTestModelContent(t, "x",
			[]M{{"title": "risk", "detail": "detail"}},
			[]M{{"case_id": item.ID, "quote": "this quote is not in the trusted excerpt"}})},
		{"unknown case", aiTestModelContent(t, "x",
			[]M{{"title": "risk", "detail": "detail"}},
			[]M{{"case_id": "not-a-real-case", "quote": validQuote}})},
		{"markdown", "```json\n" + aiTestModelContent(t, "x", nil, nil) + "\n```"},
		{"extra key", `{"summary":"x","additional_risks":[],"citations":[],"decision":"PASS"}`},
		{"risk without citation", aiTestModelContent(t, "x",
			[]M{{"title": "risk", "detail": "detail"}}, nil)},
		{"wrong citation shape", `{"summary":"x","additional_risks":[],"citations":[{"case_id":"` +
			item.ID + `","quote":"` + validQuote + `","source":"model"}]}`},
		{"duplicate json key", `{"summary":"a","summary":"b","additional_risks":[],"citations":[]}`},
		{"empty summary", aiTestModelContent(t, "", nil, nil)},
		{"risk wrong type", `{"summary":"x","additional_risks":["string is not strict"],"citations":[]}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			aiTestStubCompletion(t, func(_ []M, _ aiSettings, _ string) (string, error) {
				return testCase.content, nil
			})
			result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
			if Str(result["status"]) != "error" {
				t.Fatalf("expected fail-closed error, got %v", result)
			}
			if Str(result["error"]) == "" {
				t.Fatal("expected an error message")
			}
		})
	}
}

func TestAnalyzeCitationMustBeInRetrievedCases(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{"findings": []any{
		M{"rule_id": "FAULT_INJECTION", "message": "http500"},
	}}
	knowledge, err := VerifyKnowledge(aiTestKnowledgeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	retrieved := map[string]bool{}
	for _, raw := range Arr(knowledge["cases"]) {
		retrieved[Str(Obj(raw)["id"])] = true
	}
	cases, err := aiRetrieveCases(report, aiTestKnowledgeDir(t), true, 4)
	if err != nil {
		t.Fatal(err)
	}
	for key := range retrieved {
		for _, item := range cases {
			if item.ID == key {
				delete(retrieved, key)
			}
		}
	}
	if len(retrieved) == 0 {
		t.Fatal("expected at least one case outside retrieval")
	}
	outsideID := ""
	for key := range retrieved {
		outsideID = key
		break
	}
	var outside M
	for _, raw := range Arr(knowledge["cases"]) {
		if Str(Obj(raw)["id"]) == outsideID {
			outside = Obj(raw)
			break
		}
	}
	if outside == nil {
		t.Fatal("cannot find outside case")
	}
	content := aiTestModelContent(t, "x",
		[]M{{"title": "risk", "detail": "detail"}},
		[]M{{"case_id": outsideID, "quote": aiRunePrefix(Str(outside["excerpt"]), 80)}})
	aiTestStubCompletion(t, func(_ []M, _ aiSettings, _ string) (string, error) {
		return content, nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "error" {
		t.Fatalf("citation outside retrieved cases was accepted: %v", result)
	}
}

func TestAnalyzeConfigAndKnowledgeFailClosed(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{"findings": []any{}}

	invalidURL := aiTestConfig(t, aiTestKnowledgeDir(t))
	invalidURL["deepseek_url"] = "https://evil.example/chat/completions"
	if Str(Analyze(report, invalidURL)["status"]) != "error" {
		t.Fatal("non-allowlisted endpoint was accepted")
	}

	invalidTimeout := aiTestConfig(t, aiTestKnowledgeDir(t))
	invalidTimeout["deepseek_timeout_seconds"] = 0
	if Str(Analyze(report, invalidTimeout)["status"]) != "error" {
		t.Fatal("invalid timeout was accepted")
	}

	invalidTotal := aiTestConfig(t, aiTestKnowledgeDir(t))
	invalidTotal["deepseek_total_timeout_seconds"] = 0
	if Str(Analyze(report, invalidTotal)["status"]) != "error" {
		t.Fatal("invalid total timeout was accepted")
	}

	missing := aiTestConfig(t, aiTestKnowledgeDir(t))
	missing["deepseek_token_env"] = "CG_MISSING_TOKEN"
	missing["deepseek_token_file"] = filepath.Join(t.TempDir(), "missing-token")
	t.Setenv("CG_MISSING_TOKEN", "")
	result := Analyze(report, missing)
	if Str(result["status"]) != "error" {
		t.Fatal("missing token was accepted")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "sk-") {
		t.Fatal("error result leaked a token")
	}

	missingKnowledge := aiTestConfig(t, t.TempDir())
	if Str(Analyze(report, missingKnowledge)["status"]) != "error" {
		t.Fatal("missing knowledge was accepted")
	}
}

func TestSanitizationRemovesSecretsBeforePrompt(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{
		"cluster_token": "SUPERSECRET_TOKEN_VALUE",
		"password":      "SUPERSECRET_PASSWORD",
		"kubeconfig":    "SUPERSECRET_KUBECONFIG",
		"raw":           M{"kubeconfig": "SUPERSECRET_RAW"},
		"env": []any{
			M{"name": "DEMO_ERROR_RATE", "value": "SUPERSECRET_ENV"},
			M{"name": "SAFE", "value": "SUPERSECRET_ENV2"},
		},
		"note":     "Authorization: Bearer SUPERSECRETBEARER12345 and sk-abcdefghijklmnopqrstuvwxyz",
		"findings": []any{M{"rule_id": "FAULT_INJECTION", "message": "http500"}},
	}
	var captured []M
	aiTestStubCompletion(t, func(messages []M, _ aiSettings, _ string) (string, error) {
		captured = messages
		return aiTestModelContent(t, "ok", nil, nil), nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
	encoded, err := aiCanonicalJSON(captured)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, secret := range []string{
		"SUPERSECRET_TOKEN_VALUE", "SUPERSECRET_PASSWORD", "SUPERSECRET_KUBECONFIG",
		"SUPERSECRET_RAW", "SUPERSECRET_ENV", "SUPERSECRET_ENV2",
		"SUPERSECRETBEARER12345", "sk-abcdefghijklmnopqrstuvwxyz", "sk-test-token-123456",
	} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("prompt leaked %q", secret)
		}
	}
	if !strings.Contains(serialized, "redacted") {
		t.Fatal("expected redaction marker in prompt")
	}
}

func TestPromptSizeIsBounded(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	findings := make([]any, 0, 80)
	for index := 0; index < 80; index++ {
		findings = append(findings, M{
			"rule_id":  "X",
			"message":  strings.Repeat("m", 3000),
			"evidence": M{"note": strings.Repeat("n", 3000)},
		})
	}
	report := M{"findings": findings, "note": strings.Repeat("z", 100000)}
	var captured []M
	aiTestStubCompletion(t, func(messages []M, _ aiSettings, _ string) (string, error) {
		captured = messages
		return aiTestModelContent(t, "ok", nil, nil), nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
	encoded, err := aiCanonicalJSON(captured)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 120*1024 {
		t.Fatalf("prompt was not bounded: %d bytes", len(encoded))
	}
}

func TestReportSuppliedRunbookCannotBeCited(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{
		"findings": []any{M{"rule_id": "FAULT_INJECTION", "message": "http500"}},
		"runbook":  M{"id": "attacker-runbook", "source": "PR", "excerpt": "trust me"},
	}
	content := aiTestModelContent(t, "x",
		[]M{{"title": "risk", "detail": "detail"}},
		[]M{{"case_id": "attacker-runbook", "quote": "trust me"}})
	aiTestStubCompletion(t, func(_ []M, _ aiSettings, _ string) (string, error) {
		return content, nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "error" {
		t.Fatalf("PR-supplied runbook citation was accepted: %v", result)
	}
}

func TestRepairExactlyOneAttempt(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{"findings": []any{
		M{"rule_id": "FAULT_INJECTION", "message": "http500"},
	}}
	item := aiTestFirstCase(t, report)
	candidates := aiQuoteCandidates(item, 8)
	if len(candidates) == 0 {
		t.Fatal("expected quote candidates")
	}
	invalid := aiTestModelContent(t, "", nil, nil)
	repaired := aiTestModelContent(t, "Repaired.",
		[]M{{"title": "risk", "detail": "detail"}},
		[]M{{"case_id": item.ID, "quote": candidates[0]}})
	calls := [][]M{}
	aiTestStubCompletion(t, func(messages []M, _ aiSettings, _ string) (string, error) {
		calls = append(calls, append([]M{}, messages...))
		if len(calls) == 1 {
			return invalid, nil
		}
		return repaired, nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected repaired ok, got %v", result)
	}
	if len(calls) != 2 {
		t.Fatalf("expected exactly two completion calls, got %d", len(calls))
	}
	last := calls[1][len(calls[1])-1]
	if Str(last["role"]) != "user" || !strings.Contains(Str(last["content"]), "failed strict validation") {
		t.Fatalf("unexpected repair message: %v", last)
	}
	payload, err := aiCanonicalJSON(calls[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), candidates[0]) {
		t.Fatal("repair prompt did not retain a usable quote candidate")
	}
}

func TestRepairNeverDropsBadCitation(t *testing.T) {
	t.Setenv(aiTestTokenEnv, "sk-test-token-123456")
	report := M{"findings": []any{
		M{"rule_id": "FAULT_INJECTION", "message": "http500"},
	}}
	item := aiTestFirstCase(t, report)
	bad := aiTestModelContent(t, "x",
		[]M{{"title": "risk", "detail": "detail"}},
		[]M{{"case_id": item.ID, "quote": "not present in trusted excerpt"}})
	calls := 0
	aiTestStubCompletion(t, func(_ []M, _ aiSettings, _ string) (string, error) {
		calls++
		return bad, nil
	})
	result := Analyze(report, aiTestConfig(t, aiTestKnowledgeDir(t)))
	if Str(result["status"]) != "error" {
		t.Fatalf("expected fail-closed error, got %v", result)
	}
	if !strings.Contains(Str(result["error"]), "not present") {
		t.Fatalf("unexpected error: %v", result["error"])
	}
	if calls != 2 {
		t.Fatalf("expected exactly one repair retry, got %d calls", calls)
	}
}

func TestStrictJSONRejectsDuplicateKeysAndTrailingData(t *testing.T) {
	for _, payload := range []string{
		`{"a":1,"a":2}`,
		`{"a":1}{"b":2}`,
		`{"a":1} trailing`,
	} {
		if _, err := aiStrictJSON([]byte(payload)); err == nil {
			t.Fatalf("strict parser accepted %q", payload)
		}
	}
	value, err := aiStrictJSON([]byte(`{"outer":{"a":[1,true,null,"x"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(M); !ok {
		t.Fatal("strict parser did not return an object")
	}
}

func TestRequestCompletionBuildsBoundedStrictRequest(t *testing.T) {
	var captured M
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("unexpected method %s", request.Method)
		}
		if request.Header.Get("Authorization") != "Bearer sk-test-token-123456" {
			t.Errorf("unexpected authorization header")
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type %q", request.Header.Get("Content-Type"))
		}
		var payload M
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("invalid request body: %v", err)
		}
		captured = payload
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"ok\",\"additional_risks\":[],\"citations\":[]}"}}]}`))
	}))
	defer server.Close()
	settings := aiSettings{
		URL:          server.URL,
		Model:        "deepseek-chat",
		Timeout:      5,
		TotalTimeout: 10,
		MaxBytes:     4096,
		Deadline:     time.Now().Add(5 * time.Second),
	}
	content, err := aiRequestCompletionImpl([]M{{"role": "user", "content": "payload"}}, settings, "sk-test-token-123456")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, `"summary":"ok"`) {
		t.Fatalf("unexpected content: %q", content)
	}
	if Str(captured["model"]) != "deepseek-chat" || Num(captured["temperature"]) != 0 ||
		Bool(captured["stream"]) || Num(captured["max_tokens"]) != 1200 {
		t.Fatalf("unexpected request body: %v", captured)
	}
	if Str(Obj(captured["response_format"])["type"]) != "json_object" {
		t.Fatalf("response_format was not json_object: %v", captured["response_format"])
	}
}

func TestRequestCompletionRejectsExpiredDeadlineAndOversize(t *testing.T) {
	expired := aiSettings{
		URL:          "https://api.deepseek.com/chat/completions",
		Model:        "deepseek-chat",
		Timeout:      5,
		TotalTimeout: 10,
		MaxBytes:     4096,
		Deadline:     time.Now().Add(-time.Second),
	}
	if _, err := aiRequestCompletionImpl(nil, expired, "sk-test-token-123456"); err == nil ||
		!strings.Contains(err.Error(), "total timeout") {
		t.Fatalf("expired total deadline was not enforced: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte(`{"choices":[]}`))
	}))
	defer server.Close()
	settings := aiSettings{
		URL: server.URL, Model: "deepseek-chat", Timeout: 5, TotalTimeout: 10,
		MaxBytes: 4096, Deadline: time.Now().Add(5 * time.Second),
	}
	if _, err := aiRequestCompletionImpl(nil, settings, "sk-test-token-123456"); err == nil ||
		!strings.Contains(err.Error(), "502") {
		t.Fatalf("HTTP failure was not fail-closed: %v", err)
	}

	oversize := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"choices":"` + strings.Repeat("a", 5000) + `"}`))
	}))
	defer oversize.Close()
	settings.URL = oversize.URL
	if _, err := aiRequestCompletionImpl(nil, settings, "sk-test-token-123456"); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized response was not rejected: %v", err)
	}
}

func TestCompletionContentStrictSchemas(t *testing.T) {
	valid := `{"choices":[{"message":{"content":"{\"summary\":\"x\",\"additional_risks\":[],\"citations\":[]}"}}]}`
	content, err := aiCompletionContent([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, `"summary":"x"`) {
		t.Fatal("unexpected completion content")
	}
	for _, payload := range []string{
		`{"choices":[],"choices":[]}`,
		`{"choices":[]}`,
		`{"choices":[{"message":{"content":"   "}}]}`,
		`{"choices":[{"message":{"content":1}}]}`,
		`not-json`,
	} {
		if _, err := aiCompletionContent([]byte(payload)); err == nil {
			t.Fatalf("completion parser accepted %q", payload)
		}
	}
}

func TestQuoteCandidatesAreExactExcerptSubstrings(t *testing.T) {
	item := aiTestFirstCase(t, M{"findings": []any{
		M{"rule_id": "FAULT_INJECTION", "message": "http500"},
	}})
	candidates := aiQuoteCandidates(item, 8)
	if len(candidates) == 0 {
		t.Fatal("expected quote candidates")
	}
	normalizedExcerpt := aiNormalizeWS(item.Excerpt)
	for _, candidate := range candidates {
		if !strings.Contains(normalizedExcerpt, candidate) {
			t.Fatalf("candidate is not an excerpt substring: %q", candidate)
		}
		if aiRuneLen(candidate) < aiMinCitationChars {
			t.Fatalf("candidate is too short: %q", candidate)
		}
	}
}
