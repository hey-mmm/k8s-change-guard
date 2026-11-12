package guard

// Additional assertions over the frozen Python oracle. The expectations file is
// never modified: these tests only verify that all recorded rule ids and the
// audit schema survive the Go port, not just the final decision.

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func engTestStringSet(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func TestPythonOracleRulesAndAuditSchema(t *testing.T) {
	b, err := os.ReadFile("../../testdata/python-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture M
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := Arr(fixture["cases"])
	if len(cases) < 100 {
		t.Fatal("missing migration oracle cases")
	}
	for _, raw := range cases {
		c := Obj(raw)
		name := S(c, "name")
		t.Run(name, func(t *testing.T) {
			input := Obj(migrationRestore(c["input"]))
			resources := func(v any) []M {
				out := []M{}
				for _, resource := range Arr(v) {
					out = append(out, Obj(resource))
				}
				return out
			}
			result := Evaluate(
				resources(input["old"]),
				resources(input["new"]),
				Obj(input["evidence"]),
				Obj(input["config"]),
				Obj(input["context"]),
				migrationOptionalMap(input["ai_result"]),
			)
			if got, want := S(result, "decision"), S(c, "expected_decision"); got != want {
				t.Fatalf("decision=%s want %s; rules=%v", got, want, engTestRules(result))
			}
			wantRules := []string{}
			for _, rule := range Arr(c["expected_rules"]) {
				wantRules = append(wantRules, Str(rule))
			}
			gotRules := engTestRules(result)
			wantSet := engTestStringSet(wantRules)
			gotSet := engTestStringSet(gotRules)
			if len(gotSet) != len(wantSet) {
				t.Fatalf("rules=%v want %v", gotSet, wantSet)
			}
			for i := range wantSet {
				if gotSet[i] != wantSet[i] {
					t.Fatalf("rules=%v want %v", gotSet, wantSet)
				}
			}
			findings := Arr(result["findings"])
			audit := Obj(result["audit"])
			checks := Arr(audit["checks"])
			if len(checks) != len(findings) {
				t.Fatalf("audit.checks=%d findings=%d", len(checks), len(findings))
			}
			severityRank := map[string]bool{"BLOCK": true, "ERROR": true, "REVIEW": true}
			previousRank := 99
			for index, rawFinding := range findings {
				finding := Obj(rawFinding)
				check := Obj(checks[index])
				for _, key := range []string{"rule_id", "severity", "field", "message"} {
					if S(finding, key) == "" {
						t.Fatalf("finding[%d] missing %s: %v", index, key, finding)
					}
					if S(check, key) != S(finding, key) {
						t.Fatalf("audit.checks[%d].%s=%q finding=%q", index, key, S(check, key), S(finding, key))
					}
				}
				severity := S(finding, "severity")
				if !severityRank[severity] {
					t.Fatalf("invalid severity %q", severity)
				}
				rank := engSeverityRank[severity]
				if rank > previousRank {
					t.Fatalf("findings are not severity-sorted at %d", index)
				}
				previousRank = rank
				if _, ok := finding["evidence"]; !ok {
					t.Fatalf("finding missing evidence map: %v", finding)
				}
			}
			if _, err := CanonicalJSON(result); err != nil {
				t.Fatalf("non-finite report: %v", err)
			}
			if S(result, "audit", "schema_version") != engSchemaVersion {
				t.Fatalf("schema_version=%v", Get(result, "audit", "schema_version"))
			}
		})
	}
}
