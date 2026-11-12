package guard

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

func migrationRestore(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x["__migration_float__"].(string); ok {
			switch s {
			case "nan":
				return math.NaN()
			case "inf":
				return math.Inf(1)
			case "-inf":
				return math.Inf(-1)
			}
		}
		for k, v := range x {
			x[k] = migrationRestore(v)
		}
	case []any:
		for i, v := range x {
			x[i] = migrationRestore(v)
		}
	}
	return v
}

func migrationOptionalMap(v any) M {
	if v == nil {
		return nil
	}
	return Obj(v)
}

func TestPythonMigrationDecisionOracle(t *testing.T) {
	b, e := os.ReadFile("../../testdata/python-oracle.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture M
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	cases := Arr(fixture["cases"])
	if len(cases) < 100 {
		t.Fatal("missing migration oracle cases")
	}
	for _, raw := range cases {
		c := Obj(raw)
		t.Run(S(c, "name"), func(t *testing.T) {
			in := Obj(migrationRestore(c["input"]))
			resources := func(v any) []M {
				out := []M{}
				for _, r := range Arr(v) {
					out = append(out, Obj(r))
				}
				return out
			}
			got := Evaluate(resources(in["old"]), resources(in["new"]), Obj(in["evidence"]), Obj(in["config"]), Obj(in["context"]), migrationOptionalMap(in["ai_result"]))
			if S(got, "decision") != S(c, "expected_decision") {
				t.Errorf("decision=%s expected=%s; Python rules=%v; Go findings=%v", S(got, "decision"), S(c, "expected_decision"), c["expected_rules"], got["findings"])
			}
			if _, e := CanonicalJSON(got); e != nil {
				t.Errorf("report is not finite JSON: %v", e)
			}
		})
	}
}
