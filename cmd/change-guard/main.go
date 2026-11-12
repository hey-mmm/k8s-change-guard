// Command change-guard is the single static runtime entry point for the
// Kubernetes release guard.  It exposes the evaluation kernel, renderer
// fixture loader, read-only evidence collection, validated AI review,
// knowledge verification, daemon/PR evaluation, guarded merge, post-deploy
// verification, and the fixed root-only token helper.
//
// No Python runtime is required.  The historical Python package remains in the
// repository only as a read-only baseline until the migration is finalized.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hey-mmm/k8s-change-guard/internal/guard"
)

const (
	cgExitPass   = 0
	cgExitReview = 1
	cgExitBlock  = 2
	cgExitError  = 3

	cgPostDeployOK       = 0
	cgPostDeployFailed   = 1
	cgPostDeployError    = 2
	cgPostDeployVerifier = "change-guard-postdeploy"
)

type cgStrings []string

func (values *cgStrings) String() string { return strings.Join(*values, ",") }

func (values *cgStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	os.Exit(cgRun(os.Args[1:]))
}

func cgRun(args []string) int {
	if len(args) == 0 {
		cgUsage()
		return cgExitError
	}
	switch args[0] {
	case "--version", "-version", "version":
		fmt.Printf("change-guard %s (rules %s)\n", guard.Version, guard.RuleVersion)
		return cgExitPass
	case "--help", "-h", "help":
		cgUsage()
		return cgExitPass
	case "evaluate":
		return cgEvaluate(args[1:])
	case "render":
		return cgRender(args[1:])
	case "collect":
		return cgCollect(args[1:])
	case "ai":
		return cgAI(args[1:])
	case "verify-knowledge":
		return cgVerifyKnowledge(args[1:])
	case "daemon":
		return cgDaemon(args[1:])
	case "evaluate-pr":
		return cgEvaluatePR(args[1:])
	case "merge":
		return cgMerge(args[1:])
	case "postdeploy":
		return cgPostDeploy(args[1:])
	case "check-token":
		return cgCheckToken(args[1:])
	case "renew-token":
		return cgRenewToken(args[1:])
	case "credential-check":
		return cgCredentialCheck(args[1:])
	case "scenario", "scenario-matrix":
		return cgScenarioMatrix(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		cgUsage()
		return cgExitError
	}
}

func cgUsage() {
	fmt.Fprint(os.Stderr, `change-guard `+guard.Version+` (rules `+guard.RuleVersion+`)

Usage:
  change-guard evaluate --new FILE [--new FILE...] [--old FILE...]
      [--evidence JSON] [--config YAML] [--context JSON] [--ai-result JSON]
      [--output FILE]
  change-guard render (--tree DIR | --pre-rendered FILE [--pre-rendered FILE...])
      [--config YAML] [--output FILE]
  change-guard collect --config YAML [--output FILE]
  change-guard ai --report JSON --config YAML [--output FILE]
  change-guard verify-knowledge [--knowledge-dir DIR] [--output FILE]
  change-guard daemon --config YAML [--once]
  change-guard evaluate-pr --config YAML --pr NUMBER [--output FILE]
  change-guard merge --config YAML --pr NUMBER [--evaluation-id ID]
  change-guard postdeploy verify --config YAML --expected-sha SHA
      [--expected-app-sha SHA] [--expected-image IMAGE] [--report JSON]
      [--output FILE]
  change-guard check-token KUBECONFIG [--min-remaining SECONDS] [--now UNIX]
  change-guard renew-token
  change-guard credential-check --config YAML [--probe-sha SHA] [--output FILE]
  change-guard scenario [--output FILE]

Exit codes:
  evaluate: 0 PASS, 1 REVIEW, 2 BLOCK, 3 ERROR
  postdeploy verify: 0 ok, 1 failed, 2 error
  check-token: 0 valid, 1 rotate, 2 error
  scenario: 0 all synthetic scenarios passed, 1 mismatch, 3 error
`)
}

func cgFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	return flags
}

func cgWrite(value any, path string) error {
	if path != "" {
		return guard.WriteJSON(path, value)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func cgLoadOptional(path string) (guard.M, error) {
	if path == "" {
		return guard.M{}, nil
	}
	return guard.ReadJSON(path)
}

func cgLoadConfigOptional(path string) (guard.M, error) {
	if path == "" {
		return guard.M{}, nil
	}
	return guard.LoadConfig(path)
}

func cgLoadConfigRequired(path string) (guard.M, error) {
	if path == "" {
		return nil, errors.New("--config is required")
	}
	return guard.LoadConfig(path)
}

func cgError(err error) string {
	text := strings.TrimSpace(err.Error())
	if len(text) > 800 {
		text = text[:797] + "..."
	}
	return text
}

func cgFail(err error) int {
	payload := map[string]any{"status": "error", "error": cgError(err)}
	_ = cgWrite(payload, "")
	return cgExitError
}

func cgDecisionExit(decision string) int {
	switch strings.ToUpper(decision) {
	case "PASS":
		return cgExitPass
	case "REVIEW":
		return cgExitReview
	case "BLOCK":
		return cgExitBlock
	default:
		return cgExitError
	}
}

func cgEvaluate(args []string) int {
	flags := cgFlagSet("evaluate")
	var oldPaths, newPaths cgStrings
	flags.Var(&oldPaths, "old", "old rendered YAML (repeatable)")
	flags.Var(&newPaths, "new", "new rendered YAML (repeatable)")
	configPath := flags.String("config", "", "config YAML")
	evidencePath := flags.String("evidence", "", "evidence JSON")
	contextPath := flags.String("context", "", "context JSON")
	aiPath := flags.String("ai-result", "", "DeepSeek result JSON")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if flags.NArg() != 0 {
		return cgFail(errors.New("evaluate does not accept positional arguments"))
	}
	if len(newPaths) == 0 {
		return cgFail(errors.New("at least one --new manifest is required"))
	}
	config, err := cgLoadConfigOptional(*configPath)
	if err != nil {
		return cgFail(err)
	}
	context, err := cgLoadOptional(*contextPath)
	if err != nil {
		return cgFail(err)
	}
	evidence, err := cgLoadOptional(*evidencePath)
	if err != nil {
		return cgFail(err)
	}
	var aiResult guard.M
	if *aiPath != "" {
		aiResult, err = guard.ReadJSON(*aiPath)
		if err != nil {
			return cgFail(err)
		}
	}
	var oldResources []guard.M
	if len(oldPaths) > 0 {
		oldResources, err = guard.LoadRenderedManifests(oldPaths, config)
		if err != nil {
			return cgFail(err)
		}
	}
	newResources, err := guard.LoadRenderedManifests(newPaths, config)
	if err != nil {
		return cgFail(err)
	}
	result := guard.Evaluate(oldResources, newResources, evidence, config, context, aiResult)
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	return cgDecisionExit(guard.Str(result["decision"]))
}

func cgRender(args []string) int {
	flags := cgFlagSet("render")
	var preRendered cgStrings
	flags.Var(&preRendered, "pre-rendered", "fixture-only rendered YAML (repeatable)")
	tree := flags.String("tree", "", "candidate repository tree")
	configPath := flags.String("config", "", "renderer config YAML")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if flags.NArg() != 0 {
		return cgFail(errors.New("render does not accept positional arguments"))
	}
	config, err := cgLoadConfigOptional(*configPath)
	if err != nil {
		return cgFail(err)
	}
	var resources []guard.M
	if len(preRendered) > 0 {
		resources, err = guard.LoadRenderedManifests(preRendered, config)
	} else {
		if *tree == "" {
			return cgFail(errors.New("render requires --tree or --pre-rendered"))
		}
		resources, err = guard.RenderTree(*tree, config)
	}
	if err != nil {
		return cgFail(err)
	}
	if err := cgWrite(resources, *output); err != nil {
		return cgFail(err)
	}
	return cgExitPass
}

func cgCollect(args []string) int {
	flags := cgFlagSet("collect")
	configPath := flags.String("config", "", "config YAML")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		return cgFail(err)
	}
	result := guard.Collect(config)
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	if len(guard.Arr(result["errors"])) > 0 {
		return cgExitError
	}
	return cgExitPass
}

func cgAI(args []string) int {
	flags := cgFlagSet("ai")
	reportPath := flags.String("report", "", "sanitized report JSON")
	configPath := flags.String("config", "", "config YAML")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		return cgFail(err)
	}
	if *reportPath == "" {
		return cgFail(errors.New("--report is required"))
	}
	report, err := guard.ReadJSON(*reportPath)
	if err != nil {
		return cgFail(err)
	}
	result := guard.Analyze(report, config)
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	if guard.Str(result["status"]) != "ok" {
		return cgExitError
	}
	return cgExitPass
}

func cgVerifyKnowledge(args []string) int {
	flags := cgFlagSet("verify-knowledge")
	directory := flags.String("knowledge-dir", "knowledge", "knowledge directory")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if flags.NArg() != 0 {
		return cgFail(errors.New("verify-knowledge does not accept positional arguments"))
	}
	result, err := guard.VerifyKnowledge(*directory)
	if err != nil {
		return cgFail(err)
	}
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	return cgExitPass
}

func cgDaemon(args []string) int {
	flags := cgFlagSet("daemon")
	configPath := flags.String("config", "", "config YAML")
	once := flags.Bool("once", false, "run one polling pass and exit")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		cgFail(err)
		return 2
	}
	if err := guard.RunDaemon(config, *once); err != nil {
		cgFail(err)
		return 2
	}
	if *once {
		_ = cgWrite(map[string]any{"status": "ok"}, "")
	}
	return cgExitPass
}

func cgEvaluatePR(args []string) int {
	flags := cgFlagSet("evaluate-pr")
	configPath := flags.String("config", "", "config YAML")
	number := flags.Int("pr", 0, "pull request number")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if *number <= 0 {
		return cgFail(errors.New("--pr must be a positive pull request number"))
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		return cgFail(err)
	}
	result, err := guard.EvaluatePR(config, *number)
	if err != nil {
		return cgFail(err)
	}
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	return cgDecisionExit(guard.Str(result["decision"]))
}

func cgMerge(args []string) int {
	flags := cgFlagSet("merge")
	configPath := flags.String("config", "", "config YAML")
	number := flags.Int("pr", 0, "pull request number")
	evaluationID := flags.String("evaluation-id", "", "exact evaluation id (optional)")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if *number <= 0 {
		fmt.Println(`{"result":"REFUSED","error":"--pr must be a positive pull request number"}`)
		return 1
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		fmt.Printf("{\"result\":\"REFUSED\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 1
	}
	result, err := guard.MergeRelease(config, *number, *evaluationID)
	if err != nil {
		fmt.Printf("{\"result\":\"REFUSED\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 1
	}
	if err := cgWrite(result, ""); err != nil {
		fmt.Printf("{\"result\":\"REFUSED\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 1
	}
	return cgExitPass
}

func cgJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return `"error"`
	}
	return string(encoded)
}

func cgPostDeploy(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: change-guard postdeploy verify --config YAML --expected-sha SHA")
		return cgPostDeployError
	}
	flags := cgFlagSet("postdeploy verify")
	configPath := flags.String("config", "", "config YAML")
	expectedSHA := flags.String("expected-sha", "", "exact Git commit that Argo should sync")
	expectedAppSHA := flags.String("expected-app-sha", "", "image source commit exposed by /version")
	expectedImage := flags.String("expected-image", "", "exact repository@sha256 digest")
	reportPath := flags.String("report", "", "change-guard evaluation report JSON")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args[1:]); err != nil {
		return cgPostDeployError
	}
	if flags.NArg() != 0 {
		_ = cgWrite(pdCLIError("postdeploy verify does not accept positional arguments"), "")
		return cgPostDeployError
	}
	config, err := guard.LoadConfig(*configPath)
	if err != nil {
		_ = cgWrite(pdCLIError(cgError(err)), "")
		return cgPostDeployError
	}
	if *expectedSHA == "" {
		_ = cgWrite(pdCLIError("--expected-sha is required"), "")
		return cgPostDeployError
	}
	if *reportPath != "" {
		report, err := guard.ReadJSON(*reportPath)
		if err != nil {
			_ = cgWrite(pdCLIError(cgError(err)), "")
			return cgPostDeployError
		}
		config["_postdeploy_report"] = report
	}
	if *expectedImage != "" {
		config["expected_image"] = *expectedImage
	}
	result := guard.PostDeploy(config, *expectedSHA, *expectedAppSHA)
	if err := cgWrite(result, *output); err != nil {
		_ = cgWrite(pdCLIError(cgError(err)), "")
		return cgPostDeployError
	}
	switch guard.Str(result["status"]) {
	case "ok":
		return cgPostDeployOK
	case "failed":
		return cgPostDeployFailed
	default:
		return cgPostDeployError
	}
}

func pdCLIError(message string) guard.M {
	return guard.M{
		"schema_version": 1,
		"verifier":       cgPostDeployVerifier,
		"status":         "error",
		"error":          message,
	}
}

func cgCheckToken(args []string) int {
	flags := cgFlagSet("check-token")
	minRemaining := flags.Int("min-remaining", 3600, "minimum remaining seconds")
	now := flags.Float64("now", 0, "testing override for current Unix time")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Println(`{"status":"error","error":"usage: change-guard check-token KUBECONFIG [--min-remaining SECONDS]"}`)
		return 2
	}
	nowSet := false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == "now" {
			nowSet = true
		}
	})
	var result guard.M
	var err error
	if nowSet {
		result, err = guard.CheckTokenExpiry(flags.Arg(0), *minRemaining, *now)
	} else {
		result, err = guard.CheckTokenExpiry(flags.Arg(0), *minRemaining)
	}
	if err != nil {
		fmt.Printf("{\"status\":\"error\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 2
	}
	if err := cgWrite(result, ""); err != nil {
		fmt.Printf("{\"status\":\"error\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 2
	}
	if guard.Str(result["status"]) == "valid" {
		return 0
	}
	return 1
}

func cgRenewToken(args []string) int {
	if len(args) != 0 {
		fmt.Println(`{"status":"error","error":"renew-token accepts no arguments"}`)
		return 1
	}
	result, err := guard.RenewServiceToken()
	if err != nil {
		fmt.Printf("{\"status\":\"error\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 1
	}
	if err := cgWrite(result, ""); err != nil {
		fmt.Printf("{\"status\":\"error\",\"error\":%s}\n", cgJSONString(cgError(err)))
		return 1
	}
	return 0
}

func cgCredentialCheck(args []string) int {
	flags := cgFlagSet("credential-check")
	configPath := flags.String("config", "", "config YAML")
	probeSHA := flags.String("probe-sha", "", "perform a real pending status write for this commit")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	config, err := cgLoadConfigRequired(*configPath)
	if err != nil {
		_ = cgWrite(map[string]any{"status": "error", "error": cgError(err)}, "")
		return 1
	}
	repository := guard.CfgString(config, "repository", "")
	if repository == "" {
		_ = cgWrite(map[string]any{"status": "error", "error": "repository is required"}, "")
		return 1
	}
	client, err := guard.NewGitHub(config)
	if err != nil {
		_ = cgWrite(map[string]any{"status": "error", "error": cgError(err)}, "")
		return 1
	}
	raw, err := client.API("GET", "/repos/"+repository, nil)
	if err != nil {
		_ = cgWrite(map[string]any{"status": "error", "error": cgError(err)}, "")
		return 1
	}
	repo := guard.Obj(raw)
	result := map[string]any{
		"status":      "ok",
		"repository":  repository,
		"private":     repo["private"],
		"permissions": repo["permissions"],
	}
	if *probeSHA != "" {
		if !cgValidSHA(*probeSHA) {
			_ = cgWrite(map[string]any{"status": "error", "error": "probe SHA must be a hexadecimal Git commit id"}, "")
			return 1
		}
		body := map[string]any{
			"state":       "pending",
			"context":     "change-guard/credential-probe",
			"description": "credential capability probe",
		}
		if _, err := client.API("POST", "/repos/"+repository+"/statuses/"+*probeSHA, body); err != nil {
			_ = cgWrite(map[string]any{"status": "error", "error": cgError(err)}, "")
			return 1
		}
		result["probe"] = map[string]any{
			"status":  "written",
			"sha":     *probeSHA,
			"context": "change-guard/credential-probe",
		}
	}
	if err := cgWrite(result, *output); err != nil {
		_ = cgWrite(map[string]any{"status": "error", "error": cgError(err)}, "")
		return 1
	}
	return 0
}

func cgValidSHA(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
