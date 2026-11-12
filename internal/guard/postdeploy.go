package guard

// Read-only post-deployment verification.
//
// PostDeploy answers one question: did the exact release that the guard
// approved actually become the running release?  It checks the Argo CD sync
// revision/status/health, the Deployment image and replica status, the running
// Pods' readiness and actual status.containerStatuses[].imageID, Service
// endpoints, the demo HTTP /version provenance plus readiness endpoint, and a
// Prometheus observation window.
//
// The verifier never mutates the cluster, never reads Secrets, never uses
// exec/logs, and never rolls back automatically.  A failure is only an
// "open a revert pull request" recommendation.
//
// The GitOps/Argo revision (expectedSHA) and the image source revision exposed
// by /version (expectedAppSHA) are deliberately separate.  Pod matching uses
// the Pod spec container name/image; the runtime digest is read from
// status.containerStatuses[].imageID because containerd may report a config ID
// in status.containerStatuses[].image.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const pdSchemaVersion = 1

const (
	pdDefaultTimeoutSeconds      = 300
	pdDefaultPollSeconds         = 5
	pdDefaultObservationSeconds  = 60
	pdDefaultEvidenceTTLSeconds  = 300
	pdDefaultMaxErrorRatio       = 0.05
	pdDefaultMaxP95Seconds       = 0.5
	pdDefaultMinRequestRate      = 0.1
	pdMaxHTTPBytes               = 128 * 1024
	pdMaxKubectlBytes            = 16 * 1024 * 1024
	pdMaxChecks                  = 1000
	pdPostDeployVerifierName     = "change-guard-postdeploy"
	pdPostDeployRecommendationNo = "This verifier is read-only. Open a revert pull request for the offending change; " +
		"it does not and must not roll back or mutate the cluster automatically."
)

var (
	pdSHAPattern         = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	pdDNSLabelPattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	pdSafeLabelPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)
	pdLabelKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?(?:/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?$`)
	pdImageDigestPattern = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	pdSecretPartPattern  = []string{
		"token", "secret", "password", "passwd", "authorization", "credential",
		"private_key", "privatekey", "api_key", "apikey", "kubeconfig", "cookie", "stringdata",
	}
	pdForbiddenKubectlWords = map[string]struct{}{
		"apply": {}, "attach": {}, "auth": {}, "autoscale": {}, "certificate": {},
		"cluster-info": {}, "completion": {}, "config": {}, "cordon": {}, "cp": {},
		"create": {}, "debug": {}, "delete": {}, "drain": {}, "edit": {}, "exec": {},
		"expose": {}, "label": {}, "logs": {}, "patch": {}, "port-forward": {},
		"proxy": {}, "replace": {}, "rollout": {}, "run": {}, "scale": {}, "set": {},
		"taint": {}, "uncordon": {}, "wait": {},
	}
	pdForbiddenKubectlResources = map[string]struct{}{
		"secret": {}, "secrets": {}, "pods/log": {}, "pods/exec": {}, "deployments/scale": {},
	}
	pdTokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`),
	}
	pdControlPattern = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

type pdRunner func(args []string, timeout int) (any, error)
type pdHTTPGet func(path string, timeout int) (int, []byte, error)
type pdMetricsProvider func(config M) M

type pdOptions struct {
	kubectlRunner   pdRunner
	httpGet         pdHTTPGet
	metricsProvider pdMetricsProvider
	clock           func() float64
	sleep           func(float64)
	report          M
	expectedImage   string
}

// PostDeploy performs the read-only six-check post-deployment verification.
// config is normally the parsed config.yaml (an optional "expected_image"
// value and a private "_postdeploy_report" object are accepted).  expectedSHA
// is the Argo/GitOps revision; expectedAppSHA is the image source commit
// exposed by /version.  They are intentionally independent.
func PostDeploy(config M, expectedSHA, expectedAppSHA string) M {
	report := M(nil)
	if raw, ok := config["_postdeploy_report"]; ok {
		report = Obj(raw)
	}
	expectedImage := ""
	if raw, ok := config["expected_image"]; ok && raw != nil {
		if text, ok := raw.(string); ok {
			expectedImage = text
		}
	}
	return pdVerify(config, expectedSHA, expectedImage, expectedAppSHA, pdOptions{report: report})
}

// pdVerify is the injectable implementation used by tests and by PostDeploy.
func pdVerify(config M, expectedSHA, expectedImage, expectedAppSHA string, options pdOptions) M {
	clock := options.clock
	if clock == nil {
		clock = func() float64 { return float64(time.Now().Unix()) }
	}
	sleep := options.sleep
	if sleep == nil {
		sleep = func(seconds float64) { time.Sleep(time.Duration(seconds * float64(time.Second))) }
	}
	startedAt := pdNow(clock)
	if startedAt < 0 {
		startedAt = 0
	}

	cfg, err := pdValidateConfig(config)
	if err != nil {
		return pdErrorResult(err, startedAt)
	}
	if !pdSHAPattern.MatchString(expectedSHA) {
		return pdErrorResult(errors.New("expected_sha must be a hexadecimal Git commit id"), startedAt)
	}
	appSHA := expectedAppSHA
	if appSHA == "" {
		appSHA = expectedSHA
	}
	if !pdSHAPattern.MatchString(appSHA) {
		return pdErrorResult(errors.New("expected_app_sha must be a hexadecimal image source commit id"), startedAt)
	}
	if expectedImage == "" && options.expectedImage != "" {
		expectedImage = options.expectedImage
	}
	if expectedImage == "" && options.report != nil {
		if derived, err := pdExpectedImageFromReport(options.report, cfg); err == nil {
			expectedImage = derived
		} else {
			return pdErrorResult(err, startedAt)
		}
	}
	if expectedImage == "" {
		return pdErrorResult(errors.New("expected_image is required"), startedAt)
	}
	image, err := pdValidateExpectedImage(expectedImage, cfg)
	if err != nil {
		return pdErrorResult(err, startedAt)
	}

	runner := options.kubectlRunner
	if runner == nil {
		runner = func(args []string, timeout int) (any, error) {
			return pdDefaultKubectlRunner(cfg, args, timeout)
		}
	}
	getter := options.httpGet
	if getter == nil {
		getter = func(path string, timeout int) (int, []byte, error) {
			return pdDefaultHTTPGet(cfg, path, timeout)
		}
	}
	provider := options.metricsProvider
	if provider == nil {
		provider = func(c M) M { return Collect(c) }
	}

	timeoutSeconds := int(pdInt64Value(cfg["postdeploy_timeout_seconds"]))
	pollSeconds := pdNumValue(cfg["postdeploy_poll_seconds"])
	deadline := float64(startedAt) + float64(timeoutSeconds)
	maxAttempts := timeoutSeconds + 2
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if maxAttempts > pdMaxChecks {
		maxAttempts = pdMaxChecks
	}

	coreChecks := func() []M {
		return []M{
			pdRunCheck("argo", func() (M, error) {
				return pdCheckArgo(cfg, expectedSHA, runner)
			}),
			pdRunCheck("deployment", func() (M, error) {
				return pdCheckDeployment(cfg, image, runner)
			}),
			pdRunCheck("pods", func() (M, error) {
				return pdCheckPods(cfg, image, runner)
			}),
			pdRunCheck("endpoints", func() (M, error) {
				return pdCheckEndpoints(cfg, runner)
			}),
			pdRunCheck("http", func() (M, error) {
				return pdCheckHTTP(cfg, appSHA, getter)
			}),
		}
	}

	var checks []M
	attempts := 0
	for attempts < maxAttempts {
		attempts++
		checks = coreChecks()
		if pdAllPassed(checks) {
			break
		}
		if float64(pdNow(clock)) >= deadline {
			break
		}
		remaining := deadline - float64(pdNow(clock))
		if remaining < 1 {
			remaining = 1
		}
		wait := pollSeconds
		if wait > remaining {
			wait = remaining
		}
		sleep(wait)
	}
	if !pdAllPassed(checks) {
		return pdFailureResult(expectedSHA, appSHA, image, checks, startedAt, pdNow(clock))
	}

	observationSeconds := int(pdInt64Value(cfg["observation_seconds"]))
	if observationSeconds > 0 {
		sleep(float64(observationSeconds))
	}
	metricAttempts := 0
	metricCheck := pdCheckResult("metrics", "fail", "metrics were not observed", nil)
	for metricAttempts < maxAttempts {
		metricAttempts++
		metricCheck = pdRunCheck("metrics", func() (M, error) {
			return pdCheckMetrics(cfg, provider, observationSeconds)
		})
		if Str(metricCheck["status"]) == "pass" {
			break
		}
		if float64(pdNow(clock)) >= deadline {
			break
		}
		remaining := deadline - float64(pdNow(clock))
		if remaining < 1 {
			remaining = 1
		}
		wait := pollSeconds
		if wait > remaining {
			wait = remaining
		}
		sleep(wait)
	}
	checks = append(checks, metricCheck)
	finishedAt := pdNow(clock)
	if Str(metricCheck["status"]) != "pass" {
		return pdFailureResult(expectedSHA, appSHA, image, checks, startedAt, finishedAt)
	}
	return M{
		"schema_version":   pdSchemaVersion,
		"verifier":         pdPostDeployVerifierName,
		"status":           "ok",
		"expected_sha":     expectedSHA,
		"expected_app_sha": appSHA,
		"expected_image":   image,
		"checks":           checks,
		"observation":      metricCheck["evidence"],
		"recommendation":   nil,
		"started_at":       startedAt,
		"finished_at":      finishedAt,
	}
}

// ---------------------------------------------------------------------------
// Generic helpers

func pdNow(clock func() float64) int64 {
	value := clock()
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return -1
	}
	return int64(value)
}

func pdNumValue(value any) float64 {
	switch number := value.(type) {
	case float64:
		if !math.IsNaN(number) && !math.IsInf(number, 0) {
			return number
		}
	case float32:
		return pdNumValue(float64(number))
	case int:
		return float64(number)
	case int64:
		return float64(number)
	case int32:
		return float64(number)
	case json.Number:
		parsed, err := number.Float64()
		if err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
			return parsed
		}
	}
	return 0
}

func pdInt64Value(value any) int64 {
	switch number := value.(type) {
	case int:
		return int64(number)
	case int64:
		return number
	case int32:
		return int64(number)
	case float64:
		if !math.IsNaN(number) && !math.IsInf(number, 0) {
			return int64(number)
		}
	case json.Number:
		parsed, err := number.Int64()
		if err == nil {
			return parsed
		}
	}
	return 0
}

func pdStrictNumber(value any) (float64, bool) {
	switch number := value.(type) {
	case bool:
		return 0, false
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return 0, false
		}
		return number, true
	case float32:
		return pdStrictNumber(float64(number))
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case int32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

func pdInteger(value any) (int64, bool) {
	number, ok := pdStrictNumber(value)
	if !ok || math.Trunc(number) != number {
		return 0, false
	}
	if number < math.MinInt64 || number > math.MaxInt64 {
		return 0, false
	}
	return int64(number), true
}

func pdTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return len(typed) > 0
	case float64:
		return typed != 0 && !math.IsNaN(typed)
	case float32:
		return typed != 0
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case int32:
		return typed != 0
	case []any:
		return len(typed) > 0
	case []M:
		return len(typed) > 0
	case M:
		return len(typed) > 0
	}
	return true
}

func pdConfigBool(config M, key string, fallback bool) bool {
	if value, ok := config[key]; ok {
		return pdTruthy(value)
	}
	return fallback
}

func pdSanitize(value any, limit int) string {
	text := fmt.Sprint(value)
	for _, pattern := range pdTokenPatterns {
		text = pattern.ReplaceAllString(text, "<redacted>")
	}
	text = pdControlPattern.ReplaceAllString(text, " ")
	text = strings.Join(strings.Fields(text), " ")
	if limit > 0 && len(text) > limit {
		if limit <= 3 {
			text = text[:limit]
		} else {
			text = text[:limit-3] + "..."
		}
	}
	return text
}

func pdRedact(value any, depth int, key string) any {
	if depth > 12 {
		return "<depth-limit>"
	}
	lowered := strings.ToLower(key)
	for _, part := range pdSecretPartPattern {
		if strings.Contains(lowered, part) {
			return "<redacted>"
		}
	}
	switch typed := value.(type) {
	case M:
		out := M{}
		count := 0
		for childKey, childValue := range typed {
			if count >= 500 {
				break
			}
			out[childKey] = pdRedact(childValue, depth+1, childKey)
			count++
		}
		return out
	case []M:
		converted := make([]any, len(typed))
		for index, item := range typed {
			converted[index] = item
		}
		return pdRedact(converted, depth, key)
	case []any:
		out := make([]any, 0, len(typed))
		for index, item := range typed {
			if index >= 200 {
				break
			}
			out = append(out, pdRedact(item, depth+1, key))
		}
		return out
	case []string:
		out := make([]any, 0, len(typed))
		for index, item := range typed {
			if index >= 200 {
				break
			}
			out = append(out, pdSanitize(item, 4000))
		}
		return out
	case string:
		return pdSanitize(typed, 4000)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil
		}
		return typed
	case float32:
		return pdRedact(float64(typed), depth, key)
	case int, int64, int32, uint64, bool, nil:
		return typed
	default:
		return pdSanitize(typed, 1000)
	}
}

func pdCheckResult(name, status, detail string, evidence M) M {
	redacted := M{}
	if evidence != nil {
		redacted = Obj(pdRedact(evidence, 0, ""))
	}
	return M{
		"name":     name,
		"status":   status,
		"detail":   pdSanitize(detail, 1000),
		"evidence": redacted,
	}
}

func pdRunCheck(name string, function func() (M, error)) (result M) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = pdCheckResult(name, "fail", pdSanitize(recovered, 1000), nil)
		}
	}()
	result, err := function()
	if err != nil {
		return pdCheckResult(name, "fail", pdSanitize(err.Error(), 1000), nil)
	}
	if result == nil {
		return pdCheckResult(name, "fail", "check returned no result", nil)
	}
	return result
}

func pdAllPassed(checks []M) bool {
	for _, check := range checks {
		if Str(check["status"]) != "pass" {
			return false
		}
	}
	return true
}

func pdList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []M:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = item
		}
		return out
	case []string:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = item
		}
		return out
	}
	return nil
}

func pdString(value any) string {
	text, _ := value.(string)
	return text
}

func pdNumberFinite(value any) (float64, bool) {
	return pdStrictNumber(value)
}

// ---------------------------------------------------------------------------
// Configuration and expected image validation

func pdLabel(value any, field string) (string, error) {
	text, ok := value.(string)
	if !ok || len(text) > 63 || !pdDNSLabelPattern.MatchString(text) {
		return "", fmt.Errorf("%s is not a valid Kubernetes DNS label", field)
	}
	return text, nil
}

func pdBoundedNumber(config M, key string, fallback, minimum, maximum float64, integer bool) (any, error) {
	raw, exists := config[key]
	if !exists {
		raw = fallback
	}
	number, ok := pdStrictNumber(raw)
	if !ok {
		return nil, fmt.Errorf("%s must be a finite number", key)
	}
	if number < minimum || number > maximum {
		return nil, fmt.Errorf("%s must be between %v and %v", key, minimum, maximum)
	}
	if integer {
		return int64(number), nil
	}
	return number, nil
}

func pdHTTPBaseURL(value any, field string) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	text = strings.TrimSpace(text)
	parsed, err := url.Parse(text)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("%s must be an http(s) URL", field)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%s must not contain credentials", field)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must not contain a query or fragment", field)
	}
	path := strings.TrimRight(parsed.Path, "/")
	base := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: path}
	return base.String(), nil
}

func pdValidateConfig(config M) (M, error) {
	if config == nil {
		return nil, errors.New("config must be a mapping")
	}
	value := M{}
	for key, item := range config {
		value[key] = item
	}
	namespace, err := pdLabel(pdDefault(value, "namespace", "demo"), "namespace")
	if err != nil {
		return nil, err
	}
	deployment, err := pdLabel(pdDefault(value, "deployment", "demo"), "deployment")
	if err != nil {
		return nil, err
	}
	argocdNamespace, err := pdLabel(pdDefault(value, "argocd_namespace", "argocd"), "argocd_namespace")
	if err != nil {
		return nil, err
	}
	argoApplication, err := pdLabel(pdDefault(value, "argo_application", deployment), "argo_application")
	if err != nil {
		return nil, err
	}
	demoURL, err := pdHTTPBaseURL(value["demo_url"], "demo_url")
	if err != nil {
		return nil, err
	}
	value["namespace"] = namespace
	value["deployment"] = deployment
	value["argocd_namespace"] = argocdNamespace
	value["argo_application"] = argoApplication
	value["demo_url"] = demoURL
	value["version_path"] = pdDefault(value, "version_path", "/version")
	value["ready_path"] = pdDefault(value, "ready_path", "/ready")
	for _, pathName := range []string{"version_path", "ready_path"} {
		path := pdString(value[pathName])
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "://") || pdPathHasDotDot(path) || strings.ContainsAny(path, " \t\r\n") {
			return nil, fmt.Errorf("%s must be a clean absolute path", pathName)
		}
	}
	containerName := value["container_name"]
	if containerName != nil {
		text, ok := containerName.(string)
		if !ok || !pdSafeLabelPattern.MatchString(text) {
			return nil, errors.New("container_name is invalid")
		}
	}
	selectorDefault := fmt.Sprintf("app.kubernetes.io/name=%s,app.kubernetes.io/instance=%s", deployment, deployment)
	selector := pdDefault(value, "pod_label_selector", selectorDefault)
	selectorText, ok := selector.(string)
	if !ok || selectorText == "" || len(selectorText) > 1024 {
		return nil, errors.New("pod_label_selector is invalid")
	}
	for _, part := range strings.Split(selectorText, ",") {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return nil, errors.New("pod_label_selector must contain key=value pairs")
		}
		key := keyValue[0]
		labelValue := keyValue[1]
		if len(key) > 253 || !pdLabelKeyPattern.MatchString(key) || !pdSafeLabelPattern.MatchString(labelValue) {
			return nil, errors.New("pod_label_selector contains an invalid label")
		}
	}
	value["pod_label_selector"] = selectorText

	for _, item := range []struct {
		key      string
		fallback float64
		minimum  float64
		maximum  float64
		integer  bool
	}{
		{"postdeploy_timeout_seconds", pdDefaultTimeoutSeconds, 1, 7200, true},
		{"postdeploy_poll_seconds", pdDefaultPollSeconds, 1, 60, true},
		{"observation_seconds", pdDefaultObservationSeconds, 0, 3600, true},
		{"max_error_ratio", pdDefaultMaxErrorRatio, 0, 1, false},
		{"max_p95_seconds", pdDefaultMaxP95Seconds, 0, 60, false},
		{"min_request_rate", pdDefaultMinRequestRate, 0, 1000000, false},
		{"evidence_ttl_seconds", pdDefaultEvidenceTTLSeconds, 1, 86400, true},
	} {
		parsed, err := pdBoundedNumber(value, item.key, item.fallback, item.minimum, item.maximum, item.integer)
		if err != nil {
			return nil, err
		}
		value[item.key] = parsed
	}
	value["require_digest"] = pdConfigBool(value, "require_digest", true)
	value["require_pod_image_id"] = pdConfigBool(value, "require_pod_image_id", true)
	value["strict_image_id_digest"] = pdConfigBool(value, "strict_image_id_digest", false)
	value["use_proxy_env"] = pdConfigBool(value, "use_proxy_env", true)
	value["kubectl"] = pdDefault(value, "kubectl", "/usr/bin/kubectl")
	kubeconfig := pdDefault(value, "kubeconfig", "")
	kubeconfigText, _ := kubeconfig.(string)
	if strings.ContainsRune(kubeconfigText, '\x00') {
		return nil, errors.New("kubeconfig path is invalid")
	}
	value["kubeconfig"] = kubeconfigText
	return value, nil
}

func pdDefault(config M, key string, fallback any) any {
	if value, ok := config[key]; ok {
		return value
	}
	return fallback
}

func pdPathHasDotDot(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func pdValidateExpectedImage(image any, config M) (string, error) {
	text, ok := image.(string)
	if !ok || strings.TrimSpace(text) == "" || strings.ContainsAny(text, " \t\r\n") {
		return "", errors.New("expected image is empty or malformed")
	}
	text = strings.TrimSpace(text)
	repository := text
	if at := strings.Index(repository, "@"); at >= 0 {
		repository = repository[:at]
	}
	if strings.HasSuffix(strings.TrimSpace(repository), ":") {
		return "", errors.New("expected image has no tag/digest")
	}
	lastSlash := strings.LastIndex(repository, "/")
	lastSegment := repository
	if lastSlash >= 0 {
		lastSegment = repository[lastSlash+1:]
	}
	if colon := strings.LastIndex(lastSegment, ":"); colon >= 0 {
		repository = repository[:lastSlash+1+colon]
	}
	if allowed, ok := config["allowed_image_repository"].(string); ok && allowed != "" && repository != allowed {
		return "", errors.New("expected image repository is not allowlisted")
	}
	if at := strings.LastIndex(text, "@"); at >= 0 {
		digest := text[at+1:]
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest) {
			return "", errors.New("expected image digest must be sha256:<64 lowercase hex>")
		}
	} else if pdConfigBool(config, "require_digest", true) {
		return "", errors.New("expected image must be pinned by sha256 digest")
	}
	return text, nil
}

func pdExpectedImageFromReport(report M, config M) (string, error) {
	if report == nil {
		return "", errors.New("report must be a mapping")
	}
	images := pdList(report["deployment_images"])
	if len(images) == 0 {
		return "", errors.New("report has no deployment images")
	}
	containerName, hasContainerName := config["container_name"]
	var candidates []string
	for _, item := range images {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if pdTruthy(entry["init"]) {
			continue
		}
		if hasContainerName && containerName != nil && pdString(entry["container"]) != pdString(containerName) {
			continue
		}
		image := pdString(entry["image"])
		if image == "" {
			continue
		}
		found := false
		for _, candidate := range candidates {
			if candidate == image {
				found = true
				break
			}
		}
		if !found {
			candidates = append(candidates, image)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return "", errors.New("report has no matching non-init container image")
	}
	return "", errors.New("report has multiple deployment images; pass --expected-image explicitly")
}

// ---------------------------------------------------------------------------
// Read-only kubectl

func pdAssertReadOnlyKubectlArgs(args []string) error {
	lowered := make([]string, len(args))
	for index, arg := range args {
		lowered[index] = strings.ToLower(arg)
	}
	verbIndex := 0
	if len(lowered) >= 2 && lowered[0] == "-n" {
		verbIndex = 2
	}
	if len(lowered) <= verbIndex || lowered[verbIndex] != "get" {
		return errors.New("postdeploy only permits fixed kubectl get commands")
	}
	for _, arg := range lowered {
		if _, forbidden := pdForbiddenKubectlWords[arg]; forbidden {
			return fmt.Errorf("kubectl verb/resource %q is not permitted", arg)
		}
		if _, forbidden := pdForbiddenKubectlResources[arg]; forbidden {
			return fmt.Errorf("kubectl resource %q is not permitted", arg)
		}
		if strings.Contains(arg, "pods/log") || strings.Contains(arg, "pods/exec") {
			return fmt.Errorf("kubectl subresource %q is not permitted", arg)
		}
		if strings.HasPrefix(arg, "--raw") || strings.HasPrefix(arg, "--server") || strings.HasPrefix(arg, "--token") {
			return fmt.Errorf("kubectl option %q is not permitted", arg)
		}
	}
	hasJSON := false
	for _, arg := range lowered {
		if arg == "json" {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		return errors.New("kubectl command must request JSON output")
	}
	return nil
}

func pdKubectlCommand(config M, args []string) ([]string, error) {
	if err := pdAssertReadOnlyKubectlArgs(args); err != nil {
		return nil, err
	}
	command := []string{pdString(pdDefault(config, "kubectl", "/usr/bin/kubectl"))}
	if kubeconfig := pdString(pdDefault(config, "kubeconfig", "")); kubeconfig != "" {
		command = append(command, "--kubeconfig="+kubeconfig)
	}
	command = append(command, fmt.Sprintf("--request-timeout=%ds", pdInt64Value(config["postdeploy_timeout_seconds"])))
	command = append(command, args...)
	return command, nil
}

type pdLimitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (writer *pdLimitedBuffer) Write(data []byte) (int, error) {
	if !writer.truncated {
		remaining := writer.limit - writer.buffer.Len()
		if remaining > 0 {
			if len(data) <= remaining {
				_, _ = writer.buffer.Write(data)
			} else {
				_, _ = writer.buffer.Write(data[:remaining])
				writer.truncated = true
			}
		} else {
			writer.truncated = true
		}
	}
	return len(data), nil
}

func pdDefaultKubectlRunner(config M, args []string, timeout int) (any, error) {
	command, err := pdKubectlCommand(config, args)
	if err != nil {
		return nil, err
	}
	executable := command[0]
	if executable == "" {
		return nil, errors.New("kubectl executable is missing")
	}
	if strings.ContainsAny(executable, `/\`) {
		if stat, statErr := os.Stat(executable); statErr != nil || !stat.Mode().IsRegular() {
			return nil, errors.New("kubectl executable is missing")
		}
	}
	temporary, err := os.MkdirTemp("", "change-guard-postdeploy-")
	if err != nil {
		return nil, errors.New("could not create a private kubectl home")
	}
	defer os.RemoveAll(temporary)
	environment := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + temporary,
		"XDG_CACHE_HOME=" + temporary + "/cache",
		"XDG_CONFIG_HOME=" + temporary + "/config",
		"LANG=C",
		"LC_ALL=C",
	}
	if kubeconfig := pdString(pdDefault(config, "kubeconfig", "")); kubeconfig != "" {
		environment = append(environment, "KUBECONFIG="+kubeconfig)
	}
	contexted, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	process := exec.CommandContext(contexted, command[0], command[1:]...)
	process.Env = environment
	process.Stdin = nil
	stdout := &pdLimitedBuffer{limit: pdMaxKubectlBytes}
	stderr := &pdLimitedBuffer{limit: pdMaxKubectlBytes}
	process.Stdout = stdout
	process.Stderr = stderr
	runErr := process.Run()
	if errors.Is(contexted.Err(), context.DeadlineExceeded) {
		return nil, errors.New("kubectl timed out")
	}
	if stdout.truncated || stderr.truncated {
		return nil, errors.New("kubectl output exceeded the size limit")
	}
	if runErr != nil {
		detail := pdSanitize(stderr.buffer.String(), 500)
		return nil, fmt.Errorf("kubectl get failed: %s", detail)
	}
	if !utf8.Valid(stdout.buffer.Bytes()) {
		return nil, errors.New("kubectl returned non-UTF-8 output")
	}
	var payload any
	if err := json.Unmarshal(stdout.buffer.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("kubectl returned invalid JSON: %s", pdSanitize(err.Error(), 200))
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// HTTP

func pdDefaultHTTPGet(config M, path string, timeout int) (int, []byte, error) {
	base, err := pdHTTPBaseURL(config["demo_url"], "demo_url")
	if err != nil {
		return 0, nil, err
	}
	if !strings.HasPrefix(path, "/") || pdPathHasDotDot(path) || strings.Contains(path, "://") {
		return 0, nil, errors.New("HTTP path is invalid")
	}
	transport := &http.Transport{}
	if !pdConfigBool(config, "use_proxy_env", true) {
		transport.Proxy = nil
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return 0, nil, errors.New("HTTP request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "change-guard-postdeploy/1")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP request failed: %T", err)
	}
	defer response.Body.Close()
	if length := response.Header.Get("Content-Length"); length != "" {
		if parsed, parseErr := strconv.ParseInt(length, 10, 64); parseErr == nil && parsed > pdMaxHTTPBytes {
			return 0, nil, errors.New("HTTP response exceeded the size limit")
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, pdMaxHTTPBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP request failed: %T", err)
	}
	if len(body) > pdMaxHTTPBytes {
		return 0, nil, errors.New("HTTP response exceeded the size limit")
	}
	return response.StatusCode, body, nil
}

func pdJSONBody(raw []byte) (M, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("HTTP response is not valid JSON")
	}
	var value M
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, errors.New("HTTP response is not valid JSON")
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// Checks

func pdGetArgo(config M, runner pdRunner) (any, error) {
	args := []string{
		"-n", pdString(config["argocd_namespace"]),
		"get", "application", pdString(config["argo_application"]),
		"-o", "json",
	}
	return runner(args, int(pdInt64Value(config["postdeploy_timeout_seconds"])))
}

func pdCheckArgo(config M, expectedSHA string, runner pdRunner) (M, error) {
	raw, err := pdGetArgo(config, runner)
	if err != nil {
		return nil, err
	}
	app, ok := raw.(map[string]any)
	if !ok {
		return pdCheckResult("argo", "fail", "Argo Application response is not an object", nil), nil
	}
	metadata := Obj(app["metadata"])
	if pdTruthy(metadata["deletionTimestamp"]) {
		return pdCheckResult("argo", "fail", "Argo Application is being deleted", nil), nil
	}
	status := Obj(app["status"])
	sync := Obj(status["sync"])
	health := Obj(status["health"])
	operation := Obj(status["operationState"])
	revision := sync["revision"]
	syncStatus := sync["status"]
	healthStatus := health["status"]
	phase := operation["phase"]
	evidence := M{
		"application":     config["argo_application"],
		"revision":        revision,
		"sync_status":     syncStatus,
		"health_status":   healthStatus,
		"operation_phase": phase,
	}
	var problems []string
	if pdString(revision) != expectedSHA {
		problems = append(problems, fmt.Sprintf("Argo sync revision %q != expected %q", pdShort(revision), pdShort(expectedSHA)))
	}
	if pdString(syncStatus) != "Synced" {
		problems = append(problems, fmt.Sprintf("Argo sync status is %q, not 'Synced'", pdString(syncStatus)))
	}
	if pdString(healthStatus) != "Healthy" {
		problems = append(problems, fmt.Sprintf("Argo health status is %q, not 'Healthy'", pdString(healthStatus)))
	}
	if phase != nil && pdString(phase) != "Succeeded" && pdString(phase) != "Running" {
		problems = append(problems, fmt.Sprintf("Argo operation phase is %q", pdString(phase)))
	}
	if len(problems) > 0 {
		return pdCheckResult("argo", "fail", strings.Join(problems, "; "), evidence), nil
	}
	return pdCheckResult("argo", "pass", "Argo is Synced/Healthy at the expected revision", evidence), nil
}

func pdShort(value any) string {
	text := pdString(value)
	if len(text) > 12 {
		return text[:12]
	}
	return text
}

func pdDeploymentContainers(deployment M) []M {
	spec := Obj(deployment["spec"])
	template := Obj(spec["template"])
	podSpec := Obj(template["spec"])
	var containers []M
	for _, item := range pdList(podSpec["containers"]) {
		if container, ok := item.(map[string]any); ok {
			containers = append(containers, container)
		}
	}
	return containers
}

func pdTargetContainer(containers []M, config M, expectedImage string) M {
	name, hasName := config["container_name"]
	if hasName && name != nil {
		for _, container := range containers {
			if pdString(container["name"]) == pdString(name) {
				return container
			}
		}
		return nil
	}
	if len(containers) == 1 {
		return containers[0]
	}
	var matching []M
	for _, container := range containers {
		if pdString(container["image"]) == expectedImage {
			matching = append(matching, container)
		}
	}
	if len(matching) == 1 {
		return matching[0]
	}
	return nil
}

func pdCheckDeployment(config M, expectedImage string, runner pdRunner) (M, error) {
	args := []string{
		"-n", pdString(config["namespace"]),
		"get", "deployment", pdString(config["deployment"]),
		"-o", "json",
	}
	raw, err := runner(args, int(pdInt64Value(config["postdeploy_timeout_seconds"])))
	if err != nil {
		return nil, err
	}
	deployment, ok := raw.(map[string]any)
	if !ok {
		return pdCheckResult("deployment", "fail", "Deployment response is not an object", nil), nil
	}
	metadata := Obj(deployment["metadata"])
	spec := Obj(deployment["spec"])
	status := Obj(deployment["status"])
	containers := pdDeploymentContainers(deployment)
	target := pdTargetContainer(containers, config, expectedImage)
	images := make([]any, 0, len(containers))
	for _, container := range containers {
		images = append(images, pdString(container["image"]))
	}
	if len(images) > 20 {
		images = images[:20]
	}
	replicas := int64(1)
	if rawReplicas, exists := spec["replicas"]; exists {
		parsed, valid := pdInteger(rawReplicas)
		if !valid || parsed < 1 {
			return pdCheckResult("deployment", "fail", "Deployment replicas is invalid", nil), nil
		}
		replicas = parsed
	}
	generation := metadata["generation"]
	observed := status["observedGeneration"]
	updated := status["updatedReplicas"]
	if updated == nil {
		updated = 0
	}
	ready := status["readyReplicas"]
	if ready == nil {
		ready = 0
	}
	available := status["availableReplicas"]
	if available == nil {
		available = 0
	}
	var targetName any
	if target != nil {
		targetName = target["name"]
	}
	evidence := M{
		"name":                metadata["name"],
		"namespace":           metadata["namespace"],
		"generation":          generation,
		"observed_generation": observed,
		"replicas":            replicas,
		"updated_replicas":    updated,
		"ready_replicas":      ready,
		"available_replicas":  available,
		"images":              images,
		"target_container":    targetName,
	}
	var problems []string
	if target == nil {
		problems = append(problems, "expected container/image was not found in the Deployment")
	} else if pdString(target["image"]) != expectedImage {
		problems = append(problems, "Deployment target container image does not equal the expected digest")
	}
	if generationInt, okGeneration := pdInteger(generation); okGeneration {
		if observedInt, okObserved := pdInteger(observed); okObserved && observedInt < generationInt {
			problems = append(problems, "Deployment observedGeneration has not caught up")
		}
	}
	for _, item := range []struct {
		label string
		value any
	}{
		{"updated", updated}, {"ready", ready}, {"available", available},
	} {
		parsed, valid := pdInteger(item.value)
		if !valid || parsed < replicas {
			problems = append(problems, fmt.Sprintf("Deployment %sReplicas is below desired replicas", item.label))
		}
	}
	if len(problems) > 0 {
		return pdCheckResult("deployment", "fail", strings.Join(problems, "; "), evidence), nil
	}
	return pdCheckResult("deployment", "pass", "Deployment image and replica status match", evidence), nil
}

func pdParseImageID(value any) (string, string) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", ""
	}
	text = strings.TrimSpace(text)
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		if strings.HasPrefix(text, prefix) {
			text = text[len(prefix):]
			break
		}
	}
	var repository, digest string
	if at := strings.LastIndex(text, "@"); at >= 0 {
		repository = text[:at]
		digest = text[at+1:]
	} else if strings.Contains(text, ":") && strings.Contains(text, "sha256:") {
		parts := strings.SplitN(text, "sha256:", 2)
		repository = strings.TrimSuffix(parts[0], "@")
		digest = "sha256:" + parts[1]
	}
	if digest != "" {
		digest = pdImageDigestPattern.FindString(digest)
	}
	repository = strings.TrimSpace(repository)
	if strings.HasSuffix(repository, ":") {
		repository = ""
	}
	return repository, digest
}

func pdCheckPods(config M, expectedImage string, runner pdRunner) (M, error) {
	args := []string{
		"-n", pdString(config["namespace"]),
		"get", "pods",
		"-l", pdString(config["pod_label_selector"]),
		"-o", "json",
	}
	raw, err := runner(args, int(pdInt64Value(config["postdeploy_timeout_seconds"])))
	if err != nil {
		return nil, err
	}
	payload, ok := raw.(map[string]any)
	if !ok {
		return pdCheckResult("pods", "fail", "Pod response is not an object", nil), nil
	}
	items := pdList(payload["items"])
	if len(items) == 0 {
		return pdCheckResult("pods", "fail", "no running Pod matched the deployment selector", nil), nil
	}
	expectedRepository := expectedImage
	expectedDigest := ""
	if at := strings.LastIndex(expectedImage, "@"); at >= 0 {
		expectedRepository = expectedImage[:at]
		expectedDigest = expectedImage[at+1:]
	}
	containerName, hasContainerName := config["container_name"]
	requireImageID := pdConfigBool(config, "require_pod_image_id", true)
	strictDigest := pdConfigBool(config, "strict_image_id_digest", false)
	var podSummaries []any
	var problems []string
	var digestCaveats []any
	for index, item := range items {
		if index >= 200 {
			break
		}
		pod, ok := item.(map[string]any)
		if !ok {
			continue
		}
		metadata := Obj(pod["metadata"])
		status := Obj(pod["status"])
		podSpec := Obj(pod["spec"])
		desiredContainers := map[string]string{}
		for _, containerItem := range pdList(podSpec["containers"]) {
			container, ok := containerItem.(map[string]any)
			if !ok {
				continue
			}
			desiredContainers[pdString(container["name"])] = pdString(container["image"])
		}
		if pdTruthy(metadata["deletionTimestamp"]) {
			problems = append(problems, fmt.Sprintf("Pod %s is terminating", pdString(metadata["name"])))
			continue
		}
		if pdString(status["phase"]) != "Running" {
			problems = append(problems, fmt.Sprintf("Pod %s phase is %q", pdString(metadata["name"]), pdString(status["phase"])))
		}
		ready := false
		for _, conditionItem := range pdList(status["conditions"]) {
			condition, ok := conditionItem.(map[string]any)
			if !ok {
				continue
			}
			if pdString(condition["type"]) == "Ready" && strings.ToLower(pdString(condition["status"])) == "true" {
				ready = true
			}
		}
		if !ready {
			problems = append(problems, fmt.Sprintf("Pod %s is not Ready", pdString(metadata["name"])))
		}
		targetReady := false
		targetImageOK := false
		for _, containerItem := range pdList(status["containerStatuses"]) {
			containerStatus, ok := containerItem.(map[string]any)
			if !ok {
				continue
			}
			name := pdString(containerStatus["name"])
			image := containerStatus["image"]
			desiredImage, hasDesired := desiredContainers[name]
			if !pdTruthy(containerStatus["ready"]) {
				problems = append(problems, fmt.Sprintf("Pod %s container %s is not ready", pdString(metadata["name"]), name))
			}
			isTarget := false
			if hasContainerName && containerName != nil {
				isTarget = name == pdString(containerName)
			} else if !hasContainerName || containerName == nil {
				isTarget = hasDesired && desiredImage == expectedImage
			}
			if isTarget {
				targetReady = pdTruthy(containerStatus["ready"])
				targetImageOK = hasDesired && desiredImage == expectedImage
				if !targetImageOK {
					problems = append(problems, fmt.Sprintf("Pod %s spec image differs from expected", pdString(metadata["name"])))
				}
				repository, digest := pdParseImageID(containerStatus["imageID"])
				if requireImageID && digest == "" {
					problems = append(problems, fmt.Sprintf("Pod %s has no verifiable imageID digest", pdString(metadata["name"])))
				} else if digest != "" {
					if repository != "" && repository != expectedRepository {
						problems = append(problems, fmt.Sprintf("Pod %s imageID repository differs from expected", pdString(metadata["name"])))
					}
					if expectedDigest != "" && digest != expectedDigest {
						short := digest
						if len(short) > 19 {
							short = short[:19]
						}
						caveat := fmt.Sprintf("Pod %s imageID digest %s... differs from the manifest digest; "+
							"this is expected for some multi-arch/config image IDs", pdString(metadata["name"]), short)
						digestCaveats = append(digestCaveats, caveat)
						if strictDigest {
							problems = append(problems, caveat)
						}
					}
				}
				var runtimeImage any
				if image != nil {
					runtimeImage = image
				}
				var imageID any
				if containerStatus["imageID"] != nil {
					imageID = containerStatus["imageID"]
				}
				var digestValue any
				if digest != "" {
					digestValue = digest
				}
				podSummaries = append(podSummaries, M{
					"name":            metadata["name"],
					"node":            Obj(pod["spec"])["nodeName"],
					"ready":           ready,
					"container":       name,
					"image":           desiredImage,
					"runtime_image":   runtimeImage,
					"image_id":        imageID,
					"image_id_digest": digestValue,
				})
			}
		}
		if (!hasContainerName || containerName == nil) && !targetImageOK {
			problems = append(problems, fmt.Sprintf("Pod %s does not run the expected image", pdString(metadata["name"])))
		}
		if hasContainerName && containerName != nil && !targetReady {
			problems = append(problems, fmt.Sprintf("Pod %s target container is not ready", pdString(metadata["name"])))
		}
	}
	if len(podSummaries) > 100 {
		podSummaries = podSummaries[:100]
	}
	if len(digestCaveats) > 20 {
		digestCaveats = digestCaveats[:20]
	}
	evidence := M{
		"pod_count":      len(items),
		"pods":           podSummaries,
		"digest_caveats": digestCaveats,
	}
	if len(problems) > 0 {
		if len(problems) > 10 {
			problems = problems[:10]
		}
		return pdCheckResult("pods", "fail", strings.Join(problems, "; "), evidence), nil
	}
	return pdCheckResult("pods", "pass", "running Pods are ready and run the expected image", evidence), nil
}

func pdCheckEndpoints(config M, runner pdRunner) (M, error) {
	args := []string{
		"-n", pdString(config["namespace"]),
		"get", "endpoints", pdString(config["deployment"]),
		"-o", "json",
	}
	raw, err := runner(args, int(pdInt64Value(config["postdeploy_timeout_seconds"])))
	if err != nil {
		return nil, err
	}
	endpoints, ok := raw.(map[string]any)
	if !ok {
		return pdCheckResult("endpoints", "fail", "Endpoints response is not an object", nil), nil
	}
	var readyAddresses []any
	var notReady []any
	for _, subsetItem := range pdList(endpoints["subsets"]) {
		subset, ok := subsetItem.(map[string]any)
		if !ok {
			continue
		}
		for _, addressItem := range pdList(subset["addresses"]) {
			if address, ok := addressItem.(map[string]any); ok && pdString(address["ip"]) != "" {
				readyAddresses = append(readyAddresses, address["ip"])
			}
		}
		for _, addressItem := range pdList(subset["notReadyAddresses"]) {
			if address, ok := addressItem.(map[string]any); ok && pdString(address["ip"]) != "" {
				notReady = append(notReady, address["ip"])
			}
		}
	}
	addresses := readyAddresses
	if len(addresses) > 20 {
		addresses = addresses[:20]
	}
	evidence := M{
		"ready_addresses":     len(readyAddresses),
		"not_ready_addresses": len(notReady),
		"addresses":           addresses,
	}
	if len(readyAddresses) == 0 {
		return pdCheckResult("endpoints", "fail", "Service has no ready endpoint addresses", evidence), nil
	}
	return pdCheckResult("endpoints", "pass", "Service has ready endpoint addresses", evidence), nil
}

func pdCheckHTTP(config M, expectedAppSHA string, getter pdHTTPGet) (M, error) {
	timeout := int(pdInt64Value(config["postdeploy_timeout_seconds"]))
	versionPath := pdString(config["version_path"])
	status, raw, err := getter(versionPath, timeout)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return pdCheckResult("http_version", "fail", fmt.Sprintf("GET %s returned HTTP %d", versionPath, status), nil), nil
	}
	body, err := pdJSONBody(raw)
	if err != nil {
		return pdCheckResult("http_version", "fail", "version response is not a JSON object", nil), nil
	}
	gitSHA := body["gitSha"]
	if gitSHA == nil {
		gitSHA = body["git_sha"]
	}
	var gitSHAValue any
	if text, ok := gitSHA.(string); ok {
		gitSHAValue = text
	}
	evidence := M{
		"status":  status,
		"gitSha":  gitSHAValue,
		"version": pdSanitize(pdString(body["version"]), 100),
	}
	if pdString(gitSHA) == "" || strings.ToLower(pdString(gitSHA)) != strings.ToLower(expectedAppSHA) {
		return pdCheckResult("http_version", "fail", "HTTP /version gitSha does not equal the desired release commit", evidence), nil
	}
	readyPath := pdString(config["ready_path"])
	readyStatus, _, err := getter(readyPath, timeout)
	if err != nil {
		return nil, err
	}
	if readyStatus != http.StatusOK {
		return pdCheckResult("http_version", "fail", fmt.Sprintf("GET %s returned HTTP %d", readyPath, readyStatus), M{"status": readyStatus}), nil
	}
	return pdCheckResult("http_version", "pass", "HTTP /version provenance and readiness endpoints are healthy", evidence), nil
}

func pdCheckMetrics(config M, provider pdMetricsProvider, observationSeconds int) (M, error) {
	evidence := provider(Clone(config))
	if evidence == nil {
		return pdCheckResult("metrics", "fail", "metrics provider returned an invalid result", nil), nil
	}
	metrics := Obj(evidence["metrics"])
	var errorsFound []string
	for _, item := range pdList(evidence["errors"]) {
		switch typed := item.(type) {
		case string:
			errorsFound = append(errorsFound, typed)
		case float64:
			errorsFound = append(errorsFound, strconv.FormatFloat(typed, 'f', -1, 64))
		case int:
			errorsFound = append(errorsFound, strconv.Itoa(typed))
		case int64:
			errorsFound = append(errorsFound, strconv.FormatInt(typed, 10))
		}
	}
	requestRate, requestOK := pdNumberFinite(metrics["request_rate"])
	errorRatio, errorOK := pdNumberFinite(metrics["error_ratio"])
	p95, p95OK := pdNumberFinite(metrics["p95_seconds"])
	var firing []any
	for _, alertItem := range pdList(metrics["alerts"]) {
		alert, ok := alertItem.(map[string]any)
		if !ok {
			continue
		}
		state := strings.ToLower(pdString(alert["state"]))
		if state != "firing" && state != "active" {
			continue
		}
		labels := Obj(alert["labels"])
		relevant := pdString(labels["namespace"]) == pdString(config["namespace"]) ||
			pdString(labels["deployment"]) == pdString(config["deployment"])
		if relevant {
			firing = append(firing, M{"name": alert["name"], "state": state, "labels": labels})
		}
	}
	if len(firing) > 20 {
		firing = firing[:20]
	}
	sourceErrors := make([]any, 0, len(errorsFound))
	for _, item := range errorsFound {
		sourceErrors = append(sourceErrors, item)
	}
	if len(sourceErrors) > 20 {
		sourceErrors = sourceErrors[:20]
	}
	var requestValue, ratioValue, p95Value any
	if requestOK {
		requestValue = requestRate
	}
	if errorOK {
		ratioValue = errorRatio
	}
	if p95OK {
		p95Value = p95
	}
	observation := M{
		"window_seconds": observationSeconds,
		"request_rate":   requestValue,
		"error_ratio":    ratioValue,
		"p95_seconds":    p95Value,
		"firing_alerts":  firing,
		"source_errors":  sourceErrors,
		"collected_at":   evidence["collected_at"],
	}
	var problems []string
	if len(errorsFound) > 0 {
		limit := len(errorsFound)
		if limit > 3 {
			limit = 3
		}
		problems = append(problems, strings.Join(errorsFound[:limit], "; "))
	}
	minRate := pdNumValue(config["min_request_rate"])
	if !requestOK || requestRate < minRate {
		problems = append(problems, "positive request traffic was not observed")
	}
	if !errorOK {
		problems = append(problems, "error ratio could not be measured")
	} else if errorRatio > pdNumValue(config["max_error_ratio"]) {
		problems = append(problems, "error ratio exceeds the configured maximum")
	}
	if !p95OK {
		problems = append(problems, "p95 latency could not be measured")
	} else if p95 > pdNumValue(config["max_p95_seconds"]) {
		problems = append(problems, "p95 latency exceeds the configured maximum")
	}
	if len(firing) > 0 {
		problems = append(problems, "relevant Prometheus alerts are firing")
	}
	if len(problems) > 0 {
		if len(problems) > 6 {
			problems = problems[:6]
		}
		return pdCheckResult("metrics", "fail", strings.Join(problems, "; "), observation), nil
	}
	return pdCheckResult("metrics", "pass", "observation window shows positive traffic within SLO bounds", observation), nil
}

// ---------------------------------------------------------------------------
// Results

func pdFailureResult(expectedSHA, expectedAppSHA, expectedImage string, checks []M, startedAt, finishedAt int64) M {
	var failing []M
	var reasonParts []string
	var failingNames []any
	for _, check := range checks {
		if Str(check["status"]) == "pass" {
			continue
		}
		failing = append(failing, check)
		failingNames = append(failingNames, check["name"])
		if len(reasonParts) < 8 {
			reasonParts = append(reasonParts, fmt.Sprintf("%s: %s", Str(check["name"]), Str(check["detail"])))
		}
	}
	reason := strings.Join(reasonParts, "; ")
	if reason == "" {
		reason = "post-deployment verification failed"
	}
	return M{
		"schema_version":   pdSchemaVersion,
		"verifier":         pdPostDeployVerifierName,
		"status":           "failed",
		"expected_sha":     expectedSHA,
		"expected_app_sha": expectedAppSHA,
		"expected_image":   expectedImage,
		"checks":           checks,
		"recommendation": M{
			"action":         "open_revert_pr",
			"reason":         pdSanitize(reason, 2000),
			"failing_checks": failingNames,
			"note":           pdPostDeployRecommendationNo,
		},
		"started_at":  startedAt,
		"finished_at": finishedAt,
	}
}

func pdErrorResult(err error, startedAt int64) M {
	return M{
		"schema_version": pdSchemaVersion,
		"verifier":       pdPostDeployVerifierName,
		"status":         "error",
		"error":          pdSanitize(err.Error(), 1000),
		"started_at":     startedAt,
	}
}
