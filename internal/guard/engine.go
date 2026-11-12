package guard

// Fail-closed risk evaluation over rendered Kubernetes resources.
//
// This is the Go port of change_guard.engine from the Python 0.2.3 baseline.
// The engine deliberately knows nothing about Helm values files. Callers pass
// complete old/new rendered object lists, current Prometheus/Kubernetes
// evidence, config, PR context, and (optionally) the DeepSeek result.
//
// Decision priority is BLOCK > ERROR > REVIEW > PASS. A model failure is an
// ERROR and can never weaken a hard BLOCK. Model-added risks are capped at
// REVIEW.
//
// Private identifiers in this file are prefixed with "eng" so that every
// module in package guard can add helpers without collisions.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	engSchemaVersion               = "1.0"
	engDefaultNamespace            = "demo"
	engDefaultDeployment           = "demo"
	engDefaultAllowedImageRepo     = "ghcr.io/hey-mmm/observability-demo"
	engDefaultEvidenceTTL          = 300
	engDefaultLowTrafficRPS        = 0.1
	engDefaultMaxErrorRatio        = 0.05
	engDefaultMaxP95Seconds        = 0.5
	engDefaultMemoryHeadroomFactor = 1.25
	engClockSkewToleranceSeconds   = 120
	engDefaultContainerName        = "demo-service"
	engMaxDiffEntriesPerResource   = 1000
	engMaxTotalChanges             = 2000
	engInputErrorTTL               = 300
	engInvalidInputRule            = "INVALID_INPUT"
	engDefaultNodeSurgePercent     = 25.0
	engChangeOperationAdd          = "add"
	engChangeOperationRemove       = "remove"
	engChangeOperationReplace      = "replace"
	engDecisionBlock               = "BLOCK"
	engDecisionError               = "ERROR"
	engDecisionReview              = "REVIEW"
	engDecisionPass                = "PASS"
)

var (
	engSeverityRank = map[string]int{
		engDecisionBlock:  3,
		engDecisionError:  2,
		engDecisionReview: 1,
	}
	engFaultEnvNames = map[string]bool{
		"DEMO_ERROR_RATE":   true,
		"DEMO_LATENCY_MS":   true,
		"DEMO_STARTUP_FAIL": true,
	}
	engAllowedExecProbeCommands = map[string]bool{
		"\x00/bin/true":     true,
		"\x00/usr/bin/true": true,
		"\x00true":          true,
	}
	engSensitiveVolumeSources = []string{"secret", "projected", "configMap"}
	engClusterScopedKinds     = map[string]bool{
		"Namespace": true, "Node": true, "PersistentVolume": true,
		"StorageClass": true, "CustomResourceDefinition": true,
		"ClusterRole": true, "ClusterRoleBinding": true, "IngressClass": true,
		"PriorityClass": true, "MutatingWebhookConfiguration": true,
		"ValidatingWebhookConfiguration": true, "PodSecurityPolicy": true,
		"RuntimeClass": true, "VolumeAttachment": true, "APIService": true,
	}
	engForbiddenWorkloadKinds = map[string]bool{
		"Pod": true, "DaemonSet": true, "StatefulSet": true, "Job": true,
		"CronJob": true, "ReplicaSet": true, "ReplicationController": true,
	}
	engExposureKinds = map[string]bool{
		"Ingress": true, "Gateway": true, "HTTPRoute": true, "TCPRoute": true,
		"TLSRoute": true, "VirtualService": true, "Route": true,
	}
	engArgoKinds = map[string]bool{
		"Application": true, "AppProject": true, "ApplicationSet": true,
	}
	engAllowedKinds = map[string]bool{
		"Deployment": true, "Service": true, "ServiceMonitor": true,
	}
	engSensitivePathParts = []string{
		"secret", "password", "passwd", "token", "authorization",
		"credential", "privatekey", "api_key", "apikey",
	}
	engDNSLabelRE    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	engEnvNameRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	engDigestRE      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	engQuantityRE    = regexp.MustCompile(`^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z]*)$`)
	engEnvValuePath  = regexp.MustCompile(`\.env\[\d+\]\.value$`)
	engEnvEntryPath  = regexp.MustCompile(`\.env\[\d+\]$`)
	engNonNegativeRE = regexp.MustCompile(`^[0-9]+$`)
)

// engMissing is a unique sentinel distinguishing a missing map key from an
// explicit JSON null (nil).
type engMissing struct{}

var engMissingValue = engMissing{}

func engIsMissing(v any) bool {
	_, ok := v.(engMissing)
	return ok
}

// ---------------------------------------------------------------------------
// Generic helpers

func engAsMap(v any) (M, bool) {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m, true
	}
	return nil, false
}

func engAsList(v any) ([]any, bool) {
	switch list := v.(type) {
	case []any:
		return list, true
	case []M:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out, true
	case []string:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out, true
	case []int:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out, true
	}
	return nil, false
}

func engJSONSafe(value any) any { return engJSONSafeDepth(value, 0) }

func engJSONSafeDepth(value any, depth int) any {
	if depth > 30 {
		return "<depth-limit>"
	}
	switch v := value.(type) {
	case nil:
		return nil
	case string, bool, int, int64, int32, uint, uint64:
		return v
	case json.Number:
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "<non-finite>"
		}
		return v
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "<non-finite>"
		}
		return f
	case []byte:
		return "<bytes>"
	case map[string]any:
		out := M{}
		for key, child := range v {
			out[key] = engJSONSafeDepth(child, depth+1)
		}
		return out
	case map[string]string:
		out := M{}
		for key, child := range v {
			out[key] = child
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = engJSONSafeDepth(child, depth+1)
		}
		return out
	case []M:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = engJSONSafeDepth(child, depth+1)
		}
		return out
	case []string:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = child
		}
		return out
	case time.Time:
		return v.Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(v)
	}
}

func engCanonicalJSON(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(engJSONSafe(value)); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func engDigestResources(resources []M) string {
	safe := make([]M, len(resources))
	for i, resource := range resources {
		converted, ok := engJSONSafe(resource).(M)
		if !ok {
			converted = M{}
		}
		safe[i] = converted
	}
	sort.SliceStable(safe, func(i, j int) bool {
		left, _ := engCanonicalJSON(safe[i])
		right, _ := engCanonicalJSON(safe[j])
		return left < right
	})
	encoded, err := engCanonicalJSON(safe)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(sum[:])
}

func engTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case uint, uint64:
		return v != 0
	case float32:
		return v != 0
	case float64:
		return v != 0
	case json.Number:
		f, err := v.Float64()
		return err == nil && f != 0
	case []any:
		return len(v) > 0
	case []M:
		return len(v) > 0
	case []string:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	case map[string]string:
		return len(v) > 0
	}
	return true
}

// engOr implements Python's "a or b" for the value shapes used by the engine.
func engOr(first, second any) any {
	if engTruthy(first) {
		return first
	}
	return second
}

func engPyStr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return v
	case bool:
		if v {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint, uint64:
		return fmt.Sprint(v)
	case float32:
		return engPyFloatStr(float64(v))
	case float64:
		return engPyFloatStr(v)
	case json.Number:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func engPyFloatStr(value float64) string {
	if math.IsNaN(value) {
		return "nan"
	}
	if math.IsInf(value, 1) {
		return "inf"
	}
	if math.IsInf(value, -1) {
		return "-inf"
	}
	if value == math.Trunc(value) && math.Abs(value) < 1e16 {
		return strconv.FormatFloat(value, 'f', -1, 64) + ".0"
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}

// engNumber mirrors _number: bools and non-finite/non-numeric input yield no
// value. Numeric strings are accepted.
func engNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case nil, bool:
		return 0, false
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case json.Number:
		f, err := v.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, false
		}
		switch strings.ToLower(text) {
		case "nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity":
			return 0, false
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// engFloatStrict accepts only numeric JSON/YAML types (not strings or bools).
func engFloatStrict(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case json.Number:
		f, err := v.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// engInt mirrors Python's isinstance(value, int) with the necessary Go
// allowance for integral JSON float64 values.
func engInt(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case uint64:
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case float32:
		return engFloatInt(float64(v))
	case float64:
		return engFloatInt(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil {
			return engFloatInt(f)
		}
	}
	return 0, false
}

func engFloatInt(value float64) (int64, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) {
		return 0, false
	}
	if value < -9223372036854775808.0 || value > 9223372036854775807.0 {
		return 0, false
	}
	return int64(value), true
}

func engIsTrueIdentity(value any) bool {
	b, ok := value.(bool)
	return ok && b
}

func engIsFalseIdentity(value any) bool {
	b, ok := value.(bool)
	return ok && !b
}

// engIsZero matches Python's "value == 0" for scalar values (notably False == 0).
func engIsZero(value any) bool {
	switch v := value.(type) {
	case bool:
		return !v
	case int:
		return v == 0
	case int32:
		return v == 0
	case int64:
		return v == 0
	case uint, uint64:
		return v == 0
	case float32:
		return v == 0
	case float64:
		return v == 0
	case json.Number:
		f, err := v.Float64()
		return err == nil && f == 0
	}
	return false
}

func engPyEqual(left, right any) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if ln, ok := engFloatStrict(left); ok {
		rn, ok := engFloatStrict(right)
		return ok && ln == rn
	}
	switch lv := left.(type) {
	case string:
		rv, ok := right.(string)
		return ok && lv == rv
	case bool:
		rv, ok := right.(bool)
		return ok && lv == rv
	}
	return false
}

func engPyIn(value any, options ...any) bool {
	for _, option := range options {
		if engPyEqual(value, option) {
			return true
		}
	}
	return false
}

// engStringIs compares an arbitrary decoded JSON value with a string without
// panicking. Python's "value == 'literal'" is always safe even when value is a
// list or mapping; Go interface comparison would panic on those types.
func engStringIs(value any, expected string) bool {
	text, ok := value.(string)
	return ok && text == expected
}

func engTruncate(value string, limit int, suffix string) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	keep := limit - len([]rune(suffix))
	if keep < 0 {
		keep = 0
	}
	return string(runes[:keep]) + suffix
}

func engTimestamp(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case bool:
		return 0, false
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, false
		}
		if f, err := strconv.ParseFloat(text, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			if f > 100_000_000_000 {
				f /= 1000.0
			}
			return f, true
		}
		parsed, ok := engParseISOTime(text)
		if !ok {
			return 0, false
		}
		f := float64(parsed.UnixNano()) / 1e9
		if f > 100_000_000_000 {
			f /= 1000.0
		}
		return f, true
	default:
		f, ok := engNumber(v)
		if !ok {
			return 0, false
		}
		if f > 100_000_000_000 {
			f /= 1000.0
		}
		return f, true
	}
}

func engParseISOTime(text string) (time.Time, bool) {
	normalized := strings.Replace(text, "Z", "+00:00", 1)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, normalized); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func engParseQuantity(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case bool:
		return 0, false
	case int, int32, int64, uint, uint64, float32, float64, json.Number:
		return engNumber(v)
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, false
		}
		match := engQuantityRE.FindStringSubmatch(text)
		if match == nil {
			return 0, false
		}
		numeric, err := strconv.ParseFloat(match[1], 64)
		if err != nil || math.IsNaN(numeric) || math.IsInf(numeric, 0) {
			return 0, false
		}
		multipliers := map[string]float64{
			"": 1, "n": 1e-9, "u": 1e-6, "m": 1e-3,
			"k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12,
			"P": 1e15, "E": 1e18,
			"Ki": 1024.0, "Mi": 1024.0 * 1024.0, "Gi": 1024.0 * 1024.0 * 1024.0,
			"Ti": 1024.0 * 1024.0 * 1024.0 * 1024.0,
			"Pi": 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
			"Ei": 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
			"mK": 1.0,
		}
		multiplier, ok := multipliers[match[2]]
		if !ok {
			return 0, false
		}
		candidate := numeric * multiplier
		if math.IsNaN(candidate) || math.IsInf(candidate, 0) {
			return 0, false
		}
		return candidate, true
	}
	return 0, false
}

func engCPUMillicores(value any) (float64, bool) {
	parsed, ok := engParseQuantity(value)
	if !ok {
		return 0, false
	}
	return parsed * 1000.0, true
}

func engMemoryBytes(value any) (float64, bool) {
	return engParseQuantity(value)
}

// ---------------------------------------------------------------------------
// Resource and metric helpers

type engKey struct {
	kind      string
	namespace string
	name      string
}

func engResourceKey(resource M, defaultNamespace string) engKey {
	kind := engPyStr(resource["kind"])
	metadata, _ := engAsMap(resource["metadata"])
	name := engPyStr(metadata["name"])
	namespace := ""
	if raw, ok := metadata["namespace"]; ok {
		if engTruthy(raw) {
			namespace = engPyStr(raw)
		}
	}
	if namespace == "" && !engClusterScopedKinds[kind] {
		namespace = defaultNamespace
	}
	return engKey{kind: kind, namespace: namespace, name: name}
}

func engFlattenResources(resources []M) ([]M, error) {
	output := make([]M, 0, len(resources))
	var add func(item any) error
	add = func(item any) error {
		resource, ok := engAsMap(item)
		if !ok || resource == nil {
			return errors.New("rendered resources must be mappings")
		}
		if kind, ok := resource["kind"].(string); ok && kind == "List" {
			children, ok := engAsList(resource["items"])
			if !ok {
				return errors.New("rendered List must contain items")
			}
			for _, child := range children {
				if err := add(child); err != nil {
					return err
				}
			}
			return nil
		}
		kind, ok := resource["kind"].(string)
		if !ok || kind == "" {
			return errors.New("rendered resource is missing kind")
		}
		metadata, ok := engAsMap(resource["metadata"])
		if !ok {
			return errors.New("rendered resource is missing metadata.name")
		}
		name, ok := metadata["name"].(string)
		if !ok || name == "" {
			return errors.New("rendered resource is missing metadata.name")
		}
		output = append(output, resource)
		return nil
	}
	for _, resource := range resources {
		if err := add(resource); err != nil {
			return nil, err
		}
	}
	return output, nil
}

func engIndexResources(resources []M, config M) map[engKey][]M {
	namespace := engPyStr(config["namespace"])
	index := map[engKey][]M{}
	for _, resource := range resources {
		key := engResourceKey(resource, namespace)
		index[key] = append(index[key], resource)
	}
	return index
}

func engTargetResource(index map[engKey][]M, kind, namespace, name string) M {
	entries := index[engKey{kind: kind, namespace: namespace, name: name}]
	if len(entries) == 0 {
		return nil
	}
	return entries[0]
}

func engPodSpec(deployment M) M {
	if deployment == nil {
		return M{}
	}
	spec, ok := engAsMap(deployment["spec"])
	if !ok {
		return M{}
	}
	template, ok := engAsMap(spec["template"])
	if !ok {
		return M{}
	}
	podSpec, ok := engAsMap(template["spec"])
	if !ok {
		return M{}
	}
	return podSpec
}

func engContainers(deployment M) []M {
	return engPodContainers(engPodSpec(deployment), "containers")
}

func engInitContainers(deployment M) []M {
	return engPodContainers(engPodSpec(deployment), "initContainers")
}

func engPodContainers(podSpec M, field string) []M {
	list, ok := engAsList(podSpec[field])
	if !ok {
		return nil
	}
	out := make([]M, 0, len(list))
	for _, item := range list {
		if container, ok := engAsMap(item); ok {
			out = append(out, container)
		}
	}
	return out
}

func engReplicas(deployment M, fallback int64) (int64, bool) {
	if deployment == nil {
		return 0, false
	}
	spec, ok := engAsMap(deployment["spec"])
	if !ok {
		return 0, false
	}
	value, present := spec["replicas"]
	if !present {
		value = fallback
	}
	replicas, ok := engInt(value)
	if !ok || replicas < 0 {
		return 0, false
	}
	return replicas, true
}

type engParser func(any) (float64, bool)

func engPodRequestsFromSpec(podSpec M, quantity string, parser engParser, section string) (float64, int, int) {
	invalid := 0
	unreserved := 0
	containerValue := func(container M) any {
		resources, ok := engAsMap(container["resources"])
		if !ok {
			return nil
		}
		values, ok := engAsMap(resources[section])
		if !ok {
			return nil
		}
		return values[quantity]
	}
	sumContainers := func(items any) float64 {
		list, ok := engAsList(items)
		if !ok {
			return 0
		}
		subtotal := 0.0
		for _, item := range list {
			container, ok := engAsMap(item)
			if !ok {
				invalid++
				continue
			}
			raw := containerValue(container)
			if raw == nil {
				unreserved++
				continue
			}
			parsed, ok := parser(raw)
			if !ok {
				invalid++
				continue
			}
			subtotal += parsed
		}
		return subtotal
	}
	regular := sumContainers(podSpec["containers"])
	initMax := 0.0
	if list, ok := engAsList(podSpec["initContainers"]); ok {
		for _, item := range list {
			container, ok := engAsMap(item)
			if !ok {
				invalid++
				continue
			}
			raw := containerValue(container)
			if raw == nil {
				unreserved++
				continue
			}
			parsed, ok := parser(raw)
			if !ok {
				invalid++
				continue
			}
			initMax = math.Max(initMax, parsed)
		}
	}
	overheadValue := 0.0
	if overhead, ok := engAsMap(podSpec["overhead"]); ok {
		if raw, present := overhead[quantity]; present && raw != nil {
			parsed, ok := parser(raw)
			if !ok {
				invalid++
			} else {
				overheadValue = parsed
			}
		}
	}
	total := math.Max(regular, initMax) + overheadValue
	return total, invalid, unreserved
}

func engPodTotals(deployment M, quantity string, parser engParser) (float64, bool, bool) {
	podSpec := engPodSpec(deployment)
	list, ok := engAsList(podSpec["containers"])
	if !ok || len(list) == 0 {
		return 0, false, false
	}
	value, invalid, unreserved := engPodRequestsFromSpec(podSpec, quantity, parser, "limits")
	return value, true, invalid == 0 && unreserved == 0
}

func engPodResources(deployment M) M {
	podSpec := engPodSpec(deployment)
	cpuRequest, cpuInvalid, cpuUnreserved := engPodRequestsFromSpec(podSpec, "cpu", engCPUMillicores, "requests")
	memRequest, memInvalid, memUnreserved := engPodRequestsFromSpec(podSpec, "memory", engMemoryBytes, "requests")
	cpuLimit, _, cpuLimitComplete := engPodTotals(deployment, "cpu", engCPUMillicores)
	memLimit, _, memLimitComplete := engPodTotals(deployment, "memory", engMemoryBytes)
	return M{
		"cpu_request_millicores":               cpuRequest,
		"memory_request_bytes":                 memRequest,
		"cpu_limit_millicores":                 cpuLimit,
		"memory_limit_bytes":                   memLimit,
		"cpu_request_invalid_containers":       cpuInvalid,
		"memory_request_invalid_containers":    memInvalid,
		"cpu_request_unreserved_containers":    cpuUnreserved,
		"memory_request_unreserved_containers": memUnreserved,
		"cpu_request_missing_containers":       cpuInvalid,
		"memory_request_missing_containers":    memInvalid,
		"cpu_limit_complete":                   cpuLimitComplete,
		"memory_limit_complete":                memLimitComplete,
	}
}

func engStrategySurge(deployment M, replicas int64) (int64, bool) {
	var spec M
	if deployment != nil {
		spec, _ = engAsMap(deployment["spec"])
	}
	strategy, strategyOK := engAsMap(spec["strategy"])
	if !strategyOK {
		return int64(math.Ceil(float64(replicas) * engDefaultNodeSurgePercent / 100.0)), true
	}
	strategyType := any("RollingUpdate")
	if value, present := strategy["type"]; present {
		// dict.get("type", "RollingUpdate") keeps an explicit null/empty value;
		// treating it as the default would hide an invalid strategy.
		strategyType = value
	}
	if engStringIs(strategyType, "Recreate") {
		return 0, true
	}
	if !engStringIs(strategyType, "RollingUpdate") {
		return 0, false
	}
	rolling, ok := engAsMap(strategy["rollingUpdate"])
	if !ok {
		return int64(math.Ceil(float64(replicas) * engDefaultNodeSurgePercent / 100.0)), true
	}
	raw, present := rolling["maxSurge"]
	if !present {
		raw = "25%"
	}
	switch value := raw.(type) {
	case bool:
		return 0, false
	case string:
		if strings.HasSuffix(value, "%") {
			percent, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
			if err != nil || math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 {
				return 0, false
			}
			return int64(math.Ceil(float64(replicas) * percent / 100.0)), true
		}
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, false
		}
		if parsed < 0 {
			return 0, false
		}
		return parsed, true
	default:
		parsed, ok := engInt(raw)
		if !ok || parsed < 0 {
			return 0, false
		}
		return parsed, true
	}
}

// ---------------------------------------------------------------------------
// Diff + redaction

func engIsSensitivePath(path, kind string) bool {
	lowered := strings.ToLower(path)
	for _, part := range engSensitivePathParts {
		if strings.Contains(lowered, part) {
			return true
		}
	}
	if kind == "Secret" && (strings.Contains(lowered, ".data") || strings.Contains(lowered, ".stringdata")) {
		return true
	}
	// Do not echo arbitrary environment values into an audit/report artifact.
	return engEnvValuePath.MatchString(lowered)
}

func engSafeDiffValue(value any, path, kind string) any {
	if engIsMissing(value) {
		return nil
	}
	if engIsSensitivePath(path, kind) {
		return "<redacted>"
	}
	lowered := strings.ToLower(path)
	if mapping, ok := engAsMap(value); ok && engEnvEntryPath.MatchString(lowered) {
		// Adding/removing an env list entry must not echo its literal value.
		sanitized := engJSONSafe(mapping)
		if safeMap, ok := sanitized.(M); ok {
			if _, present := safeMap["value"]; present {
				safeMap["value"] = "<redacted>"
			}
			if _, present := safeMap["valueFrom"]; present {
				safeMap["valueFrom"] = "<redacted>"
			}
			return safeMap
		}
	}
	if text, ok := value.(string); ok {
		return engTruncate(text, 800, "...")
	}
	if number, ok := value.(float64); ok && (math.IsNaN(number) || math.IsInf(number, 0)) {
		return "<non-finite>"
	}
	if mapping, ok := engAsMap(value); ok {
		encoded, err := engCanonicalJSON(mapping)
		if err != nil {
			return "<unserializable>"
		}
		return engTruncate(encoded, 1500, "...")
	}
	if list, ok := engAsList(value); ok {
		encoded, err := engCanonicalJSON(list)
		if err != nil {
			return "<unserializable>"
		}
		return engTruncate(encoded, 1500, "...")
	}
	return engJSONSafe(value)
}

func engDiffValues(old, new any, path string, output *[]M, kind string, limit int) {
	if len(*output) >= limit {
		return
	}
	if engIsMissing(old) || engIsMissing(new) {
		operation := engChangeOperationAdd
		if engIsMissing(old) {
			operation = engChangeOperationAdd
		} else {
			operation = engChangeOperationRemove
		}
		*output = append(*output, M{
			"path":         path,
			"operation":    operation,
			"old":          engSafeDiffValue(old, path, kind),
			"new":          engSafeDiffValue(new, path, kind),
			"pod_template": strings.HasPrefix(path, "spec.template"),
		})
		return
	}
	oldMap, oldIsMap := engAsMap(old)
	newMap, newIsMap := engAsMap(new)
	if oldIsMap && newIsMap {
		seen := map[string]bool{}
		keys := make([]string, 0, len(oldMap)+len(newMap))
		for key := range oldMap {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
		for key := range newMap {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			oldChild, oldPresent := oldMap[key]
			if !oldPresent {
				oldChild = engMissingValue
			}
			newChild, newPresent := newMap[key]
			if !newPresent {
				newChild = engMissingValue
			}
			engDiffValues(oldChild, newChild, childPath, output, kind, limit)
			if len(*output) >= limit {
				return
			}
		}
		return
	}
	oldList, oldIsList := engAsList(old)
	newList, newIsList := engAsList(new)
	if oldIsList && newIsList {
		length := len(oldList)
		if len(newList) > length {
			length = len(newList)
		}
		for index := 0; index < length; index++ {
			childPath := fmt.Sprintf("[%d]", index)
			if path != "" {
				childPath = fmt.Sprintf("%s[%d]", path, index)
			}
			oldChild := any(engMissingValue)
			if index < len(oldList) {
				oldChild = oldList[index]
			}
			newChild := any(engMissingValue)
			if index < len(newList) {
				newChild = newList[index]
			}
			engDiffValues(oldChild, newChild, childPath, output, kind, limit)
			if len(*output) >= limit {
				return
			}
		}
		return
	}
	oldEncoded, _ := engCanonicalJSON(old)
	newEncoded, _ := engCanonicalJSON(new)
	if oldEncoded != newEncoded {
		*output = append(*output, M{
			"path":         path,
			"operation":    engChangeOperationReplace,
			"old":          engSafeDiffValue(old, path, kind),
			"new":          engSafeDiffValue(new, path, kind),
			"pod_template": strings.HasPrefix(path, "spec.template"),
		})
	}
}

func engChangesBetween(oldIndex, newIndex map[engKey][]M) ([]M, bool, bool) {
	changes := []M{}
	podTemplateChanged := false
	truncated := false
	seen := map[engKey]bool{}
	keys := make([]engKey, 0, len(oldIndex)+len(newIndex))
	for key := range oldIndex {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	for key := range newIndex {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		if keys[i].namespace != keys[j].namespace {
			return keys[i].namespace < keys[j].namespace
		}
		return keys[i].name < keys[j].name
	})
	for _, key := range keys {
		oldEntries := oldIndex[key]
		newEntries := newIndex[key]
		resourceLabel := key.kind + "/" + key.name
		if key.namespace != "" {
			resourceLabel = key.kind + "/" + key.namespace + "/" + key.name
		}
		if len(oldEntries) == 0 {
			changes = append(changes, M{
				"resource":     resourceLabel,
				"kind":         key.kind,
				"namespace":    key.namespace,
				"name":         key.name,
				"operation":    engChangeOperationAdd,
				"path":         "$",
				"old":          nil,
				"new":          "resource present",
				"pod_template": key.kind == "Deployment",
			})
			if key.kind == "Deployment" {
				podTemplateChanged = true
			}
			continue
		}
		if len(newEntries) == 0 {
			changes = append(changes, M{
				"resource":     resourceLabel,
				"kind":         key.kind,
				"namespace":    key.namespace,
				"name":         key.name,
				"operation":    engChangeOperationRemove,
				"path":         "$",
				"old":          "resource present",
				"new":          nil,
				"pod_template": key.kind == "Deployment",
			})
			if key.kind == "Deployment" {
				podTemplateChanged = true
			}
			continue
		}
		fieldChanges := []M{}
		engDiffValues(oldEntries[0], newEntries[0], "", &fieldChanges, key.kind, engMaxDiffEntriesPerResource)
		if len(fieldChanges) >= engMaxDiffEntriesPerResource {
			truncated = true
		}
		for _, change := range fieldChanges {
			if engTruthy(change["pod_template"]) {
				podTemplateChanged = true
			}
			merged := M{
				"resource":  resourceLabel,
				"kind":      key.kind,
				"namespace": key.namespace,
				"name":      key.name,
				"operation": "modify",
			}
			for field, value := range change {
				merged[field] = value
			}
			changes = append(changes, merged)
		}
		if len(changes) >= engMaxTotalChanges {
			truncated = true
			changes = changes[:engMaxTotalChanges]
			break
		}
	}
	return changes, podTemplateChanged, truncated
}

// ---------------------------------------------------------------------------
// Findings

type engFindings struct {
	items []M
	seen  map[string]bool
}

func newEngFindings() *engFindings {
	return &engFindings{items: []M{}, seen: map[string]bool{}}
}

func (f *engFindings) add(ruleID, severity, field, message string, evidence M) {
	if _, ok := engSeverityRank[severity]; !ok {
		panic("invalid severity " + severity)
	}
	key := ruleID + "\x00" + field + "\x00" + message
	if f.seen[key] {
		return
	}
	f.seen[key] = true
	safe := engJSONSafe(evidence)
	safeEvidence, ok := safe.(M)
	if !ok {
		safeEvidence = M{}
	}
	f.items = append(f.items, M{
		"rule_id":  ruleID,
		"severity": severity,
		"field":    field,
		"message":  message,
		"evidence": safeEvidence,
	})
}

func (f *engFindings) decision() string {
	for _, item := range f.items {
		if item["severity"] == engDecisionBlock {
			return engDecisionBlock
		}
	}
	for _, item := range f.items {
		if item["severity"] == engDecisionError {
			return engDecisionError
		}
	}
	for _, item := range f.items {
		if item["severity"] == engDecisionReview {
			return engDecisionReview
		}
	}
	return engDecisionPass
}

func (f *engFindings) sorted() []M {
	out := append([]M{}, f.items...)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i], out[j]
		leftRank := engSeverityRank[engPyStr(left["severity"])]
		rightRank := engSeverityRank[engPyStr(right["severity"])]
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if engPyStr(left["rule_id"]) != engPyStr(right["rule_id"]) {
			return engPyStr(left["rule_id"]) < engPyStr(right["rule_id"])
		}
		if engPyStr(left["field"]) != engPyStr(right["field"]) {
			return engPyStr(left["field"]) < engPyStr(right["field"])
		}
		return engPyStr(left["message"]) < engPyStr(right["message"])
	})
	return out
}

// ---------------------------------------------------------------------------
// Resource checks

func engCheckServiceResource(resource M, key engKey, config M, findings *engFindings) {
	namespace, name := key.namespace, key.name
	fieldName := "Service/" + name
	if namespace != "" {
		fieldName = "Service/" + namespace + "/" + name
	}
	if namespace != engPyStr(config["namespace"]) || name != engPyStr(config["deployment"]) {
		findings.add("UNEXPECTED_RESOURCE", engDecisionReview, fieldName,
			"an additional Service is outside the configured demo release", nil)
	}
	spec, ok := engAsMap(resource["spec"])
	if !ok {
		findings.add("SERVICE_INVALID", engDecisionBlock, fieldName, "the Service has no spec", nil)
		return
	}
	serviceType := any("ClusterIP")
	if value, present := spec["type"]; present {
		serviceType = value
	}
	if !engStringIs(serviceType, "ClusterIP") && !engStringIs(serviceType, "ExternalName") {
		findings.add("SERVICE_EXPOSURE", engDecisionBlock, fieldName+".spec.type",
			"NodePort/LoadBalancer exposure is not approved", M{"type": serviceType})
	}
	if engTruthy(spec["externalIPs"]) {
		findings.add("SERVICE_EXPOSURE", engDecisionBlock, fieldName+".spec.externalIPs",
			"external service IPs are not approved", M{"externalIPs": spec["externalIPs"]})
	}
	if ports, ok := engAsList(spec["ports"]); ok {
		for index, rawPort := range ports {
			port, ok := engAsMap(rawPort)
			if !ok {
				continue
			}
			if nodePort, present := port["nodePort"]; present && nodePort != nil {
				findings.add("SERVICE_EXPOSURE", engDecisionBlock,
					fmt.Sprintf("%s.spec.ports[%d].nodePort", fieldName, index),
					"nodePort is not approved", M{"nodePort": nodePort})
			}
		}
	}
}

func engCheckResourceScope(newResources []M, newIndex map[engKey][]M, config M, findings *engFindings) {
	namespace := engPyStr(config["namespace"])
	deployment := engPyStr(config["deployment"])
	keys := make([]engKey, 0, len(newIndex))
	for key := range newIndex {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		if keys[i].namespace != keys[j].namespace {
			return keys[i].namespace < keys[j].namespace
		}
		return keys[i].name < keys[j].name
	})
	for _, key := range keys {
		entries := newIndex[key]
		kind, itemNamespace, name := key.kind, key.namespace, key.name
		fieldName := kind + "/" + name
		if itemNamespace != "" {
			fieldName = kind + "/" + itemNamespace + "/" + name
		}
		if len(entries) > 1 {
			findings.add("DUPLICATE_RESOURCE", engDecisionBlock, fieldName,
				"the rendered release contains duplicate resources with the same identity",
				M{"count": len(entries)})
		}
		if engAllowedKinds[kind] {
			if kind == "Deployment" && (itemNamespace != namespace || name != deployment) {
				findings.add("UNEXPECTED_WORKLOAD", engDecisionBlock, fieldName,
					"only the configured demo Deployment may be rendered",
					M{"expected_namespace": namespace, "expected_name": deployment})
			} else if kind == "Service" {
				engCheckServiceResource(entries[0], key, config, findings)
			}
			continue
		}
		if engClusterScopedKinds[kind] || kind == "Role" || kind == "RoleBinding" {
			findings.add("FORBIDDEN_RESOURCE_KIND", engDecisionBlock, fieldName,
				"the release may not render RBAC or cluster-scoped resources", M{"kind": kind})
		} else if engForbiddenWorkloadKinds[kind] {
			findings.add("FORBIDDEN_RESOURCE_KIND", engDecisionBlock, fieldName,
				"the release may not render additional workload controllers", M{"kind": kind})
		} else if engExposureKinds[kind] {
			findings.add("SERVICE_EXPOSURE", engDecisionBlock, fieldName,
				"Ingress/Gateway exposure is not approved for the demo release", M{"kind": kind})
		} else if engArgoKinds[kind] {
			findings.add("ARGOCD_RESOURCE_CHANGE", engDecisionReview, fieldName,
				"an Argo CD source/application object appears in the release", M{"kind": kind})
		} else {
			findings.add("UNEXPECTED_RESOURCE", engDecisionBlock, fieldName,
				"the protected demo chart rendered an unknown resource kind", M{"kind": kind})
		}
	}
}

func engSplitImage(image string) (string, *string, *string) {
	namePart := image
	var digest *string
	if strings.Contains(image, "@") {
		index := strings.LastIndex(image, "@")
		namePart = image[:index]
		value := image[index+1:]
		digest = &value
	}
	var tag *string
	lastSlash := strings.LastIndex(namePart, "/")
	lastColon := strings.LastIndex(namePart, ":")
	if lastColon > lastSlash {
		value := namePart[lastColon+1:]
		tag = &value
		namePart = namePart[:lastColon]
	}
	return namePart, tag, digest
}

func engCheckImage(image any, fieldName string, config M, findings *engFindings) {
	text, ok := image.(string)
	if !ok || strings.TrimSpace(text) == "" || strings.IndexFunc(text, unicode.IsSpace) >= 0 {
		findings.add("IMAGE_INVALID", engDecisionBlock, fieldName,
			"container image is empty or malformed", nil)
		return
	}
	repository, tag, digest := engSplitImage(strings.TrimSpace(text))
	allowed := engPyStr(config["allowed_image_repository"])
	if repository != allowed {
		findings.add("IMAGE_REPOSITORY_NOT_ALLOWED", engDecisionBlock, fieldName,
			"container image repository is not allowlisted",
			M{"repository": repository, "allowed": allowed})
	}
	if digest == nil {
		if engTruthy(config["require_digest"]) {
			evidence := M{"image": image}
			if tag != nil {
				evidence["tag"] = *tag
			} else {
				evidence["tag"] = nil
			}
			findings.add("IMAGE_DIGEST_REQUIRED", engDecisionBlock, fieldName,
				"an immutable sha256 image digest is required", evidence)
		} else {
			evidence := M{"tag": nil}
			if tag != nil {
				evidence["tag"] = *tag
			}
			findings.add("IMAGE_TAG_ONLY", engDecisionReview, fieldName,
				"image is tag-only; a digest is preferred", evidence)
		}
	} else if !engDigestRE.MatchString(*digest) {
		findings.add("IMAGE_DIGEST_INVALID", engDecisionBlock, fieldName,
			"image digest must be sha256:<64 lowercase hex>", M{"digest": *digest})
	}
	if digest == nil && tag != nil && *tag == "latest" {
		findings.add("IMAGE_MUTABLE_TAG", engDecisionBlock, fieldName,
			"the mutable 'latest' tag is not permitted", nil)
	}
	if digest == nil && tag == nil {
		findings.add("IMAGE_INVALID", engDecisionBlock, fieldName,
			"image has neither an immutable digest nor an explicit tag", nil)
	}
}

func engParseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}

func engCheckEnv(container M, containerField string, findings *engFindings) {
	env := []any{}
	if raw, present := container["env"]; present && raw != nil {
		list, ok := engAsList(raw)
		if !ok {
			findings.add("ENV_INVALID", engDecisionBlock, containerField+".env", "env must be a list", nil)
			return
		}
		env = list
	}
	if raw, present := container["envFrom"]; present && raw != nil {
		list, ok := engAsList(raw)
		if !ok {
			findings.add("ENV_FROM_INVALID", engDecisionBlock, containerField+".envFrom",
				"envFrom must be a list", nil)
		} else if len(list) > 0 {
			findings.add("ENV_FROM_NOT_ALLOWED", engDecisionBlock, containerField+".envFrom",
				"envFrom can inject values that are not visible to the guard and is not permitted",
				M{"sources": len(list)})
		}
	}
	seen := map[string]int{}
	for index, rawEntry := range env {
		path := fmt.Sprintf("%s.env[%d]", containerField, index)
		entry, ok := engAsMap(rawEntry)
		if !ok {
			findings.add("ENV_INVALID", engDecisionBlock, path, "environment entry must be a mapping", nil)
			continue
		}
		name, ok := entry["name"].(string)
		if !ok || !engEnvNameRE.MatchString(name) {
			findings.add("ENV_NAME_INVALID", engDecisionBlock, path+".name",
				"environment variable name is invalid", nil)
			continue
		}
		if first, present := seen[name]; present {
			findings.add("DUPLICATE_ENV", engDecisionBlock, path+".name",
				"environment variable name is duplicated", M{"name": name, "first_index": first})
		} else {
			seen[name] = index
		}
		valueFrom, valueFromPresent := entry["valueFrom"]
		if !engFaultEnvNames[name] {
			continue
		}
		if valueFromPresent && valueFrom != nil {
			if _, ok := engAsMap(valueFrom); ok {
				findings.add("FAULT_VALUE_FROM", engDecisionBlock, path,
					"fault-injection knobs may not be sourced through valueFrom", M{"name": name})
			} else {
				findings.add("FAULT_VALUE_FROM", engDecisionBlock, path,
					"fault-injection knobs may not use valueFrom", M{"name": name})
			}
			continue
		}
		rawValue, valuePresent := entry["value"]
		if !valuePresent {
			findings.add("FAULT_ENV_INVALID", engDecisionBlock, path,
				"fault-injection knob has no literal value", M{"name": name})
			continue
		}
		text, ok := rawValue.(string)
		if !ok {
			findings.add("FAULT_ENV_INVALID", engDecisionBlock, path+".value",
				"fault-injection knob must be a string", M{"name": name})
			continue
		}
		switch name {
		case "DEMO_ERROR_RATE":
			parsed, ok := engNumber(text)
			if !ok || parsed < 0 || parsed > 1 {
				findings.add("FAULT_ENV_INVALID", engDecisionBlock, path+".value",
					"DEMO_ERROR_RATE must be between 0 and 1", M{"value": text})
			} else if parsed > 0 {
				findings.add("FAULT_INJECTION", engDecisionBlock, path+".value",
					"DEMO_ERROR_RATE requests deliberate HTTP 500 injection",
					M{"name": name, "value": text})
			}
		case "DEMO_LATENCY_MS":
			trimmed := strings.TrimSpace(text)
			if !engNonNegativeRE.MatchString(trimmed) {
				findings.add("FAULT_ENV_INVALID", engDecisionBlock, path+".value",
					"DEMO_LATENCY_MS must be a non-negative integer", M{"value": text})
			} else if engDigitsPositive(trimmed) {
				findings.add("FAULT_INJECTION", engDecisionBlock, path+".value",
					"DEMO_LATENCY_MS requests deliberate latency injection",
					M{"name": name, "value": text})
			}
		case "DEMO_STARTUP_FAIL":
			parsed, ok := engParseBool(text)
			if !ok {
				findings.add("FAULT_ENV_INVALID", engDecisionBlock, path+".value",
					"DEMO_STARTUP_FAIL must be a boolean", M{"value": text})
			} else if parsed {
				findings.add("FAULT_INJECTION", engDecisionBlock, path+".value",
					"DEMO_STARTUP_FAIL requests deliberate startup failure",
					M{"name": name, "value": text})
			}
		}
	}
}

func engDigitsPositive(text string) bool {
	for _, char := range text {
		if char != '0' {
			return true
		}
	}
	return false
}

func engCheckProbe(container M, containerField, probeName, severity string, findings *engFindings) {
	rawProbe, present := container[probeName]
	path := containerField + "." + probeName
	if !present || rawProbe == nil {
		findings.add("PROBE_MISSING", severity, path,
			probeName+" is required for safe rollout behavior", nil)
		return
	}
	probe, ok := engAsMap(rawProbe)
	if !ok {
		findings.add("PROBE_INVALID", engDecisionBlock, path, probeName+" must be a mapping", nil)
		return
	}
	handlers := []string{}
	for _, key := range []string{"httpGet", "tcpSocket", "exec", "grpc"} {
		if _, present := probe[key]; present {
			handlers = append(handlers, key)
		}
	}
	if len(handlers) != 1 {
		findings.add("PROBE_INVALID", engDecisionBlock, path,
			probeName+" must contain exactly one handler", M{"handlers": handlers})
		return
	}
	handlerKey := handlers[0]
	rawHandler := probe[handlerKey]
	handler, ok := engAsMap(rawHandler)
	if !ok {
		findings.add("PROBE_INVALID", engDecisionBlock, path+"."+handlerKey,
			"probe handler must be a mapping", nil)
	} else {
		if handlerKey == "httpGet" || handlerKey == "tcpSocket" || handlerKey == "grpc" {
			port := handler["port"]
			portInt, isInt := engInt(port)
			portString, isString := port.(string)
			validPort := (isInt && portInt >= 1 && portInt <= 65535) ||
				(isString && engDNSLabelRE.MatchString(portString))
			if !validPort {
				findings.add("PROBE_INVALID", engDecisionBlock,
					path+"."+handlerKey+".port", "probe port is invalid", M{"port": port})
			}
			if handlerKey == "httpGet" {
				scheme := any("HTTP")
				if value, present := handler["scheme"]; present {
					scheme = value
				}
				if !engStringIs(scheme, "HTTP") && !engStringIs(scheme, "HTTPS") {
					findings.add("PROBE_INVALID", engDecisionBlock,
						path+".httpGet.scheme", "probe scheme is invalid", nil)
				}
				httpPath := any("/")
				if value, present := handler["path"]; present {
					httpPath = value
				}
				if _, ok := httpPath.(string); !ok {
					findings.add("PROBE_INVALID", engDecisionBlock,
						path+".httpGet.path", "probe path is invalid", nil)
				}
			}
		}
		if handlerKey == "exec" {
			command := handler["command"]
			commandList, isList := engAsList(command)
			valid := isList && len(commandList) > 0
			if valid {
				for _, part := range commandList {
					if _, ok := part.(string); !ok {
						valid = false
						break
					}
				}
			}
			if !valid {
				findings.add("PROBE_INVALID", engDecisionBlock,
					path+".exec.command", "exec probe command must be a non-empty string list", nil)
			} else if !engAllowedExecCommand(commandList) {
				findings.add("PROBE_EXEC_COMMAND_NOT_ALLOWED", engDecisionBlock,
					path+".exec.command", "exec probe command is not in the fixed allowlist",
					M{"command": command})
			}
		}
	}
	for _, numericName := range []string{"periodSeconds", "timeoutSeconds", "failureThreshold", "successThreshold"} {
		if value, present := probe[numericName]; present {
			parsed, ok := engInt(value)
			if !ok || parsed < 1 {
				findings.add("PROBE_INVALID", engDecisionBlock,
					path+"."+numericName, numericName+" is invalid", M{"value": value})
			}
		}
	}
	if value, present := probe["initialDelaySeconds"]; present {
		parsed, ok := engInt(value)
		if !ok || parsed < 0 {
			findings.add("PROBE_INVALID", engDecisionBlock,
				path+".initialDelaySeconds", "initialDelaySeconds is invalid", M{"value": value})
		}
	}
}

func engAllowedExecCommand(command []any) bool {
	if len(command) == 0 {
		return false
	}
	parts := make([]string, len(command))
	for i, part := range command {
		text, ok := part.(string)
		if !ok {
			return false
		}
		parts[i] = text
	}
	return engAllowedExecProbeCommands["\x00"+strings.Join(parts, "\x00")]
}

func engCheckSecurity(deployment M, findings *engFindings) {
	podSpec := engPodSpec(deployment)
	podSC, _ := engAsMap(podSpec["securityContext"])
	if podSC == nil {
		podSC = M{}
	}
	fieldBase := "Deployment.spec.template.spec"
	for _, flag := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if engIsTrueIdentity(podSpec[flag]) {
			findings.add("POD_HOST_NAMESPACE", engDecisionBlock,
				fieldBase+"."+flag,
				flag+" shares a host namespace and is not permitted", nil)
		}
	}
	if engIsTrueIdentity(podSpec["shareProcessNamespace"]) {
		findings.add("SHARED_PROCESS_NAMESPACE", engDecisionReview,
			fieldBase+".shareProcessNamespace",
			"process namespace sharing increases container-to-container exposure", nil)
	}
	if !engIsFalseIdentity(podSpec["automountServiceAccountToken"]) {
		findings.add("SERVICE_ACCOUNT_TOKEN_AUTOMOUNT", engDecisionReview,
			fieldBase+".automountServiceAccountToken",
			"automountServiceAccountToken should be explicitly false",
			M{"value": podSpec["automountServiceAccountToken"]})
	}
	if volumes, ok := engAsList(podSpec["volumes"]); ok {
		for index, rawVolume := range volumes {
			volume, ok := engAsMap(rawVolume)
			if !ok {
				continue
			}
			if _, present := volume["hostPath"]; present {
				findings.add("HOST_PATH_VOLUME", engDecisionBlock,
					fmt.Sprintf("%s.volumes[%d].hostPath", fieldBase, index),
					"hostPath volumes are not permitted", M{"name": volume["name"]})
			}
			for _, source := range engSensitiveVolumeSources {
				if _, present := volume[source]; present {
					findings.add("SENSITIVE_VOLUME", engDecisionBlock,
						fmt.Sprintf("%s.volumes[%d].%s", fieldBase, index, source),
						"secret/projected/configMap volumes are not permitted for the demo workload",
						M{"name": volume["name"], "source": source})
				}
			}
		}
	}
	regular := engContainers(deployment)
	regularCount := len(regular)
	containers := append(append([]M{}, regular...), engInitContainers(deployment)...)
	for index, container := range containers {
		containerName := any(fmt.Sprintf("container-%d", index))
		if value, present := container["name"]; present {
			containerName = value
		}
		var fieldPrefix string
		if index < regularCount {
			fieldPrefix = fmt.Sprintf("Deployment.spec.template.spec.containers[%d]", index)
		} else {
			fieldPrefix = fmt.Sprintf("Deployment.spec.template.spec.initContainers[%d]", index-regularCount)
		}
		securityContext, _ := engAsMap(container["securityContext"])
		if securityContext == nil {
			securityContext = M{}
		}
		if engIsTrueIdentity(securityContext["privileged"]) {
			findings.add("PRIVILEGED_CONTAINER", engDecisionBlock,
				fieldPrefix+".securityContext.privileged", "privileged containers are not permitted",
				M{"container": containerName})
		}
		if !engIsFalseIdentity(securityContext["allowPrivilegeEscalation"]) {
			findings.add("PRIVILEGE_ESCALATION_ALLOWED", engDecisionBlock,
				fieldPrefix+".securityContext.allowPrivilegeEscalation",
				"allowPrivilegeEscalation must be explicitly false",
				M{"container": containerName, "value": securityContext["allowPrivilegeEscalation"]})
		}
		if engIsZero(securityContext["runAsUser"]) || engIsZero(podSC["runAsUser"]) {
			findings.add("RUN_AS_ROOT", engDecisionBlock,
				fieldPrefix+".securityContext.runAsUser",
				"running as UID 0 is not permitted", M{"container": containerName})
		}
		nonRoot := podSC["runAsNonRoot"]
		if value, present := securityContext["runAsNonRoot"]; present {
			nonRoot = value
		}
		if !engIsTrueIdentity(nonRoot) {
			findings.add("RUN_AS_NONROOT_REQUIRED", engDecisionBlock,
				fieldPrefix+".securityContext.runAsNonRoot",
				"runAsNonRoot must be explicitly true",
				M{"container": containerName, "value": nonRoot})
		}
		if capabilities, ok := engAsMap(securityContext["capabilities"]); ok {
			if added, ok := engAsList(capabilities["add"]); ok && len(added) > 0 {
				findings.add("CAPABILITIES_ADDED", engDecisionBlock,
					fieldPrefix+".securityContext.capabilities.add",
					"adding Linux capabilities is not permitted", M{"capabilities": added})
			}
			normalizedDrop := []string{}
			if dropped, ok := engAsList(capabilities["drop"]); ok {
				for _, item := range dropped {
					normalizedDrop = append(normalizedDrop, strings.ToUpper(engPyStr(item)))
				}
			}
			if !engContainsString(normalizedDrop, "ALL") {
				findings.add("CAPABILITIES_NOT_DROPPED", engDecisionReview,
					fieldPrefix+".securityContext.capabilities.drop",
					"all Linux capabilities should be dropped", M{"drop": capabilities["drop"]})
			}
		} else {
			findings.add("CAPABILITIES_NOT_DROPPED", engDecisionReview,
				fieldPrefix+".securityContext.capabilities",
				"capabilities.drop: [ALL] is missing", nil)
		}
		if !engIsTrueIdentity(securityContext["readOnlyRootFilesystem"]) {
			findings.add("ROOT_FILESYSTEM_WRITABLE", engDecisionReview,
				fieldPrefix+".securityContext.readOnlyRootFilesystem",
				"readOnlyRootFilesystem should be true", M{"container": containerName})
		}
		var seccomp M
		if profile, ok := engAsMap(securityContext["seccompProfile"]); ok {
			seccomp = profile
		}
		if seccomp == nil {
			if profile, ok := engAsMap(podSC["seccompProfile"]); ok {
				seccomp = profile
			}
		}
		var seccompType any
		if seccomp != nil {
			seccompType = seccomp["type"]
		}
		if engStringIs(seccompType, "Unconfined") {
			findings.add("SECCOMP_UNCONFINED", engDecisionBlock,
				fieldPrefix+".securityContext.seccompProfile.type",
				"Unconfined seccomp is not permitted", M{"container": containerName})
		} else if !engStringIs(seccompType, "RuntimeDefault") && !engStringIs(seccompType, "Localhost") {
			findings.add("SECCOMP_PROFILE_MISSING", engDecisionReview,
				fieldPrefix+".securityContext.seccompProfile",
				"a RuntimeDefault seccomp profile should be set", M{"container": containerName})
		}
		if ports, ok := engAsList(container["ports"]); ok {
			for portIndex, rawPort := range ports {
				port, ok := engAsMap(rawPort)
				if !ok {
					continue
				}
				if value, present := port["hostPort"]; present {
					findings.add("HOST_PORT", engDecisionBlock,
						fmt.Sprintf("%s.ports[%d].hostPort", fieldPrefix, portIndex),
						"hostPort is not permitted",
						M{"container": containerName, "hostPort": value})
				}
			}
		}
	}
}

func engContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func engCheckDeployment(oldDeployment, newDeployment M, config M, findings *engFindings) bool {
	if newDeployment == nil {
		findings.add("DEPLOYMENT_MISSING", engDecisionBlock,
			fmt.Sprintf("Deployment/%s/%s", engPyStr(config["namespace"]), engPyStr(config["deployment"])),
			"the configured Deployment would be deleted or is not rendered", nil)
		return false
	}
	namespace := engPyStr(config["namespace"])
	name := engPyStr(config["deployment"])
	base := "Deployment/" + namespace + "/" + name
	spec, ok := engAsMap(newDeployment["spec"])
	if !ok {
		findings.add("DEPLOYMENT_INVALID", engDecisionBlock, base+".spec", "Deployment spec is missing", nil)
		return false
	}
	replicas, replicasOK := engReplicas(newDeployment, 1)
	if !replicasOK {
		findings.add("REPLICAS_INVALID", engDecisionBlock, base+".spec.replicas",
			"replicas must be a non-negative integer", M{"value": spec["replicas"]})
	} else if replicas == 0 {
		findings.add("REPLICAS_ZERO", engDecisionBlock, base+".spec.replicas",
			"zero replicas is not an approved release", nil)
	}
	selector := spec["selector"]
	rawTemplate, templatePresent := spec["template"]
	template, templateOK := engAsMap(rawTemplate)
	if !templatePresent || !templateOK {
		findings.add("POD_TEMPLATE_MISSING", engDecisionBlock, base+".spec.template",
			"Pod template is missing", nil)
		return false
	}
	templateMetadata, _ := engAsMap(template["metadata"])
	if templateMetadata == nil {
		templateMetadata = M{}
	}
	templateLabels, _ := engAsMap(templateMetadata["labels"])
	if templateLabels == nil {
		templateLabels = M{}
	}
	var selectorLabels M
	if selectorMap, ok := engAsMap(selector); ok {
		selectorLabels, _ = engAsMap(selectorMap["matchLabels"])
	}
	if selectorLabels == nil || len(selectorLabels) == 0 {
		findings.add("SELECTOR_INVALID", engDecisionBlock, base+".spec.selector.matchLabels",
			"Deployment selector must have matchLabels", nil)
	} else {
		keys := make([]string, 0, len(selectorLabels))
		for key := range selectorLabels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, labelKey := range keys {
			expected := selectorLabels[labelKey]
			if !engPyEqual(templateLabels[labelKey], expected) {
				findings.add("SELECTOR_MISMATCH", engDecisionBlock, base+".spec.selector.matchLabels",
					"Pod template labels do not satisfy the immutable selector",
					M{"label": labelKey, "expected": expected, "actual": templateLabels[labelKey]})
				break
			}
		}
	}
	if oldDeployment != nil {
		oldSpec, _ := engAsMap(oldDeployment["spec"])
		if oldSpec == nil {
			oldSpec = M{}
		}
		oldEncoded, _ := engCanonicalJSON(oldSpec["selector"])
		newEncoded, _ := engCanonicalJSON(selector)
		if oldEncoded != newEncoded {
			findings.add("SELECTOR_CHANGED", engDecisionBlock, base+".spec.selector",
				"changing a Deployment selector is immutable and risks orphaned Pods", nil)
		}
	}
	podSpec := engPodSpec(newDeployment)
	containersList, containersOK := engAsList(podSpec["containers"])
	if !containersOK || len(containersList) == 0 {
		findings.add("CONTAINERS_MISSING", engDecisionBlock,
			base+".spec.template.spec.containers", "no containers", nil)
		return false
	}
	regularContainers := engContainers(newDeployment)
	initContainers := engInitContainers(newDeployment)
	if len(regularContainers) != 1 {
		findings.add("CONTAINER_SET_NOT_ALLOWED", engDecisionBlock,
			base+".spec.template.spec.containers",
			"exactly one fixed demo-service container is permitted",
			M{"count": len(regularContainers), "expected": engDefaultContainerName})
	}
	if len(initContainers) > 0 {
		findings.add("INIT_CONTAINER_NOT_ALLOWED", engDecisionBlock,
			base+".spec.template.spec.initContainers",
			"init containers are not permitted for the demo workload",
			M{"count": len(initContainers)})
	}
	for index, container := range regularContainers {
		containerName := fmt.Sprintf("container-%d", index)
		if value, present := container["name"]; present {
			containerName = engPyStr(value)
		}
		fieldPrefix := fmt.Sprintf("Deployment.spec.template.spec.containers[%d]", index)
		if containerName != engDefaultContainerName {
			findings.add("CONTAINER_NAME_NOT_ALLOWED", engDecisionBlock, fieldPrefix+".name",
				"only the fixed demo-service container is permitted",
				M{"name": containerName, "expected": engDefaultContainerName})
		}
		for _, key := range []string{"command", "args"} {
			value, present := container[key]
			if !present || value == nil {
				continue
			}
			if list, ok := engAsList(value); !ok || len(list) != 0 {
				findings.add("CONTAINER_COMMAND_NOT_ALLOWED", engDecisionBlock,
					fieldPrefix+"."+key,
					"command/args overrides are not permitted for the fixed demo container",
					M{"container": containerName, key: value})
			}
		}
		if lifecycle, present := container["lifecycle"]; present && lifecycle != nil {
			if mapping, ok := engAsMap(lifecycle); !ok || len(mapping) != 0 {
				findings.add("LIFECYCLE_NOT_ALLOWED", engDecisionBlock, fieldPrefix+".lifecycle",
					"lifecycle hooks (including exec postStart/preStop) are not permitted",
					M{"container": containerName})
			}
		}
	}
	for index, initContainer := range initContainers {
		initName := fmt.Sprintf("init-container-%d", index)
		if value, present := initContainer["name"]; present {
			initName = engPyStr(value)
		}
		findings.add("INIT_CONTAINER_COMMAND_NOT_ALLOWED", engDecisionBlock,
			fmt.Sprintf("Deployment.spec.template.spec.initContainers[%d]", index),
			"init containers may not run candidate commands", M{"name": initName})
	}
	names := map[string]bool{}
	for _, container := range engContainers(newDeployment) {
		containerName, ok := container["name"].(string)
		if !ok || containerName == "" {
			findings.add("CONTAINER_NAME_INVALID", engDecisionBlock, base+".containers",
				"container name is missing", nil)
			continue
		}
		if names[containerName] {
			findings.add("CONTAINER_NAME_DUPLICATE", engDecisionBlock, base+".containers",
				"container name is duplicated", M{"name": containerName})
		}
		names[containerName] = true
	}
	for _, initContainer := range engInitContainers(newDeployment) {
		initName, ok := initContainer["name"].(string)
		if !ok || initName == "" {
			findings.add("CONTAINER_NAME_INVALID", engDecisionBlock, base+".initContainers",
				"init container name missing", nil)
		} else if names[initName] {
			findings.add("CONTAINER_NAME_DUPLICATE", engDecisionBlock, base+".initContainers",
				"init container name collides with a container", M{"name": initName})
		} else {
			names[initName] = true
		}
	}
	groups := []struct {
		name       string
		containers []M
	}{
		{"containers", engContainers(newDeployment)},
		{"initContainers", engInitContainers(newDeployment)},
	}
	for _, group := range groups {
		for index, container := range group.containers {
			containerName := fmt.Sprintf("container-%d", index)
			if value, present := container["name"]; present {
				containerName = engPyStr(value)
			}
			prefix := fmt.Sprintf("Deployment.spec.template.spec.%s[%d]", group.name, index)
			engCheckImage(container["image"], prefix+".image", config, findings)
			engCheckEnv(container, prefix, findings)
			resources, resourcesOK := engAsMap(container["resources"])
			if !resourcesOK {
				findings.add("RESOURCE_REQUESTS_MISSING", engDecisionReview, prefix+".resources",
					"resource requests are missing; capacity cannot be reserved",
					M{"container": containerName})
			} else {
				requests, _ := engAsMap(resources["requests"])
				if requests == nil {
					requests = M{}
				}
				limits, _ := engAsMap(resources["limits"])
				if limits == nil {
					limits = M{}
				}
				_, hasCPURequest := requests["cpu"]
				_, hasMemoryRequest := requests["memory"]
				if !hasCPURequest || !hasMemoryRequest {
					findings.add("RESOURCE_REQUESTS_MISSING", engDecisionReview,
						prefix+".resources.requests",
						"CPU and memory requests should both be set", M{"container": containerName})
				}
				for _, resourceName := range []string{"cpu", "memory"} {
					parser := engCPUMillicores
					if resourceName == "memory" {
						parser = engMemoryBytes
					}
					requestValue := requests[resourceName]
					limitValue := limits[resourceName]
					if requestValue != nil {
						if _, ok := parser(requestValue); !ok {
							findings.add("INVALID_RESOURCE_QUANTITY", engDecisionBlock,
								prefix+".resources.requests."+resourceName,
								"invalid Kubernetes resource quantity", M{"value": requestValue})
						}
					}
					if limitValue != nil {
						if _, ok := parser(limitValue); !ok {
							findings.add("INVALID_RESOURCE_QUANTITY", engDecisionBlock,
								prefix+".resources.limits."+resourceName,
								"invalid Kubernetes resource quantity", M{"value": limitValue})
						}
					}
					var parsedRequest, parsedLimit float64
					var requestOK, limitOK bool
					if requestValue != nil {
						parsedRequest, requestOK = parser(requestValue)
					}
					if limitValue != nil {
						parsedLimit, limitOK = parser(limitValue)
					}
					if requestOK && limitOK && parsedLimit < parsedRequest {
						findings.add("RESOURCE_LIMIT_BELOW_REQUEST", engDecisionBlock, prefix+".resources",
							resourceName+" limit is below its request", nil)
					}
				}
			}
		}
	}
	for index, container := range engContainers(newDeployment) {
		prefix := fmt.Sprintf("Deployment.spec.template.spec.containers[%d]", index)
		engCheckProbe(container, prefix, "readinessProbe", engDecisionBlock, findings)
		engCheckProbe(container, prefix, "livenessProbe", engDecisionBlock, findings)
		engCheckProbe(container, prefix, "startupProbe", engDecisionReview, findings)
	}
	engCheckSecurity(newDeployment, findings)
	return true
}

func engCheckMemory(metrics M, newDeployment M, config M, findings *engFindings) {
	if newDeployment == nil {
		return
	}
	memory, _ := engMetric(metrics, "memory_working_set_bytes")
	if !memory.ok {
		return
	}
	podResources := engPodResources(newDeployment)
	limit, limitOK := engNumber(podResources["memory_limit_bytes"])
	complete := engTruthy(podResources["memory_limit_complete"])
	if !limitOK || !complete {
		findings.add("MEMORY_LIMIT_MISSING", engDecisionError,
			"Deployment.spec.template.spec.containers[].resources.limits.memory",
			"cannot assess the memory safety threshold without a complete Pod memory limit",
			M{"measured_max_over_15m": memory.value})
		return
	}
	factor := engDefaultMemoryHeadroomFactor
	if parsed, ok := engNumber(config["memory_headroom_factor"]); ok && parsed != 0 {
		factor = parsed
	}
	threshold := factor * memory.value
	if limit < threshold {
		findings.add("MEMORY_LIMIT_TOO_LOW", engDecisionBlock,
			"Deployment.spec.template.spec.containers[].resources.limits.memory",
			"Pod memory limit is below the required headroom over the 15m observed maximum",
			M{
				"memory_limit_bytes":      limit,
				"max_over_15m_bytes":      memory.value,
				"headroom_factor":         factor,
				"required_at_least_bytes": threshold,
			})
	}
}

func engCheckResourceReduction(oldDeployment, newDeployment M, findings *engFindings) {
	if oldDeployment == nil || newDeployment == nil {
		return
	}
	oldResources := engPodResources(oldDeployment)
	newResources := engPodResources(newDeployment)
	keys := []struct {
		key   string
		label string
	}{
		{"cpu_request_millicores", "CPU request"},
		{"memory_request_bytes", "memory request"},
		{"cpu_limit_millicores", "CPU limit"},
		{"memory_limit_bytes", "memory limit"},
	}
	for _, entry := range keys {
		oldValue, oldOK := engNumber(oldResources[entry.key])
		newValue, newOK := engNumber(newResources[entry.key])
		if !oldOK || oldValue <= 0 || !newOK {
			continue
		}
		if newValue < oldValue*0.5 {
			findings.add("RESOURCE_REDUCTION", engDecisionReview,
				"Deployment.spec.template.spec.containers[].resources."+entry.key,
				"the Pod "+entry.label+" is reduced by more than 50%",
				M{
					"resource":           entry.key,
					"old":                oldValue,
					"new":                newValue,
					"reduction_fraction": 1.0 - (newValue / oldValue),
				})
		}
	}
}

func engNodeReady(node M) bool {
	if ready, ok := node["ready"].(bool); ok {
		return ready
	}
	status, _ := engAsMap(node["status"])
	if status == nil {
		status = M{}
	}
	if conditions, ok := engAsList(status["conditions"]); ok {
		for _, rawCondition := range conditions {
			condition, ok := engAsMap(rawCondition)
			if !ok || !engStringIs(condition["type"], "Ready") {
				continue
			}
			statusValue := "false"
			if value, present := condition["status"]; present {
				statusValue = engPyStr(value)
			}
			return strings.ToLower(statusValue) == "true"
		}
	}
	return false
}

func engNodeIsWorker(node M) bool {
	if value, present := node["control_plane"]; present {
		return !engTruthy(value)
	}
	labels, _ := engAsMap(node["labels"])
	if labels == nil {
		labels = M{}
	}
	if _, present := labels["node-role.kubernetes.io/control-plane"]; present {
		return false
	}
	if _, present := labels["node-role.kubernetes.io/master"]; present {
		return false
	}
	spec, _ := engAsMap(node["spec"])
	if spec != nil && engTruthy(spec["unschedulable"]) {
		return false
	}
	taints := node["taints"]
	if _, ok := engAsList(taints); !ok && spec != nil {
		taints = spec["taints"]
	}
	if list, ok := engAsList(taints); ok {
		for _, rawTaint := range list {
			taint, ok := engAsMap(rawTaint)
			if ok && engStringIs(taint["effect"], "NoSchedule") {
				return false
			}
		}
	}
	if engIsFalseIdentity(node["schedulable"]) {
		return false
	}
	return true
}

func engNodeAllocatable(node M, resource string) (float64, bool) {
	if resource == "cpu" {
		for _, key := range []string{"allocatable_cpu_millicores", "cpu_millicores"} {
			if value, present := node[key]; present {
				if parsed, ok := engNumber(value); ok {
					return parsed, true
				}
			}
		}
	} else {
		for _, key := range []string{"allocatable_memory_bytes", "memory_bytes"} {
			if value, present := node[key]; present {
				if parsed, ok := engNumber(value); ok {
					return parsed, true
				}
			}
		}
	}
	allocatable, _ := engAsMap(node["allocatable"])
	if allocatable == nil {
		status, _ := engAsMap(node["status"])
		if status != nil {
			allocatable, _ = engAsMap(status["allocatable"])
		}
	}
	if allocatable == nil {
		return 0, false
	}
	if resource == "cpu" {
		return engCPUMillicores(allocatable["cpu"])
	}
	return engMemoryBytes(allocatable["memory"])
}

func engPodPhaseDone(pod M) bool {
	var phase any
	if value, present := pod["phase"]; present && engTruthy(value) {
		phase = value
	} else if status, ok := engAsMap(pod["status"]); ok {
		phase = status["phase"]
	}
	return engStringIs(phase, "Succeeded") || engStringIs(phase, "Failed")
}

func engPodNode(pod M) string {
	if value, present := pod["node"]; present && engTruthy(value) {
		return engPyStr(value)
	}
	spec, _ := engAsMap(pod["spec"])
	if spec == nil {
		spec = M{}
	}
	return engPyStr(engOr(spec["nodeName"], ""))
}

func engCurrentDemoPodRequests(evidence M) (float64, float64, bool, bool) {
	deployment, ok := engAsMap(evidence["deployment"])
	if !ok {
		return 0, 0, false, false
	}
	containers, ok := engAsList(deployment["containers"])
	if !ok || len(containers) == 0 {
		return 0, 0, false, false
	}
	spec := M{"containers": containers}
	cpu, cpuInvalid, _ := engPodRequestsFromSpec(spec, "cpu", engCPUMillicores, "requests")
	memory, memoryInvalid, _ := engPodRequestsFromSpec(spec, "memory", engMemoryBytes, "requests")
	if cpuInvalid != 0 || memoryInvalid != 0 {
		return 0, 0, false, false
	}
	return cpu, memory, true, true
}

func engCheckScheduling(newDeployment M, evidence M, findings *engFindings) {
	if newDeployment == nil {
		return
	}
	podSpec := engPodSpec(newDeployment)
	fieldBase := "Deployment.spec.template.spec"
	markers := []string{"control-plane", "node-role.kubernetes.io/master", "master"}
	claimsControlPlane := func(value any) bool {
		text, err := engCanonicalJSON(value)
		if err != nil {
			text = engPyStr(value)
		}
		text = strings.ToLower(text)
		for _, marker := range markers {
			if strings.Contains(text, marker) {
				return true
			}
		}
		return false
	}
	workerLabels := []M{}
	if nodes, ok := engAsList(evidence["nodes"]); ok {
		for _, rawNode := range nodes {
			node, ok := engAsMap(rawNode)
			if !ok || !engNodeReady(node) || !engNodeIsWorker(node) {
				continue
			}
			labels, ok := engAsMap(node["labels"])
			if !ok {
				labels = M{}
			}
			workerLabels = append(workerLabels, labels)
		}
	}
	if nodeSelector, ok := engAsMap(podSpec["nodeSelector"]); ok && len(nodeSelector) > 0 {
		if claimsControlPlane(nodeSelector) {
			findings.add("CONTROL_PLANE_SCHEDULING", engDecisionBlock, fieldBase+".nodeSelector",
				"nodeSelector targets the control plane, which is outside the capacity model",
				M{"nodeSelector": nodeSelector})
		} else {
			matched := false
			for _, labels := range workerLabels {
				allMatch := true
				for key, value := range nodeSelector {
					if !engPyEqual(labels[key], engPyStr(value)) {
						allMatch = false
						break
					}
				}
				if allMatch {
					matched = true
					break
				}
			}
			if !matched {
				findings.add("SCHEDULING_UNVERIFIED", engDecisionReview, fieldBase+".nodeSelector",
					"nodeSelector cannot be matched to a Ready schedulable worker from evidence",
					M{"nodeSelector": nodeSelector})
			}
		}
	}
	if affinity, ok := engAsMap(podSpec["affinity"]); ok && len(affinity) > 0 {
		if claimsControlPlane(affinity) {
			findings.add("CONTROL_PLANE_SCHEDULING", engDecisionBlock, fieldBase+".affinity",
				"affinity targets the control plane, which is outside the capacity model", nil)
		} else {
			findings.add("SCHEDULING_UNVERIFIED", engDecisionReview, fieldBase+".affinity",
				"affinity rules cannot be proven to stay on workers already counted for capacity", nil)
		}
	}
	if tolerations, ok := engAsList(podSpec["tolerations"]); ok && len(tolerations) > 0 {
		controlToleration := false
		broadToleration := false
		for _, rawToleration := range tolerations {
			toleration, ok := engAsMap(rawToleration)
			if !ok {
				continue
			}
			key := ""
			if value, present := toleration["key"]; present {
				key = engPyStr(value)
			}
			operator := "Equal"
			if value, present := toleration["operator"]; present {
				operator = engPyStr(value)
			}
			if strings.HasPrefix(key, "node-role.kubernetes.io/control-plane") ||
				strings.HasPrefix(key, "node-role.kubernetes.io/master") {
				controlToleration = true
			}
			if key == "" && operator == "Exists" {
				broadToleration = true
			}
		}
		if controlToleration || broadToleration {
			findings.add("CONTROL_PLANE_TOLERATION", engDecisionBlock, fieldBase+".tolerations",
				"toleration can place the workload on a tainted control-plane node",
				M{"tolerations": tolerations})
		} else {
			findings.add("SCHEDULING_UNVERIFIED", engDecisionReview, fieldBase+".tolerations",
				"toleration intent cannot be verified against the counted worker set",
				M{"tolerations": tolerations})
		}
	}
}

func engCheckScheduledPodRequests(evidence M, findings *engFindings) {
	nodes, nodesOK := engAsList(evidence["nodes"])
	pods, podsOK := engAsList(evidence["pods"])
	if !nodesOK || !podsOK {
		return
	}
	workerNames := map[string]bool{}
	for _, rawNode := range nodes {
		node, ok := engAsMap(rawNode)
		if !ok || !engNodeReady(node) || !engNodeIsWorker(node) {
			continue
		}
		name := ""
		if value, present := node["name"]; present && engTruthy(value) {
			name = engPyStr(value)
		}
		if name != "" {
			workerNames[name] = true
		}
	}
	if len(workerNames) == 0 {
		return
	}
	invalidRequests := 0
	unreservedRequests := 0
	for _, rawPod := range pods {
		pod, ok := engAsMap(rawPod)
		if !ok || engPodPhaseDone(pod) {
			continue
		}
		if !workerNames[engPodNode(pod)] {
			continue
		}
		spec, ok := engAsMap(pod["spec"])
		if !ok {
			spec = pod
		}
		_, cpuInvalid, cpuUnreserved := engPodRequestsFromSpec(spec, "cpu", engCPUMillicores, "requests")
		_, memoryInvalid, memoryUnreserved := engPodRequestsFromSpec(spec, "memory", engMemoryBytes, "requests")
		invalidRequests += cpuInvalid + memoryInvalid
		unreservedRequests += cpuUnreserved + memoryUnreserved
	}
	if invalidRequests != 0 {
		findings.add("CAPACITY_POD_REQUESTS_INVALID", engDecisionError,
			"evidence.pods[].spec.containers[].resources.requests",
			"some scheduled Pods have malformed resource requests, so free capacity cannot be proven",
			M{"invalid_requests": invalidRequests})
	}
	if unreservedRequests != 0 {
		findings.add("CAPACITY_POD_REQUESTS_UNRESERVED", engDecisionReview,
			"evidence.pods[].spec.containers[].resources.requests",
			"some scheduled Pods have no CPU/memory requests and are treated as zero; free capacity may be overstated",
			M{"unreserved_requests": unreservedRequests})
	}
}

func engCapacityFromNodesAndPods(evidence M, findings *engFindings) M {
	nodes, nodesOK := engAsList(evidence["nodes"])
	pods, podsOK := engAsList(evidence["pods"])
	if !nodesOK || len(nodes) == 0 || !podsOK {
		return nil
	}
	workers := []M{}
	workerNames := map[string]bool{}
	for _, rawNode := range nodes {
		node, ok := engAsMap(rawNode)
		if !ok || !engNodeReady(node) || !engNodeIsWorker(node) {
			continue
		}
		workers = append(workers, node)
		name := ""
		if value, present := node["name"]; present && engTruthy(value) {
			name = engPyStr(value)
		} else if metadata, ok := engAsMap(node["metadata"]); ok {
			if value, present := metadata["name"]; present && engTruthy(value) {
				name = engPyStr(value)
			}
		}
		if name != "" {
			workerNames[name] = true
		}
	}
	sortedNames := make([]string, 0, len(workerNames))
	for name := range workerNames {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)
	if len(workers) == 0 {
		return M{
			"available_cpu_millicores":              0.0,
			"available_memory_bytes":                0.0,
			"workers_ready":                         0,
			"allocatable_cpu_millicores":            0.0,
			"allocatable_memory_bytes":              0.0,
			"existing_pods_requests_cpu_millicores": 0.0,
			"existing_pods_requests_memory_bytes":   0.0,
			"worker_names":                          []any{},
			"source":                                "nodes",
			"overcommitted":                         false,
		}
	}
	allocCPU := 0.0
	allocMemory := 0.0
	incompleteNodes := 0
	for _, node := range workers {
		cpu, cpuOK := engNodeAllocatable(node, "cpu")
		memory, memoryOK := engNodeAllocatable(node, "memory")
		if !cpuOK || !memoryOK {
			incompleteNodes++
			continue
		}
		allocCPU += cpu
		allocMemory += memory
	}
	if incompleteNodes != 0 {
		findings.add("CAPACITY_NODE_DATA_INCOMPLETE", engDecisionError,
			"evidence.nodes[].allocatable",
			"Ready worker allocatable CPU/memory is incomplete",
			M{"incomplete_workers": incompleteNodes})
	}
	usedCPU := 0.0
	usedMemory := 0.0
	invalidRequests := 0
	unreservedRequests := 0
	for _, rawPod := range pods {
		pod, ok := engAsMap(rawPod)
		if !ok || engPodPhaseDone(pod) {
			continue
		}
		if !workerNames[engPodNode(pod)] {
			continue
		}
		spec, ok := engAsMap(pod["spec"])
		if !ok {
			spec = pod
		}
		cpu, cpuInvalid, cpuUnreserved := engPodRequestsFromSpec(spec, "cpu", engCPUMillicores, "requests")
		memory, memoryInvalid, memoryUnreserved := engPodRequestsFromSpec(spec, "memory", engMemoryBytes, "requests")
		usedCPU += cpu
		usedMemory += memory
		invalidRequests += cpuInvalid + memoryInvalid
		unreservedRequests += cpuUnreserved + memoryUnreserved
	}
	if invalidRequests != 0 {
		findings.add("CAPACITY_POD_REQUESTS_INVALID", engDecisionError,
			"evidence.pods[].spec.containers[].resources.requests",
			"some scheduled Pods have malformed resource requests, so free capacity cannot be proven",
			M{"invalid_requests": invalidRequests})
	}
	if unreservedRequests != 0 {
		findings.add("CAPACITY_POD_REQUESTS_UNRESERVED", engDecisionReview,
			"evidence.pods[].spec.containers[].resources.requests",
			"some scheduled Pods have no CPU/memory requests and are treated as zero; free capacity may be overstated",
			M{"unreserved_requests": unreservedRequests})
	}
	availableCPU := allocCPU - usedCPU
	availableMemory := allocMemory - usedMemory
	return M{
		"available_cpu_millicores":              math.Max(0.0, availableCPU),
		"available_memory_bytes":                math.Max(0.0, availableMemory),
		"workers_ready":                         len(workers),
		"allocatable_cpu_millicores":            allocCPU,
		"allocatable_memory_bytes":              allocMemory,
		"existing_pods_requests_cpu_millicores": usedCPU,
		"existing_pods_requests_memory_bytes":   usedMemory,
		"unreserved_request_containers":         unreservedRequests,
		"invalid_request_containers":            invalidRequests,
		"worker_names":                          sortedNames,
		"source":                                "nodes+pods",
		"overcommitted":                         availableCPU < 0 || availableMemory < 0,
	}
}

func engCapacitySnapshot(evidence M, findings *engFindings) M {
	if explicit, ok := engAsMap(evidence["capacity"]); ok {
		cpu, cpuOK := engParseQuantity(explicit["available_cpu_millicores"])
		memory, memoryOK := engParseQuantity(explicit["available_memory_bytes"])
		if cpuOK && memoryOK && cpu >= 0 && memory >= 0 {
			engCheckScheduledPodRequests(evidence, findings)
			var workers any
			rawWorkers, present := explicit["workers_ready"]
			if present {
				if parsed, ok := engInt(rawWorkers); ok {
					workers = parsed
				}
			}
			if workers == nil {
				if parsed, ok := engInt(explicit["workers"]); ok {
					workers = parsed
				}
			}
			workerNames := any([]any{})
			if list, ok := engAsList(explicit["worker_names"]); ok {
				workerNames = list
			}
			allocCPU, _ := engParseQuantity(explicit["allocatable_cpu_millicores"])
			allocCPUOK := false
			if _, present := explicit["allocatable_cpu_millicores"]; present {
				allocCPU, allocCPUOK = engParseQuantity(explicit["allocatable_cpu_millicores"])
			}
			allocMemory, allocMemoryOK := engParseQuantity(explicit["allocatable_memory_bytes"])
			if _, present := explicit["allocatable_memory_bytes"]; !present {
				allocMemoryOK = false
			}
			existingCPU, existingCPUOK := engParseQuantity(explicit["existing_pods_requests_cpu_millicores"])
			if _, present := explicit["existing_pods_requests_cpu_millicores"]; !present {
				existingCPUOK = false
			}
			existingMemory, existingMemoryOK := engParseQuantity(explicit["existing_pods_requests_memory_bytes"])
			if _, present := explicit["existing_pods_requests_memory_bytes"]; !present {
				existingMemoryOK = false
			}
			var allocCPUValue, allocMemoryValue, existingCPUValue, existingMemoryValue any
			if allocCPUOK {
				allocCPUValue = allocCPU
			}
			if allocMemoryOK {
				allocMemoryValue = allocMemory
			}
			if existingCPUOK {
				existingCPUValue = existingCPU
			}
			if existingMemoryOK {
				existingMemoryValue = existingMemory
			}
			return M{
				"available_cpu_millicores":              cpu,
				"available_memory_bytes":                memory,
				"workers_ready":                         workers,
				"allocatable_cpu_millicores":            allocCPUValue,
				"allocatable_memory_bytes":              allocMemoryValue,
				"existing_pods_requests_cpu_millicores": existingCPUValue,
				"existing_pods_requests_memory_bytes":   existingMemoryValue,
				"worker_names":                          workerNames,
				"source":                                "evidence.capacity",
				"overcommitted":                         engTruthy(explicit["overcommitted"]),
			}
		}
	}
	return engCapacityFromNodesAndPods(evidence, findings)
}

func engCheckCapacity(evidence M, oldDeployment, newDeployment M, findings *engFindings) M {
	if newDeployment == nil {
		return M{}
	}
	replicas, ok := engReplicas(newDeployment, 1)
	if !ok {
		return M{}
	}
	resources := engPodResources(newDeployment)
	cpuInvalid := int64(engJSONInt(resources["cpu_request_invalid_containers"]))
	memoryInvalid := int64(engJSONInt(resources["memory_request_invalid_containers"]))
	cpuUnreserved := int64(engJSONInt(resources["cpu_request_unreserved_containers"]))
	memoryUnreserved := int64(engJSONInt(resources["memory_request_unreserved_containers"]))
	if cpuInvalid != 0 || memoryInvalid != 0 {
		findings.add("CAPACITY_REQUESTS_INVALID", engDecisionError,
			"Deployment.spec.template.spec.containers[].resources.requests",
			"Pod resource requests contain malformed quantities, so capacity cannot be proven",
			M{"cpu_invalid_containers": cpuInvalid, "memory_invalid_containers": memoryInvalid})
	}
	if cpuUnreserved != 0 || memoryUnreserved != 0 {
		findings.add("CAPACITY_REQUESTS_UNRESERVED", engDecisionReview,
			"Deployment.spec.template.spec.containers[].resources.requests",
			"CPU/memory requests are omitted; Kubernetes schedules them as zero and they remain unreserved",
			M{"cpu_unreserved_containers": cpuUnreserved, "memory_unreserved_containers": memoryUnreserved})
	}
	podCPU, _ := engNumber(resources["cpu_request_millicores"])
	podMemory, _ := engNumber(resources["memory_request_bytes"])
	surge, strategyValid := engStrategySurge(newDeployment, replicas)
	if !strategyValid {
		findings.add("ROLLOUT_STRATEGY_INVALID", engDecisionBlock, "Deployment.spec.strategy",
			"rolling update strategy is invalid", nil)
		surge = 0
	}
	oldReplicas := int64(0)
	oldReplicasOK := false
	if oldDeployment != nil {
		oldReplicas, oldReplicasOK = engReplicas(oldDeployment, 1)
	}
	rolling := oldDeployment != nil && oldReplicasOK && oldReplicas > 0
	oldPodCPU := 0.0
	oldPodMemory := 0.0
	if oldDeployment != nil {
		oldResources := engPodResources(oldDeployment)
		oldPodCPU, _ = engNumber(oldResources["cpu_request_millicores"])
		oldPodMemory, _ = engNumber(oldResources["memory_request_bytes"])
	}
	currentCPU, currentMemory, currentCPUOK, currentMemoryOK := engCurrentDemoPodRequests(evidence)
	var currentReplicas float64
	currentReplicasOK := false
	if currentTarget, ok := engAsMap(evidence["deployment"]); ok {
		currentReplicas, currentReplicasOK = engNumber(currentTarget["replicas"])
	}
	if currentCPUOK && currentMemoryOK && rolling && currentReplicasOK &&
		int64(currentReplicas) == int64(oldReplicas) {
		oldPodCPU = currentCPU
		oldPodMemory = currentMemory
	}
	var oldCount, peakTotalPods, newPodsAtPeak int64
	var peakDemoCPU, peakDemoMemory, oldCPUTotal, oldMemoryTotal, requiredCPU, requiredMemory float64
	if rolling {
		oldCount = oldReplicas
		peakTotalPods = maxInt64(oldCount, replicas) + surge
		newPodsAtPeak = maxInt64(0, peakTotalPods-oldCount)
		peakDemoCPU = float64(oldCount)*oldPodCPU + float64(newPodsAtPeak)*podCPU
		peakDemoMemory = float64(oldCount)*oldPodMemory + float64(newPodsAtPeak)*podMemory
		oldCPUTotal = float64(oldCount) * oldPodCPU
		oldMemoryTotal = float64(oldCount) * oldPodMemory
		requiredCPU = math.Max(0.0, peakDemoCPU-oldCPUTotal)
		requiredMemory = math.Max(0.0, peakDemoMemory-oldMemoryTotal)
	} else {
		oldCount = 0
		peakTotalPods = replicas
		newPodsAtPeak = replicas
		peakDemoCPU = float64(replicas) * podCPU
		peakDemoMemory = float64(replicas) * podMemory
		oldCPUTotal = 0
		oldMemoryTotal = 0
		requiredCPU = peakDemoCPU
		requiredMemory = peakDemoMemory
	}
	capacity := engCapacitySnapshot(evidence, findings)
	audit := M{
		"pod_request_cpu_millicores":     podCPU,
		"pod_request_memory_bytes":       podMemory,
		"old_pod_request_cpu_millicores": 0.0,
		"old_pod_request_memory_bytes":   0.0,
		"replicas":                       replicas,
		"surge_pods":                     surge,
		"new_pods_reserved":              newPodsAtPeak,
		"additional_pods_reserved":       newPodsAtPeak,
		"peak_total_pods":                peakTotalPods,
		"peak_demo_cpu_millicores":       peakDemoCPU,
		"peak_demo_memory_bytes":         peakDemoMemory,
		"retained_old_replicas":          0,
		"required_cpu_millicores":        requiredCPU,
		"required_memory_bytes":          requiredMemory,
		"source":                         nil,
	}
	if rolling {
		audit["old_pod_request_cpu_millicores"] = oldPodCPU
		audit["old_pod_request_memory_bytes"] = oldPodMemory
		audit["retained_old_replicas"] = oldCount
	}
	if capacity == nil {
		findings.add("CAPACITY_MISSING", engDecisionError, "evidence.capacity",
			"scheduling capacity evidence is missing", nil)
		return audit
	}
	for key, value := range capacity {
		audit[key] = value
	}
	if workers, ok := engNumber(capacity["workers_ready"]); ok && workers == 0 {
		findings.add("NO_SCHEDULABLE_WORKER", engDecisionReview, "evidence.capacity.workers_ready",
			"no Ready, schedulable worker is available for the rollout", M{"capacity": capacity})
	} else if engTruthy(capacity["overcommitted"]) {
		findings.add("CAPACITY_OVERCOMMITTED", engDecisionReview, "evidence.capacity",
			"existing Pod requests already exceed worker allocatable capacity", M{"capacity": capacity})
	}
	cpuAvailable, cpuAvailableOK := engNumber(capacity["available_cpu_millicores"])
	memoryAvailable, memoryAvailableOK := engNumber(capacity["available_memory_bytes"])
	if !cpuAvailableOK {
		cpuAvailable = 0
	}
	if !memoryAvailableOK {
		memoryAvailable = 0
	}
	insufficient := requiredCPU > cpuAvailable || requiredMemory > memoryAvailable
	allocatableCPU, allocatableCPUOK := engNumber(capacity["allocatable_cpu_millicores"])
	allocatableMemory, allocatableMemoryOK := engNumber(capacity["allocatable_memory_bytes"])
	existingCPU, existingCPUOK := engNumber(capacity["existing_pods_requests_cpu_millicores"])
	existingMemory, existingMemoryOK := engNumber(capacity["existing_pods_requests_memory_bytes"])
	var projectedCPU, projectedMemory any
	if rolling {
		if existingCPUOK && oldCPUTotal != 0 {
			projectedCPU = math.Max(0.0, existingCPU-oldCPUTotal) + peakDemoCPU
		}
		if existingMemoryOK && oldMemoryTotal != 0 {
			projectedMemory = math.Max(0.0, existingMemory-oldMemoryTotal) + peakDemoMemory
		}
		if projected, ok := projectedCPU.(float64); ok && allocatableCPUOK && projected > allocatableCPU {
			insufficient = true
		}
		if projected, ok := projectedMemory.(float64); ok && allocatableMemoryOK && projected > allocatableMemory {
			insufficient = true
		}
		if !allocatableCPUOK && !existingCPUOK && oldPodCPU > podCPU && peakDemoCPU > cpuAvailable {
			insufficient = true
		}
		if !allocatableMemoryOK && !existingMemoryOK && oldPodMemory > podMemory && peakDemoMemory > memoryAvailable {
			insufficient = true
		}
	}
	audit["projected_total_cpu_millicores"] = projectedCPU
	audit["projected_total_memory_bytes"] = projectedMemory
	if insufficient {
		// Capacity fixtures may omit allocatable totals. Keep the audit
		// evidence null in that case exactly like the Python baseline instead of
		// substituting a misleading zero.
		var allocatableCPUEvidence, allocatableMemoryEvidence any
		if allocatableCPUOK {
			allocatableCPUEvidence = allocatableCPU
		}
		if allocatableMemoryOK {
			allocatableMemoryEvidence = allocatableMemory
		}
		findings.add("CAPACITY_INSUFFICIENT", engDecisionReview, "evidence.capacity",
			"rolling rollout with old Pods retained and surge Pods does not fit available worker capacity",
			M{
				"required_cpu_millicores":        requiredCPU,
				"available_cpu_millicores":       cpuAvailable,
				"required_memory_bytes":          requiredMemory,
				"available_memory_bytes":         memoryAvailable,
				"surge_pods":                     surge,
				"additional_pods_reserved":       newPodsAtPeak,
				"peak_total_pods":                peakTotalPods,
				"retained_old_replicas":          oldCount,
				"peak_demo_cpu_millicores":       peakDemoCPU,
				"peak_demo_memory_bytes":         peakDemoMemory,
				"projected_total_cpu_millicores": projectedCPU,
				"projected_total_memory_bytes":   projectedMemory,
				"allocatable_cpu_millicores":     allocatableCPUEvidence,
				"allocatable_memory_bytes":       allocatableMemoryEvidence,
			})
	}
	return audit
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func engJSONInt(value any) int {
	parsed, ok := engInt(value)
	if !ok {
		return 0
	}
	return int(parsed)
}

// ---------------------------------------------------------------------------
// Metrics + alerts

type engMetricValue struct {
	value float64
	ok    bool
	ts    float64
	tsOK  bool
	raw   any
}

func engMetric(metrics M, key string) (engMetricValue, any) {
	raw := metrics[key]
	value := raw
	embeddedTS := 0.0
	embeddedOK := false
	if mapping, ok := engAsMap(raw); ok {
		if candidate, present := mapping["value"]; present {
			value = candidate
		} else if values, ok := engAsList(mapping["values"]); ok && len(values) > 0 {
			value = values[len(values)-1]
		}
		var tsRaw any
		if candidate, present := mapping["timestamp"]; present {
			tsRaw = candidate
		} else if candidate, present := mapping["time"]; present {
			tsRaw = candidate
		} else if candidate, present := mapping["ts"]; present {
			tsRaw = candidate
		}
		embeddedTS, embeddedOK = engTimestamp(tsRaw)
	}
	number, ok := engNumber(value)
	return engMetricValue{value: number, ok: ok, ts: embeddedTS, tsOK: embeddedOK, raw: raw}, raw
}

func engSourceTimestamp(evidence, metrics M, key string, embeddedTS float64, embeddedOK bool) (float64, bool) {
	sources, ok := engAsMap(evidence["source_timestamps"])
	if !ok {
		sources, _ = engAsMap(metrics["source_timestamps"])
	}
	if sources != nil {
		aliases := map[string][]string{
			"memory_working_set_bytes": {"memory_working_set_bytes", "memory", "memory_max_over_15m"},
			"request_rate":             {"request_rate", "rate", "requests_rate"},
			"error_ratio":              {"error_ratio", "error_rate"},
			"p95_seconds":              {"p95_seconds", "p95", "latency_p95"},
			"alerts":                   {"alerts"},
		}[key]
		if aliases == nil {
			aliases = []string{key}
		}
		for _, alias := range aliases {
			candidate := sources[alias]
			if mapping, ok := engAsMap(candidate); ok {
				if value, present := mapping["timestamp"]; present {
					candidate = value
				} else if value, present := mapping["ts"]; present {
					candidate = value
				} else {
					candidate = nil
				}
			}
			if parsed, ok := engTimestamp(candidate); ok {
				return parsed, true
			}
		}
	}
	if embeddedOK {
		return embeddedTS, true
	}
	return 0, false
}

func engRelevantFiringAlerts(alerts any, namespace, deployment string) []M {
	if _, isBool := alerts.(bool); isBool {
		return []M{}
	}
	if count, ok := engInt(alerts); ok {
		if count > 0 {
			return []M{{"name": "<unspecified>", "state": "firing", "count": count}}
		}
		return []M{}
	}
	list, ok := engAsList(alerts)
	if !ok {
		return []M{}
	}
	relevant := []M{}
	for _, rawAlert := range list {
		if text, ok := rawAlert.(string); ok {
			lowered := strings.ToLower(strings.TrimSpace(text))
			if lowered == "firing" || lowered == "active" {
				relevant = append(relevant, M{"name": text, "state": "firing"})
			}
			continue
		}
		alert, ok := engAsMap(rawAlert)
		if !ok {
			continue
		}
		var stateRaw any = "firing"
		if value, present := alert["state"]; present {
			stateRaw = value
		} else if value, present := alert["status"]; present {
			stateRaw = value
		} else if value, present := alert["alertstate"]; present {
			stateRaw = value
		}
		state := strings.ToLower(engPyStr(stateRaw))
		if state != "firing" && state != "active" {
			continue
		}
		labels, _ := engAsMap(alert["labels"])
		if labels == nil {
			labels = M{}
		}
		alertName := engPyStr(engOr(engOr(alert["name"], labels["alertname"]), ""))
		if alertName == "Watchdog" || engStringIs(labels["severity"], "none") {
			continue
		}
		alertNamespace := labels["namespace"]
		alertDeployment := engOr(engOr(labels["deployment"], labels["app"]), labels["app_kubernetes_io_name"])
		if !engPyIn(alertNamespace, nil, "", namespace) {
			continue
		}
		if !engPyIn(alertDeployment, nil, "", deployment) {
			continue
		}
		if safe, ok := engJSONSafe(alert).(M); ok {
			relevant = append(relevant, safe)
		}
	}
	return relevant
}

func engCheckMetrics(evidence, config M, newDeployment M, findings *engFindings, now float64, ttl int64) (M, float64, bool) {
	audit := M{}
	if rawErrors, present := evidence["errors"]; present {
		if errorsList, ok := engAsList(rawErrors); ok {
			for index, rawError := range errorsList {
				if index >= 25 {
					break
				}
				text := engTruncate(engPyStr(rawError), 800, "")
				findings.add("EVIDENCE_ERROR", engDecisionError,
					fmt.Sprintf("evidence.errors[%d]", index),
					"evidence collection reported an error", M{"error": text})
			}
		} else if engTruthy(rawErrors) {
			findings.add("EVIDENCE_ERROR", engDecisionError, "evidence.errors",
				"evidence collection reported an error",
				M{"error": engTruncate(engPyStr(rawErrors), 800, "")})
		}
	}
	target, targetOK := engAsMap(evidence["deployment"])
	if !targetOK || len(target) == 0 {
		findings.add("TARGET_EVIDENCE_MISSING", engDecisionError, "evidence.deployment",
			"current target Deployment health evidence is missing", nil)
	} else {
		desired, desiredOK := engNumber(target["replicas"])
		ready, readyOK := engNumber(target["ready_replicas"])
		available, availableOK := engNumber(target["available_replicas"])
		if !desiredOK || !readyOK || !availableOK {
			findings.add("TARGET_HEALTH_MISSING", engDecisionError, "evidence.deployment",
				"ready/available/desired replica fields are missing or invalid",
				M{
					"replicas":           target["replicas"],
					"ready_replicas":     target["ready_replicas"],
					"available_replicas": target["available_replicas"],
				})
		} else if desired <= 0 || ready < 1 {
			findings.add("TARGET_NOT_READY", engDecisionReview, "evidence.deployment.ready_replicas",
				"the target Deployment is offline (zero Ready replicas), so healthy metrics cannot be attributed to it",
				M{"replicas": desired, "ready_replicas": ready, "available_replicas": available})
		} else if ready < desired || available < desired {
			findings.add("TARGET_DEGRADED", engDecisionReview, "evidence.deployment",
				"the target Deployment has fewer Ready/available replicas than desired",
				M{"replicas": desired, "ready_replicas": ready, "available_replicas": available})
		}
	}
	collectedAt, collectedOK := engTimestamp(evidence["collected_at"])
	minTimestamp := collectedAt
	minTimestampOK := collectedOK
	if !collectedOK {
		findings.add("EVIDENCE_TIMESTAMP_MISSING", engDecisionError, "evidence.collected_at",
			"evidence has no valid collection timestamp", nil)
	} else {
		if now-collectedAt > float64(ttl) {
			findings.add("EVIDENCE_STALE", engDecisionError, "evidence.collected_at",
				"evidence is older than the configured TTL",
				M{"age_seconds": now - collectedAt, "ttl_seconds": ttl})
		}
		if collectedAt-now > engClockSkewToleranceSeconds {
			findings.add("EVIDENCE_TIMESTAMP_FUTURE", engDecisionError, "evidence.collected_at",
				"evidence timestamp is in the future",
				M{"delta_seconds": collectedAt - now})
		}
	}
	metrics, metricsOK := engAsMap(evidence["metrics"])
	if !metricsOK {
		findings.add("METRICS_MISSING", engDecisionError, "evidence.metrics",
			"metrics evidence is missing", nil)
		return audit, minTimestamp, minTimestampOK
	}
	lowTrafficRPS := engDefaultLowTrafficRPS
	if parsed, ok := engNumber(config["low_traffic_rps"]); ok && parsed != 0 {
		lowTrafficRPS = parsed
	}
	maxErrorRatio := engDefaultMaxErrorRatio
	if parsed, ok := engNumber(config["max_error_ratio"]); ok && parsed != 0 {
		maxErrorRatio = parsed
	}
	maxP95Seconds := engDefaultMaxP95Seconds
	if parsed, ok := engNumber(config["max_p95_seconds"]); ok && parsed != 0 {
		maxP95Seconds = parsed
	}
	memory, _ := engMetric(metrics, "memory_working_set_bytes")
	requestRate, _ := engMetric(metrics, "request_rate")
	errorRatio, _ := engMetric(metrics, "error_ratio")
	p95, _ := engMetric(metrics, "p95_seconds")
	up, _ := engMetric(metrics, "up")
	lowTraffic := requestRate.ok && requestRate.value < lowTrafficRPS
	type requiredMetric struct {
		key string
		val engMetricValue
	}
	requiredMetrics := []requiredMetric{
		{"memory_working_set_bytes", memory},
		{"request_rate", requestRate},
	}
	if errorRatio.ok || !lowTraffic {
		requiredMetrics = append(requiredMetrics, requiredMetric{"error_ratio", errorRatio})
	}
	if p95.ok || !lowTraffic {
		requiredMetrics = append(requiredMetrics, requiredMetric{"p95_seconds", p95})
	}
	if _, present := metrics["up"]; present && up.ok {
		requiredMetrics = append(requiredMetrics, requiredMetric{"up", up})
	}
	if !memory.ok {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.memory_working_set_bytes",
			"memory max-over-15m is missing or non-finite",
			M{"raw": engJSONSafe(metrics["memory_working_set_bytes"])})
	} else if memory.value < 0 {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.memory_working_set_bytes", "memory measurement is negative",
			M{"value": memory.value})
	}
	if !requestRate.ok {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.request_rate", "request rate is missing or non-finite",
			M{"raw": engJSONSafe(metrics["request_rate"])})
	} else if requestRate.value < 0 {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.request_rate", "request rate is negative",
			M{"value": requestRate.value})
	}
	if !errorRatio.ok {
		if !lowTraffic {
			findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
				"evidence.metrics.error_ratio", "error ratio is missing or non-finite",
				M{"raw": engJSONSafe(metrics["error_ratio"])})
		}
	} else if errorRatio.value < 0 || errorRatio.value > 1 {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.error_ratio", "error ratio is outside [0, 1]",
			M{"value": errorRatio.value})
	}
	if !p95.ok {
		if !lowTraffic {
			findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
				"evidence.metrics.p95_seconds", "p95 latency is missing or non-finite",
				M{"raw": engJSONSafe(metrics["p95_seconds"])})
		}
	} else if p95.value < 0 {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError,
			"evidence.metrics.p95_seconds", "p95 latency is negative",
			M{"value": p95.value})
	}
	if _, present := metrics["up"]; !present {
		findings.add("TARGET_UP_MISSING", engDecisionError, "evidence.metrics.up",
			"target up/scrape evidence is required for every release evaluation", nil)
	} else if !up.ok {
		findings.add("METRIC_MISSING_OR_INVALID", engDecisionError, "evidence.metrics.up",
			"target up value is non-finite or invalid",
			M{"raw": engJSONSafe(metrics["up"])})
	} else if up.value < 1 {
		findings.add("TARGET_UP_NOT_READY", engDecisionReview, "evidence.metrics.up",
			"Prometheus reports the target scrape as down", M{"up": up.value})
	}
	presence, _ := engAsMap(metrics["series_presence"])
	for _, source := range []string{"up", "memory", "requests_total", "latency_bucket"} {
		value, present := presence[source]
		if !present || value != true {
			ruleID := "METRIC_SOURCE_MISSING"
			if lowTraffic {
				ruleID = "LOW_TRAFFIC_SOURCE_MISSING"
			}
			findings.add(ruleID, engDecisionError,
				"evidence.metrics.series_presence."+source,
				"raw source series must exist for every release evaluation", M{"source": source})
		}
	}
	var relevantAlerts []M
	if _, present := metrics["alerts"]; !present {
		findings.add("ALERTS_MISSING", engDecisionError, "evidence.metrics.alerts",
			"firing alert evidence is missing", nil)
		relevantAlerts = []M{}
	} else {
		relevantAlerts = engRelevantFiringAlerts(metrics["alerts"],
			engPyStr(config["namespace"]), engPyStr(config["deployment"]))
	}
	checkTimestamp := func(key string, metric engMetricValue) (float64, bool) {
		timestamp, ok := engSourceTimestamp(evidence, metrics, key, metric.ts, metric.tsOK)
		if !ok {
			findings.add("METRIC_TIMESTAMP_MISSING", engDecisionError,
				"evidence.metrics.source_timestamps."+key,
				"metric has no real source timestamp", nil)
			return 0, false
		}
		if !minTimestampOK || timestamp < minTimestamp {
			minTimestamp = timestamp
			minTimestampOK = true
		}
		if now-timestamp > float64(ttl) {
			findings.add("METRIC_STALE", engDecisionError,
				"evidence.metrics.source_timestamps."+key,
				"metric sample is older than the configured TTL",
				M{"age_seconds": now - timestamp, "ttl_seconds": ttl})
		}
		if timestamp-now > engClockSkewToleranceSeconds {
			findings.add("METRIC_TIMESTAMP_FUTURE", engDecisionError,
				"evidence.metrics.source_timestamps."+key,
				"metric timestamp is in the future",
				M{"delta_seconds": timestamp - now})
		}
		return timestamp, true
	}
	for _, required := range requiredMetrics {
		if required.val.ok {
			checkTimestamp(required.key, required.val)
		}
	}
	if lowTraffic && !p95.ok {
		checkTimestamp("p95_seconds", p95)
	}
	if lowTraffic {
		findings.add("LOW_TRAFFIC", engDecisionReview, "evidence.metrics.request_rate",
			"traffic is too low to treat observed zero errors or latency as healthy",
			M{
				"request_rate":  requestRate.value,
				"threshold_rps": lowTrafficRPS,
				"error_ratio":   nullableMetric(errorRatio),
				"p95_seconds":   nullableMetric(p95),
			})
	}
	if errorRatio.ok && errorRatio.value > maxErrorRatio {
		findings.add("HIGH_ERROR_RATIO", engDecisionReview, "evidence.metrics.error_ratio",
			"the 5m error ratio exceeds the review threshold",
			M{"error_ratio": errorRatio.value, "threshold": maxErrorRatio})
	}
	if p95.ok && p95.value > maxP95Seconds {
		findings.add("HIGH_P95_LATENCY", engDecisionReview, "evidence.metrics.p95_seconds",
			"p95 latency exceeds the review threshold",
			M{"p95_seconds": p95.value, "threshold": maxP95Seconds})
	}
	if len(relevantAlerts) > 0 {
		alertWindow := relevantAlerts
		if len(alertWindow) > 10 {
			alertWindow = alertWindow[:10]
		}
		findings.add("FIRING_ALERTS", engDecisionReview, "evidence.metrics.alerts",
			"one or more relevant alerts are firing",
			M{"alerts": alertWindow, "count": len(relevantAlerts)})
	}
	if memory.ok {
		engCheckMemory(metrics, newDeployment, config, findings)
	}
	audit["memory_working_set_bytes"] = nullableMetric(memory)
	audit["request_rate"] = nullableMetric(requestRate)
	audit["error_ratio"] = nullableMetric(errorRatio)
	audit["p95_seconds"] = nullableMetric(p95)
	audit["up"] = nullableMetric(up)
	audit["low_traffic"] = lowTraffic
	audit["firing_alerts"] = len(relevantAlerts)
	audit["source_timestamps"] = M{
		"memory_working_set_bytes": sourceTimestampValue(evidence, metrics, "memory_working_set_bytes", memory),
		"request_rate":             sourceTimestampValue(evidence, metrics, "request_rate", requestRate),
		"error_ratio":              sourceTimestampValue(evidence, metrics, "error_ratio", errorRatio),
		"p95_seconds":              sourceTimestampValue(evidence, metrics, "p95_seconds", p95),
		"up":                       sourceTimestampValue(evidence, metrics, "up", up),
	}
	return audit, minTimestamp, minTimestampOK
}

func nullableMetric(metric engMetricValue) any {
	if !metric.ok {
		return nil
	}
	return metric.value
}

func sourceTimestampValue(evidence, metrics M, key string, metric engMetricValue) any {
	value, ok := engSourceTimestamp(evidence, metrics, key, metric.ts, metric.tsOK)
	if !ok {
		return nil
	}
	return value
}

// ---------------------------------------------------------------------------
// Context + AI

func engCheckTreeContext(context M, findings *engFindings) {
	if engIsTrueIdentity(context["argo_source_changed"]) {
		findings.add("ARGOCD_SOURCE_CHANGED", engDecisionBlock, "context.argo_source_changed",
			"the Argo CD source repository/path/revision changed", nil)
	}
	// Python uses context.get("tree_changes") and falls back to changed_paths
	// whenever that value is None, including an explicit JSON null.
	paths := context["tree_changes"]
	if paths == nil {
		paths = context["changed_paths"]
	}
	if text, ok := paths.(string); ok {
		paths = []any{text}
	}
	list, ok := engAsList(paths)
	if !ok {
		return
	}
	argoSeen := map[string]bool{}
	if len(list) > 500 {
		list = list[:500]
	}
	for _, raw := range list {
		path := strings.ToLower(strings.ReplaceAll(engPyStr(raw), "\\", "/"))
		if strings.HasPrefix(path, "gitops/argocd/") ||
			strings.HasSuffix(path, "/application.yaml") ||
			strings.HasSuffix(path, "/project.yaml") {
			if !argoSeen[path] {
				argoSeen[path] = true
				findings.add("ARGOCD_MANIFEST_CHANGE", engDecisionReview, "context.tree_changes",
					"an Argo CD source/application/project file changed", M{"path": engPyStr(raw)})
			}
		} else if strings.HasPrefix(path, "charts/demo/templates/") || path == "charts/demo/chart.yaml" {
			findings.add("TEMPLATE_FILE_CHANGE", engDecisionReview, "context.tree_changes",
				"the Helm chart template changed and requires review even when current renders match",
				M{"path": engPyStr(raw)})
		}
	}
}

func engCheckAI(aiResult M, config M, findings *engFindings) M {
	audit := M{"status": nil}
	required := true
	if value, present := config["ai_required"]; present {
		required = engTruthy(value)
	}
	if aiResult == nil {
		if required {
			findings.add("AI_REQUIRED_UNAVAILABLE", engDecisionError, "ai_result",
				"DeepSeek review is required but no result was supplied", nil)
			audit["status"] = "missing"
		} else {
			audit["status"] = "disabled"
		}
		return audit
	}
	status := aiResult["status"]
	audit["status"] = status
	if model, ok := aiResult["model"].(string); ok {
		audit["model"] = model
	} else {
		audit["model"] = nil
	}
	if engStringIs(status, "error") {
		errorValue := any("unknown error")
		if value, present := aiResult["error"]; present {
			errorValue = value
		}
		findings.add("AI_UNAVAILABLE", engDecisionError, "ai_result.error",
			"DeepSeek review failed closed",
			M{"error": engTruncate(engPyStr(errorValue), 1000, "")})
		return audit
	}
	if !engStringIs(status, "ok") {
		findings.add("AI_INVALID_RESULT", engDecisionError, "ai_result.status",
			"AI result has an invalid status", M{"status": status})
		return audit
	}
	summary, summaryOK := aiResult["summary"].(string)
	if !summaryOK || strings.TrimSpace(summary) == "" {
		findings.add("AI_INVALID_RESULT", engDecisionError, "ai_result.summary",
			"AI result has no summary", nil)
	}
	risks, risksOK := engAsList(aiResult["additional_risks"])
	if !risksOK {
		findings.add("AI_INVALID_RESULT", engDecisionError, "ai_result.additional_risks",
			"AI additional_risks must be a list", nil)
		risks = []any{}
	}
	citations, citationsOK := engAsList(aiResult["citations"])
	if !citationsOK {
		findings.add("AI_INVALID_RESULT", engDecisionError, "ai_result.citations",
			"AI citations must be a list", nil)
		citations = []any{}
	} else {
		valid := []any{}
		for index, rawCitation := range citations {
			if index >= 20 {
				break
			}
			citation, isMap := engAsMap(rawCitation)
			caseID, caseOK := citation["case_id"].(string)
			quote, quoteOK := citation["quote"].(string)
			if !isMap || !caseOK || caseID == "" || !quoteOK || strings.TrimSpace(quote) == "" {
				findings.add("AI_INVALID_RESULT", engDecisionError,
					fmt.Sprintf("ai_result.citations[%d]", index),
					"AI citation must contain case_id and quote", nil)
				continue
			}
			valid = append(valid, citation)
		}
		citations = valid
	}
	normalizedRisks := []M{}
	for index, rawRisk := range risks {
		if index >= 20 {
			break
		}
		if text, ok := rawRisk.(string); ok {
			normalizedRisks = append(normalizedRisks, M{
				"title": engTruncate(text, 300, ""), "detail": "",
			})
			continue
		}
		risk, ok := engAsMap(rawRisk)
		if !ok {
			findings.add("AI_INVALID_RESULT", engDecisionError,
				fmt.Sprintf("ai_result.additional_risks[%d]", index),
				"AI risk entry must be a string or mapping", nil)
			continue
		}
		title := engOr(engOr(risk["title"], risk["risk"]), risk["message"])
		detail := engOr(engOr(risk["detail"], risk["why"]), "")
		titleText, titleOK := title.(string)
		if !titleOK || strings.TrimSpace(titleText) == "" {
			findings.add("AI_INVALID_RESULT", engDecisionError,
				fmt.Sprintf("ai_result.additional_risks[%d]", index),
				"AI risk entry has no title", nil)
			continue
		}
		normalizedRisks = append(normalizedRisks, M{
			"title":  engTruncate(titleText, 500, ""),
			"detail": engTruncate(engPyStr(detail), 1000, ""),
		})
	}
	if len(normalizedRisks) > 0 {
		window := normalizedRisks
		if len(window) > 10 {
			window = window[:10]
		}
		findings.add("AI_ADDITIONAL_RISK", engDecisionReview, "ai_result.additional_risks",
			"the model identified additional risk; it can only raise the decision to REVIEW",
			M{"risks": window, "count": len(normalizedRisks)})
	}
	audit["additional_risks"] = len(normalizedRisks)
	audit["citations"] = len(citations)
	return audit
}

func engSanitizeContext(context M) M {
	var sanitize func(value any, depth int) any
	sanitize = func(value any, depth int) any {
		if depth > 8 {
			return "<depth-limit>"
		}
		if mapping, ok := engAsMap(value); ok {
			result := M{}
			keys := make([]string, 0, len(mapping))
			for key := range mapping {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if len(keys) > 200 {
				keys = keys[:200]
			}
			for _, key := range keys {
				lowered := strings.ToLower(key)
				sensitive := false
				for _, part := range engSensitivePathParts {
					if strings.Contains(lowered, part) {
						sensitive = true
						break
					}
				}
				if sensitive {
					result[key] = "<redacted>"
				} else {
					result[key] = sanitize(mapping[key], depth+1)
				}
			}
			return result
		}
		if list, ok := engAsList(value); ok {
			if len(list) > 200 {
				list = list[:200]
			}
			out := make([]any, len(list))
			for i, item := range list {
				out[i] = sanitize(item, depth+1)
			}
			return out
		}
		if text, ok := value.(string); ok {
			return engTruncate(text, 2000, "...")
		}
		return engJSONSafe(value)
	}
	if context == nil {
		return M{}
	}
	result, ok := sanitize(context, 0).(M)
	if !ok {
		return M{}
	}
	return result
}

// ---------------------------------------------------------------------------
// Public API

// Evaluate is the fail-closed release evaluation entry point. Invalid input
// (which raises ValueError in the Python baseline) is reported as an ERROR
// decision because the Go interface has no error return. This keeps callers
// from ever treating malformed data as PASS. A defensive recover converts any
// unexpected panic on hostile in-memory values into the same ERROR report.
func Evaluate(oldResources, newResources []M, evidence, config, context, aiResult M) (result M) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = engInvalidInputResult(
				fmt.Errorf("evaluation panic: %v", recovered),
				oldResources, newResources, context)
		}
	}()
	result, err := engEvaluate(oldResources, newResources, evidence, config, context, aiResult)
	if err != nil {
		return engInvalidInputResult(err, oldResources, newResources, context)
	}
	return result
}

func engEvaluate(oldResourcesIn, newResourcesIn []M, evidence, config, context, aiResult M) (M, error) {
	oldResources, err := engFlattenResources(oldResourcesIn)
	if err != nil {
		return nil, err
	}
	newResources, err := engFlattenResources(newResourcesIn)
	if err != nil {
		return nil, err
	}
	if evidence == nil {
		evidence = M{}
	}
	if config == nil {
		config = M{}
	}
	if context == nil {
		context = M{}
	}
	namespace := engDefaultNamespace
	if value, present := config["namespace"]; present {
		namespace = engPyStr(value)
	}
	deploymentName := engDefaultDeployment
	if value, present := config["deployment"]; present {
		deploymentName = engPyStr(value)
	}
	if !engDNSLabelRE.MatchString(namespace) {
		return nil, errors.New("invalid namespace")
	}
	if !engDNSLabelRE.MatchString(deploymentName) {
		return nil, errors.New("invalid deployment name")
	}
	allowedRepo := engDefaultAllowedImageRepo
	if value, present := config["allowed_image_repository"]; present {
		allowedRepo = engPyStr(value)
	}
	if allowedRepo == "" || strings.IndexFunc(allowedRepo, unicode.IsSpace) >= 0 {
		return nil, errors.New("invalid allowed_image_repository")
	}
	normalizedConfig := M{}
	for key, value := range config {
		normalizedConfig[key] = value
	}
	normalizedConfig["namespace"] = namespace
	normalizedConfig["deployment"] = deploymentName
	normalizedConfig["allowed_image_repository"] = allowedRepo
	requireDigest := true
	if value, present := config["require_digest"]; present {
		requireDigest = engTruthy(value)
	}
	normalizedConfig["require_digest"] = requireDigest
	ttlRaw, present := config["evidence_ttl_seconds"]
	if !present {
		ttlRaw = engDefaultEvidenceTTL
	}
	ttlFloat, ok := engFloatStrict(ttlRaw)
	if !ok {
		return nil, errors.New("invalid evidence_ttl_seconds")
	}
	ttl := int64(ttlFloat)
	if ttl <= 0 {
		return nil, errors.New("evidence_ttl_seconds must be positive")
	}
	var nowValue any
	if value, present := context["evaluated_at"]; present {
		nowValue = value
	} else {
		nowValue = context["now"]
	}
	var now float64
	if nowValue == nil {
		now = float64(Now())
	} else {
		parsed, ok := engTimestamp(nowValue)
		if !ok {
			return nil, errors.New("context.evaluated_at must be a Unix timestamp")
		}
		now = parsed
	}
	nowInt := int64(now)
	oldIndex := engIndexResources(oldResources, normalizedConfig)
	newIndex := engIndexResources(newResources, normalizedConfig)
	findings := newEngFindings()
	engCheckResourceScope(newResources, newIndex, normalizedConfig, findings)
	oldDeployment := engTargetResource(oldIndex, "Deployment", namespace, deploymentName)
	newDeployment := engTargetResource(newIndex, "Deployment", namespace, deploymentName)
	deploymentOK := engCheckDeployment(oldDeployment, newDeployment, normalizedConfig, findings)
	engCheckScheduling(newDeployment, evidence, findings)
	capacityAudit := M{}
	if deploymentOK {
		engCheckResourceReduction(oldDeployment, newDeployment, findings)
		capacityAudit = engCheckCapacity(evidence, oldDeployment, newDeployment, findings)
	}
	changes, podTemplateChanged, changesTruncated := engChangesBetween(oldIndex, newIndex)
	engCheckTreeContext(context, findings)
	metricsAudit, minTimestamp, minTimestampOK := engCheckMetrics(
		evidence, normalizedConfig, newDeployment, findings, now, ttl)
	aiAudit := engCheckAI(aiResult, normalizedConfig, findings)
	targetService := engTargetResource(newIndex, "Service", namespace, deploymentName)
	oldService := engTargetResource(oldIndex, "Service", namespace, deploymentName)
	if oldService != nil && targetService == nil {
		findings.add("SERVICE_REMOVED", engDecisionReview,
			"Service/"+namespace+"/"+deploymentName,
			"the demo Service would be removed", nil)
	}
	if newDeployment != nil && targetService == nil {
		findings.add("SERVICE_MISSING", engDecisionReview,
			"Service/"+namespace+"/"+deploymentName,
			"the rendered release has no demo Service", nil)
	}
	if changesTruncated {
		findings.add("CHANGES_TRUNCATED", engDecisionReview, "changes",
			"the rendered field diff was truncated; manual review is required",
			M{"max_changes": engMaxTotalChanges})
	}
	decision := findings.decision()
	findingsList := findings.sorted()
	expiresBase := now
	if minTimestampOK && minTimestamp < expiresBase {
		expiresBase = minTimestamp
	}
	expiresAt := int64(expiresBase + float64(ttl))
	aiRequired := true
	if value, present := normalizedConfig["ai_required"]; present {
		aiRequired = engTruthy(value)
	}
	evidenceCollectedAt := any(nil)
	if value, ok := engTimestamp(evidence["collected_at"]); ok {
		evidenceCollectedAt = value
	}
	contextOut := engSanitizeContext(context)
	contextOut["namespace"] = namespace
	contextOut["deployment"] = deploymentName
	contextOut["old_resource_count"] = len(oldResources)
	contextOut["new_resource_count"] = len(newResources)
	contextOut["pod_template_changed"] = podTemplateChanged
	contextOut["ai_required"] = aiRequired
	contextOut["ai_status"] = aiAudit["status"]
	contextOut["evidence_collected_at"] = evidenceCollectedAt
	contextOut["evidence_ttl_seconds"] = ttl
	checks := make([]any, len(findingsList))
	for i, item := range findingsList {
		checks[i] = M{
			"rule_id":  item["rule_id"],
			"severity": item["severity"],
			"field":    item["field"],
			"message":  item["message"],
		}
	}
	newDigest := engDigestResources(newResources)
	oldDigest := engDigestResources(oldResources)
	audit := M{
		"schema_version":       engSchemaVersion,
		"rule_version":         RuleVersion,
		"evaluated_at":         nowInt,
		"checks":               checks,
		"metrics":              engJSONSafe(metricsAudit),
		"capacity":             engJSONSafe(capacityAudit),
		"ai":                   aiAudit,
		"changes_count":        len(changes),
		"pod_template_changed": podTemplateChanged,
		"render_digest":        newDigest,
		"old_render_digest":    oldDigest,
	}
	return M{
		"decision":          decision,
		"findings":          findingsList,
		"changes":           changes,
		"context":           contextOut,
		"render_digest":     newDigest,
		"old_render_digest": oldDigest,
		"evaluated_at":      nowInt,
		"expires_at":        expiresAt,
		"rule_version":      RuleVersion,
		"audit":             audit,
	}, nil
}

func engInvalidInputResult(err error, oldResources, newResources []M, context M) M {
	now := float64(Now())
	if parsed, ok := engTimestamp(engOr(context["evaluated_at"], context["now"])); ok {
		now = parsed
	}
	nowInt := int64(now)
	message := engTruncate(err.Error(), 800, "")
	finding := M{
		"rule_id":  engInvalidInputRule,
		"severity": engDecisionError,
		"field":    "input",
		"message":  message,
		"evidence": M{},
	}
	newDigest := engDigestResources(newResources)
	oldDigest := engDigestResources(oldResources)
	contextOut := engSanitizeContext(context)
	audit := M{
		"schema_version": engSchemaVersion,
		"rule_version":   RuleVersion,
		"evaluated_at":   nowInt,
		"checks": []any{M{
			"rule_id": engInvalidInputRule, "severity": engDecisionError,
			"field": "input", "message": message,
		}},
		"metrics":              M{},
		"capacity":             M{},
		"ai":                   M{"status": nil},
		"changes_count":        0,
		"pod_template_changed": false,
		"render_digest":        newDigest,
		"old_render_digest":    oldDigest,
	}
	return M{
		"decision":          engDecisionError,
		"findings":          []M{finding},
		"changes":           []M{},
		"context":           contextOut,
		"render_digest":     newDigest,
		"old_render_digest": oldDigest,
		"evaluated_at":      nowInt,
		"expires_at":        nowInt + engInputErrorTTL,
		"rule_version":      RuleVersion,
		"audit":             audit,
	}
}
