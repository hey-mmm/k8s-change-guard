package guard

// Render the tiny, fixed Helm surface used by the demo workload.
//
// Security properties preserved from the Python baseline:
//   - Production rendering is Linux-only and always uses bubblewrap. There is
//     no "run helm directly" fallback.
//   - Only charts/demo and gitops/demo/values.yaml are copied into a fresh
//     temporary directory. Symlinks, extra chart roots (including charts/
//     dependencies), oversized files, and non-data values are rejected.
//   - The sandbox has no network, no host home, no service credentials, no Helm
//     plugins, no dependency update, no post-renderer, and bounded time, memory,
//     file size, document count, and output size.
//   - Candidate files are data only. We never execute a candidate Shell/Python
//     script and never invoke a candidate-provided binary.
//
// The fixture-only pre-rendered path is available on non-Linux hosts and when
// fixture_mode is explicitly enabled. It can never be enabled on Linux unless
// fixture_mode is explicitly set, and it never executes anything.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	rndChartRelPath  = "charts/demo"
	rndValuesRelPath = "gitops/demo/values.yaml"
	rndHelmTarget    = "/guard-helm"

	rndDefaultTimeoutSeconds     = 60
	rndDefaultOutputLimitBytes   = 4 * 1024 * 1024
	rndDefaultMemoryLimitBytes   = 2 * 1024 * 1024 * 1024
	rndDefaultTmpfsBytes         = 64 * 1024 * 1024
	rndMaxInputFileBytes         = 2 * 1024 * 1024
	rndMaxInputTotalBytes        = 12 * 1024 * 1024
	rndMaxInputFiles             = 256
	rndMaxManifestDocuments      = 512
	rndMaxStructureDepth         = 100
	rndMaxStructureNodes         = 200000
	rndSandboxClockSkewTolerance = 120
)

var rndAllowedChartRootEntries = map[string]bool{
	"Chart.yaml":         true,
	"values.yaml":        true,
	"values.schema.json": true,
	".helmignore":        true,
	"templates":          true,
}

var rndForbiddenTemplateRE = regexp.MustCompile(
	`\b(lookup|tpl|now|randAlphaNum|randAlpha|randAscii|randNumeric|randBytes|` +
		`uuidv4|genCA|genSelfSignedCert|genSignedCert|encryptAES|derivePassword|` +
		`getHostByName)\b|\.Capabilities\b|\.Release\.(Revision|IsInstall|IsUpgrade)\b`)

var rndDNSLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var rndKubeVersionRE = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)(\.(0|[1-9]\d*))?$`)

// RenderError is a fail-closed renderer failure with a stable machine-readable
// code, mirroring the Python RenderError.
type RenderError struct {
	Code    string
	Message string
	Details M
}

func (e *RenderError) Error() string { return e.Message }

// AsDict returns the stable structured error representation.
func (e *RenderError) AsDict() M {
	details := e.Details
	if details == nil {
		details = M{}
	}
	return M{"code": e.Code, "message": e.Message, "details": details}
}

func rndErr(code, format string, args ...any) *RenderError {
	return &RenderError{Code: code, Message: fmt.Sprintf(format, args...), Details: M{}}
}

func rndErrDetails(code, message string, details M) *RenderError {
	if details == nil {
		details = M{}
	}
	return &RenderError{Code: code, Message: message, Details: details}
}

// Test seams. Production behavior is the default implementation.
var (
	rndIsLinux        = func() bool { return runtime.GOOS == "linux" }
	rndRequireSandbox = rndRequireSandboxImpl
	rndExecute        = rndExecuteImpl
	// Fixed absolute candidates only. The daemon's PATH is never consulted for
	// the resource-limit wrapper, so a candidate tree or inherited environment
	// cannot substitute a different executable.
	rndPrlimitCandidates = []string{"/usr/bin/prlimit", "/bin/prlimit"}
)

// rndPyStr mirrors Python str() for the scalar config values that can appear in
// a decoded YAML/JSON map.
func rndPyStr(value any) string {
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
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func rndTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case int64:
		return v != 0
	case int32:
		return v != 0
	case uint64:
		return v != 0
	case float64:
		return v != 0 && !math.IsNaN(v)
	case float32:
		return v != 0 && !math.IsNaN(float64(v))
	case []any:
		return len(v) > 0
	case []M:
		return len(v) > 0
	case M:
		return len(v) > 0
	default:
		return true
	}
}

// rndBoundedInt performs the same explicit integer/range validation as the
// Python renderer. Integral JSON numbers are accepted because encoding/json
// decodes every number as float64; booleans and fractional values are not.
func rndBoundedInt(config M, key string, def, minimum, maximum int) (int, error) {
	raw, present := config[key]
	if !present {
		return def, nil
	}
	value, ok := rndIntValue(raw)
	if !ok {
		return 0, rndErr("invalid_render_config", "%s must be an integer", key)
	}
	if value < minimum || value > maximum {
		return 0, rndErr("invalid_render_config", "%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func rndIntValue(raw any) (int, bool) {
	switch v := raw.(type) {
	case bool:
		return 0, false
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
			return 0, false
		}
		if v > float64(^uint(0)>>1) || v < -float64(^uint(0)>>1)-1 {
			return 0, false
		}
		return int(v), true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f {
			return 0, false
		}
		return int(f), true
	}
	return 0, false
}

func rndConfigString(config M, key, fallback string) string {
	raw, present := config[key]
	if !present {
		return fallback
	}
	return rndPyStr(raw)
}

func rndValidateConfig(config M) (M, error) {
	if config == nil {
		config = M{}
	}
	chartRel := rndConfigString(config, "chart_rel_path", rndChartRelPath)
	valuesRel := rndConfigString(config, "values_rel_path", rndValuesRelPath)
	if chartRel != rndChartRelPath || valuesRel != rndValuesRelPath {
		return nil, rndErr("path_not_permitted",
			"the renderer only accepts charts/demo and gitops/demo/values.yaml")
	}
	namespace := rndConfigString(config, "namespace", "demo")
	release := rndConfigString(config, "release_name", "demo")
	if err := rndValidateDNSLabel(namespace, "namespace"); err != nil {
		return nil, err
	}
	if err := rndValidateDNSLabel(release, "release_name"); err != nil {
		return nil, err
	}
	kubeVersion := rndConfigString(config, "kube_version", "1.37.2")
	if !rndKubeVersionRE.MatchString(kubeVersion) {
		return nil, rndErr("invalid_render_config", "invalid kube_version")
	}
	timeout, err := rndBoundedInt(config, "render_timeout_seconds", rndDefaultTimeoutSeconds, 1, 600)
	if err != nil {
		return nil, err
	}
	outputLimit, err := rndBoundedInt(config, "render_output_limit_bytes",
		rndDefaultOutputLimitBytes, 1024, 64*1024*1024)
	if err != nil {
		return nil, err
	}
	memoryLimit, err := rndBoundedInt(config, "sandbox_memory_bytes",
		rndDefaultMemoryLimitBytes, 64*1024*1024, 8*1024*1024*1024)
	if err != nil {
		return nil, err
	}
	tmpfsBytes, err := rndBoundedInt(config, "sandbox_tmpfs_bytes",
		rndDefaultTmpfsBytes, 1024*1024, 1024*1024*1024)
	if err != nil {
		return nil, err
	}
	return M{
		"chart_rel":    chartRel,
		"values_rel":   valuesRel,
		"namespace":    namespace,
		"release":      release,
		"kube_version": kubeVersion,
		"helm":         rndConfigString(config, "helm", "/usr/local/bin/helm"),
		"bwrap":        rndConfigString(config, "bwrap", "/usr/bin/bwrap"),
		"timeout":      timeout,
		"output_limit": outputLimit,
		"memory_limit": memoryLimit,
		"tmpfs_bytes":  tmpfsBytes,
	}, nil
}

func rndValidateDNSLabel(value, field string) error {
	if len(value) > 63 || !rndDNSLabelRE.MatchString(value) {
		return rndErr("invalid_render_config", "%s is not a valid DNS label", field)
	}
	return nil
}

// rndAssertNoSymlink rejects a symlink at path. A missing path is not itself a
// symlink; the caller performs the subsequent existence/type check.
func rndAssertNoSymlink(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return rndErr("path_unreadable", "cannot inspect %s: %v", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return rndErr("symlink_not_permitted", "%s must not be a symlink", label)
	}
	return nil
}

func rndAssertChainWithoutSymlinks(root, target, label string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return rndErr("path_not_permitted", "%s escapes the candidate tree", label)
	}
	current := root
	if err := rndAssertNoSymlink(current, label+" root"); err != nil {
		return err
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := rndAssertNoSymlink(current, label); err != nil {
			return err
		}
	}
	return nil
}

func rndReadRegularFile(path string, limit int, label string) ([]byte, error) {
	if err := rndAssertNoSymlink(path, label); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, rndErr("path_unreadable", "cannot stat %s: %v", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, rndErr("path_not_permitted", "%s is not a regular file", label)
	}
	if info.Size() > int64(limit) {
		return nil, rndErrDetails("input_too_large",
			fmt.Sprintf("%s exceeds %d bytes", label, limit),
			M{"size": info.Size(), "limit": limit})
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, rndErr("path_unreadable", "cannot read %s: %v", label, err)
	}
	if int64(len(raw)) > int64(limit) {
		return nil, rndErrDetails("input_too_large",
			fmt.Sprintf("%s exceeds %d bytes", label, limit),
			M{"size": len(raw), "limit": limit})
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// YAML decoding with duplicate-key, recursion, depth, and node-count guards.

type rndNodeConverter struct {
	nodes int
	stack map[*yaml.Node]bool
}

func rndNewNodeConverter() *rndNodeConverter {
	return &rndNodeConverter{stack: map[*yaml.Node]bool{}}
}

func (c *rndNodeConverter) convert(node *yaml.Node, depth int, source string) (any, error) {
	c.nodes++
	if c.nodes > rndMaxStructureNodes {
		return nil, rndErr("manifest_too_complex", "%s contains too many YAML nodes", source)
	}
	if depth > rndMaxStructureDepth {
		return nil, rndErr("manifest_too_complex", "%s YAML nesting is too deep", source)
	}
	if node == nil {
		return nil, nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return c.convert(node.Content[0], depth+1, source)
	case yaml.AliasNode:
		target := node.Alias
		if target == nil {
			return nil, rndErr("invalid_yaml", "invalid YAML alias in %s", source)
		}
		if c.stack[target] {
			return nil, rndErr("manifest_too_complex", "%s contains a recursive YAML alias", source)
		}
		return c.convert(target, depth+1, source)
	case yaml.MappingNode:
		if c.stack[node] {
			return nil, rndErr("manifest_too_complex", "%s contains a recursive YAML alias", source)
		}
		c.stack[node] = true
		defer delete(c.stack, node)
		result := M{}
		seen := map[string]bool{}
		for index := 0; index+1 < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			valueNode := node.Content[index+1]
			keyValue, err := c.convert(keyNode, depth+1, source)
			if err != nil {
				return nil, err
			}
			key, ok := rndYAMLKeyString(keyValue)
			if !ok {
				return nil, rndErr("invalid_yaml",
					"found an unhashable key in %s", source)
			}
			if seen[key] {
				return nil, rndErr("invalid_yaml",
					"found duplicate key %q in %s", key, source)
			}
			seen[key] = true
			value, err := c.convert(valueNode, depth+1, source)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, nil
	case yaml.SequenceNode:
		if c.stack[node] {
			return nil, rndErr("manifest_too_complex", "%s contains a recursive YAML alias", source)
		}
		c.stack[node] = true
		defer delete(c.stack, node)
		result := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := c.convert(child, depth+1, source)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		return result, nil
	case yaml.ScalarNode:
		return c.convertScalar(node, source)
	default:
		return nil, rndErr("invalid_yaml", "%s contains an unsupported YAML node", source)
	}
}

func (c *rndNodeConverter) convertScalar(node *yaml.Node, source string) (any, error) {
	tag := node.Tag
	if strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!") {
		return nil, rndErr("invalid_yaml", "%s contains an unsupported YAML tag %q", source, tag)
	}
	switch tag {
	case "", "!!str", "!!merge":
		return node.Value, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		var value bool
		if err := node.Decode(&value); err != nil {
			return nil, rndErr("invalid_yaml", "invalid boolean in %s: %v", source, err)
		}
		return value, nil
	case "!!int":
		var integer int64
		if err := node.Decode(&integer); err == nil {
			return integer, nil
		}
		var number float64
		if err := node.Decode(&number); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
			return number, nil
		}
		return nil, rndErr("invalid_yaml", "invalid integer in %s", source)
	case "!!float":
		var number float64
		if err := node.Decode(&number); err != nil {
			return nil, rndErr("invalid_yaml", "invalid number in %s: %v", source, err)
		}
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, rndErr("invalid_manifest", "%s contains a non-finite number", source)
		}
		return number, nil
	case "!!binary":
		return nil, rndErr("invalid_manifest", "%s contains binary data", source)
	case "!!timestamp":
		return nil, rndErr("invalid_manifest", "%s contains unsupported value type datetime", source)
	default:
		return nil, rndErr("invalid_yaml", "%s contains an unsupported YAML tag %q", source, tag)
	}
}

func rndYAMLKeyString(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "null", true
	case string:
		return v, true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	default:
		return "", false
	}
}

func rndLoadYAMLDocuments(text, source string, maxDocuments int) ([]any, error) {
	if len([]byte(text)) > rndDefaultOutputLimitBytes*4 {
		return nil, rndErr("output_too_large", "%s is too large", source)
	}
	decoder := yaml.NewDecoder(strings.NewReader(text))
	converter := rndNewNodeConverter()
	documents := []any{}
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, rndErr("invalid_yaml", "invalid YAML in %s: %v", source, err)
		}
		value, err := converter.convert(&node, 0, source)
		if err != nil {
			return nil, err
		}
		if value == nil {
			continue
		}
		documents = append(documents, value)
		if len(documents) > maxDocuments {
			return nil, rndErr("too_many_documents",
				"%s contains more than %d YAML documents", source, maxDocuments)
		}
	}
	return documents, nil
}

func rndLoadSingleYAML(text, source string) (any, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	converter := rndNewNodeConverter()
	var first any
	found := false
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, rndErr("invalid_yaml", "invalid YAML in %s: %v", source, err)
		}
		value, err := converter.convert(&node, 0, source)
		if err != nil {
			return nil, err
		}
		if value == nil {
			continue
		}
		if found {
			return nil, rndErr("invalid_yaml", "%s must contain a single YAML document", source)
		}
		first = value
		found = true
	}
	return first, nil
}

func rndLooksLikeKubernetesObject(value any) bool {
	object, ok := value.(M)
	if !ok || object == nil {
		return false
	}
	apiVersion, ok := object["apiVersion"].(string)
	if !ok || apiVersion == "" {
		return false
	}
	kind, ok := object["kind"].(string)
	return ok && kind != ""
}

func rndFlattenManifests(documents []any, source string) ([]M, error) {
	resources := []M{}
	var add func(value any) error
	add = func(value any) error {
		if !rndLooksLikeKubernetesObject(value) {
			return rndErr("invalid_manifest",
				"%s contains a document that is not a Kubernetes object", source)
		}
		object := value.(M)
		kind := object["kind"].(string)
		if kind == "List" {
			items, ok := object["items"].([]any)
			if !ok {
				return rndErr("invalid_manifest", "%s contains a List without items", source)
			}
			for _, item := range items {
				if err := add(item); err != nil {
					return err
				}
			}
			return nil
		}
		metadata, ok := object["metadata"].(M)
		if !ok {
			return rndErr("invalid_manifest", "%s contains a %s without metadata.name", source, kind)
		}
		name, ok := metadata["name"].(string)
		if !ok || name == "" {
			return rndErr("invalid_manifest", "%s contains a %s without metadata.name", source, kind)
		}
		resources = append(resources, object)
		return nil
	}
	for _, document := range documents {
		if err := add(document); err != nil {
			return nil, err
		}
	}
	if len(resources) > rndMaxManifestDocuments {
		return nil, rndErr("too_many_documents", "%s renders too many objects", source)
	}
	return resources, nil
}

// LoadRenderedManifests loads bounded, validated, already-rendered YAML
// fixtures. It never executes anything.
func LoadRenderedManifests(paths []string, config M) ([]M, error) {
	if config == nil {
		config = M{}
	}
	outputLimit, err := rndBoundedInt(config, "render_output_limit_bytes",
		rndDefaultOutputLimitBytes, 1024, 64*1024*1024)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, rndErr("invalid_input", "no rendered manifest supplied")
	}
	if len(paths) > rndMaxInputFiles {
		return nil, rndErr("input_too_large", "too many rendered manifests")
	}
	fileLimit := rndMaxInputFileBytes
	if outputLimit < fileLimit {
		fileLimit = outputLimit
	}
	totalLimit := rndMaxInputTotalBytes
	if outputLimit < totalLimit {
		totalLimit = outputLimit
	}
	documents := []any{}
	total := 0
	for index, candidate := range paths {
		info, statErr := os.Lstat(candidate)
		if statErr == nil && info.IsDir() {
			return nil, rndErr("path_not_permitted", "rendered input must be a file, not a directory")
		}
		raw, readErr := rndReadRegularFile(candidate, fileLimit, fmt.Sprintf("rendered manifest %d", index))
		if readErr != nil {
			return nil, readErr
		}
		total += len(raw)
		if total > totalLimit {
			return nil, rndErr("input_too_large", "rendered manifests exceed the size limit")
		}
		if !rndValidUTF8(raw) {
			return nil, rndErr("invalid_manifest", "rendered manifest is not UTF-8")
		}
		loaded, loadErr := rndLoadYAMLDocuments(string(raw),
			fmt.Sprintf("rendered manifest %d", index), rndMaxManifestDocuments)
		if loadErr != nil {
			return nil, loadErr
		}
		documents = append(documents, loaded...)
	}
	return rndFlattenManifests(documents, "rendered manifests")
}

func rndValidUTF8(raw []byte) bool {
	return strings.ToValidUTF8(string(raw), "\x00") == string(raw)
}

func rndCopyFileChecked(source, destination string, remaining int64, label string) (int64, error) {
	if err := rndAssertNoSymlink(source, label); err != nil {
		return 0, err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return 0, rndErr("path_unreadable", "cannot stat %s: %v", label, err)
	}
	if !info.Mode().IsRegular() {
		return 0, rndErr("path_not_permitted", "%s is not a regular file", label)
	}
	size := info.Size()
	if size > rndMaxInputFileBytes {
		return 0, rndErrDetails("input_too_large", label+" is too large", M{"size": size})
	}
	if size > remaining {
		return 0, rndErr("input_too_large", "%s exceeds the total input limit", label)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return 0, rndErr("path_unreadable", "cannot create destination for %s: %v", label, err)
	}
	input, err := os.Open(source)
	if err != nil {
		return 0, rndErr("path_unreadable", "cannot read %s: %v", label, err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return 0, rndErr("path_unreadable", "cannot write %s: %v", label, err)
	}
	written, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return 0, rndErr("path_unreadable", "cannot copy %s: %v", label, copyErr)
	}
	if closeErr != nil {
		return 0, rndErr("path_unreadable", "cannot write %s: %v", label, closeErr)
	}
	return written, nil
}

func rndCopyPermittedTree(root, workdir string, config M) (string, string, error) {
	chartRel := config["chart_rel"].(string)
	valuesRel := config["values_rel"].(string)
	chartRoot := filepath.Join(root, filepath.FromSlash(chartRel))
	valuesPath := filepath.Join(root, filepath.FromSlash(valuesRel))
	if err := rndAssertChainWithoutSymlinks(root, chartRoot, "chart path"); err != nil {
		return "", "", err
	}
	if err := rndAssertChainWithoutSymlinks(root, valuesPath, "values path"); err != nil {
		return "", "", err
	}
	chartInfo, err := os.Stat(chartRoot)
	if err != nil || !chartInfo.IsDir() {
		return "", "", rndErr("chart_missing", "%s does not exist", chartRel)
	}
	valuesInfo, err := os.Stat(valuesPath)
	if err != nil || !valuesInfo.Mode().IsRegular() {
		return "", "", rndErr("values_missing", "%s does not exist", valuesRel)
	}

	chartDestination := filepath.Join(workdir, "chart")
	if err := os.MkdirAll(chartDestination, 0700); err != nil {
		return "", "", rndErr("path_unreadable", "cannot create chart destination: %v", err)
	}
	valuesDestination := filepath.Join(workdir, "values.yaml")

	total, err := rndCopyFileChecked(valuesPath, valuesDestination, rndMaxInputTotalBytes, valuesRel)
	if err != nil {
		return "", "", err
	}
	valuesRaw, err := os.ReadFile(valuesDestination)
	if err != nil {
		return "", "", rndErr("path_unreadable", "cannot read copied values file: %v", err)
	}
	if !rndValidUTF8(valuesRaw) {
		return "", "", rndErr("invalid_values", "values file is not UTF-8")
	}
	valuesDocument, err := rndLoadSingleYAML(string(valuesRaw), "values")
	if err != nil {
		return "", "", rndErr("invalid_values", "invalid values YAML: %v", err)
	}
	if valuesDocument == nil {
		valuesDocument = M{}
	}
	if _, ok := valuesDocument.(M); !ok {
		return "", "", rndErr("invalid_values", "values file must contain a mapping")
	}

	files := 0
	entries, err := os.ReadDir(chartRoot)
	if err != nil {
		return "", "", rndErr("path_unreadable", "cannot list chart directory: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if !rndAllowedChartRootEntries[name] {
			return "", "", rndErr("unsupported_chart_entry",
				"chart entry %q is not permitted (dependencies/files/crds are rejected)", name)
		}
		if name == "templates" {
			templates := filepath.Join(chartRoot, name)
			if err := rndAssertNoSymlink(templates, "templates directory"); err != nil {
				return "", "", err
			}
			info, err := os.Stat(templates)
			if err != nil || !info.IsDir() {
				return "", "", rndErr("invalid_chart", "templates must be a directory")
			}
			walkErr := filepath.WalkDir(templates, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return rndErr("path_unreadable", "cannot walk templates directory: %v", walkErr)
				}
				if path == templates {
					return nil
				}
				if d.Type()&os.ModeSymlink != 0 {
					return rndErr("symlink_not_permitted", "templates directory must not contain symlinks")
				}
				if d.IsDir() {
					return nil
				}
				files++
				if files > rndMaxInputFiles {
					return rndErr("input_too_large", "chart has too many files")
				}
				relative, relErr := filepath.Rel(chartRoot, path)
				if relErr != nil {
					return rndErr("path_not_permitted", "chart file path escapes the chart")
				}
				destination := filepath.Join(chartDestination, relative)
				copied, copyErr := rndCopyFileChecked(path, destination,
					rndMaxInputTotalBytes-total,
					"chart file "+filepath.ToSlash(relative))
				if copyErr != nil {
					return copyErr
				}
				total += copied
				if total > rndMaxInputTotalBytes {
					return rndErr("input_too_large", "chart input exceeds the total size limit")
				}
				return nil
			})
			if walkErr != nil {
				return "", "", walkErr
			}
			continue
		}
		source := filepath.Join(chartRoot, name)
		if err := rndAssertNoSymlink(source, "chart file "+name); err != nil {
			return "", "", err
		}
		info, err := os.Stat(source)
		if err != nil || !info.Mode().IsRegular() {
			return "", "", rndErr("path_not_permitted", "chart file %s is not a regular file", name)
		}
		files++
		if files > rndMaxInputFiles {
			return "", "", rndErr("input_too_large", "chart has too many files")
		}
		copied, copyErr := rndCopyFileChecked(source, filepath.Join(chartDestination, name),
			rndMaxInputTotalBytes-total, "chart file "+name)
		if copyErr != nil {
			return "", "", copyErr
		}
		total += copied
		if total > rndMaxInputTotalBytes {
			return "", "", rndErr("input_too_large", "chart input exceeds the total size limit")
		}
	}

	chartYAML := filepath.Join(chartDestination, "Chart.yaml")
	if info, err := os.Stat(chartYAML); err != nil || !info.Mode().IsRegular() {
		return "", "", rndErr("invalid_chart", "chart is missing Chart.yaml")
	}
	if info, err := os.Stat(filepath.Join(chartDestination, "templates")); err != nil || !info.IsDir() {
		return "", "", rndErr("invalid_chart", "chart is missing templates/")
	}

	scanErr := filepath.WalkDir(chartDestination, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return rndErr("path_unreadable", "cannot scan chart: %v", walkErr)
		}
		if d.IsDir() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return rndErr("path_unreadable", "cannot read chart file: %v", readErr)
		}
		if !rndValidUTF8(raw) {
			return rndErr("invalid_chart", "chart file is not UTF-8")
		}
		if rndForbiddenTemplateRE.Match(raw) {
			return rndErr("dynamic_template_forbidden",
				"chart uses dynamic or environment-dependent templates")
		}
		return nil
	})
	if scanErr != nil {
		return "", "", scanErr
	}

	chartRaw, err := os.ReadFile(chartYAML)
	if err != nil {
		return "", "", rndErr("path_unreadable", "cannot read Chart.yaml: %v", err)
	}
	chartMeta, err := rndLoadSingleYAML(string(chartRaw), "Chart.yaml")
	if err != nil {
		return "", "", rndErr("invalid_chart", "invalid Chart.yaml: %v", err)
	}
	chartObject, ok := chartMeta.(M)
	if !ok {
		return "", "", rndErr("unsupported_chart_entry", "chart dependencies are not permitted")
	}
	if rndTruthy(chartObject["dependencies"]) {
		return "", "", rndErr("unsupported_chart_entry", "chart dependencies are not permitted")
	}
	return chartDestination, valuesDestination, nil
}

func rndRequireSandboxImpl(config M) error {
	if !rndIsLinux() {
		return rndErr("bwrap_required",
			"production rendering requires Linux bubblewrap; use load_rendered_manifests for fixtures")
	}
	bwrap := config["bwrap"].(string)
	if !rndExecutable(bwrap) {
		return rndErr("bwrap_missing",
			"bubblewrap is required and must be executable; no unsandboxed fallback exists")
	}
	helm := config["helm"].(string)
	if !rndExecutable(helm) {
		return rndErr("helm_missing", "helm executable is missing")
	}
	return nil
}

func rndExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0111 != 0
}

func rndResolvePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Python's Path.resolve(strict=False) resolves existing symlinks and keeps
	// missing paths lexically intact; mirror that so the trusted helm path can
	// be mounted even when it is not present in a test environment.
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		return resolved, nil
	}
	return absolute, nil
}

func rndBuildBwrapCommand(config M, workdir string) ([]string, error) {
	helm, err := rndResolvePath(config["helm"].(string))
	if err != nil {
		return nil, rndErr("helm_missing", "helm executable is missing")
	}
	command := []string{
		config["bwrap"].(string),
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--clearenv",
		"--cap-drop", "ALL",
		"--ro-bind-try", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--dir", "/etc",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--bind", workdir, "/work",
		"--chdir", "/work",
		"--setenv", "HOME", "/tmp",
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--setenv", "HELM_CACHE_HOME", "/tmp/helm-cache",
		"--setenv", "HELM_CONFIG_HOME", "/tmp/helm-config",
		"--setenv", "HELM_DATA_HOME", "/tmp/helm-data",
		"--setenv", "HELM_PLUGINS", "/tmp/no-helm-plugins",
		"--setenv", "HELM_REGISTRY_CONFIG", "/tmp/empty-registry.json",
		"--setenv", "HELM_REPOSITORY_CONFIG", "/tmp/empty-repositories.yaml",
		"--setenv", "HELM_REPOSITORY_CACHE", "/tmp/helm-cache",
		"--setenv", "KUBECONFIG", "/tmp/empty-kubeconfig",
		"--setenv", "HELM_DEBUG", "0",
		"--",
		rndHelmTarget,
		"template",
		config["release"].(string),
		"/work/chart",
		"--namespace",
		config["namespace"].(string),
		"--values",
		"/work/values.yaml",
		"--kube-version",
		config["kube_version"].(string),
	}
	if helm != rndHelmTarget {
		index := -1
		for i, part := range command {
			if part == "--dir" {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, rndErr("sandbox_start_failed", "internal bwrap command is invalid")
		}
		insert := []string{"--ro-bind", helm, rndHelmTarget}
		command = append(command[:index], append(insert, command[index:]...)...)
	}
	return command, nil
}

// rndExecutionEnvironment is the fixed, non-inherited environment used for the
// sandboxed child.
func rndExecutionEnvironment(cwd string) []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + filepath.Join(cwd, "empty-home"),
		"LANG=C",
		"LC_ALL=C",
	}
}

// rndTrustedExecutable verifies a fixed absolute system path is a regular,
// executable file that is not group- or world-writable. This is used for the
// resource-limit wrapper because a writable helper would nullify the bounds.
func rndTrustedExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	permissions := info.Mode().Perm()
	return permissions&0111 != 0 && permissions&0022 == 0
}

// rndSandboxLimits wraps the sandbox command with a trusted prlimit binary.
// RLIMIT_AS/NPROC cannot be set through Go's portable SysProcAttr. Unlike the
// previous implementation, this fails closed on Linux when no trusted prlimit
// is available: silently dropping the configured memory bound is not allowed.
// Time/output bounds are additionally enforced by the supervisor.
func rndSandboxLimits(command []string, memoryLimit, outputLimit, timeout int) ([]string, error) {
	if !rndIsLinux() {
		return command, nil
	}
	prlimit := ""
	for _, candidate := range rndPrlimitCandidates {
		if rndTrustedExecutable(candidate) {
			prlimit = candidate
			break
		}
	}
	if prlimit == "" {
		return nil, rndErr("sandbox_limits_unavailable",
			"a trusted prlimit executable is required to enforce sandbox memory, file-size, CPU, and process limits; refusing to render without resource limits")
	}
	cpuSeconds := timeout + 5
	if cpuSeconds < 2 {
		cpuSeconds = 2
	}
	prefix := []string{
		prlimit,
		fmt.Sprintf("--as=%d", memoryLimit),
		fmt.Sprintf("--fsize=%d", outputLimit),
		fmt.Sprintf("--cpu=%d", cpuSeconds),
		"--nofile=128",
		"--nproc=128",
		"--",
	}
	return append(prefix, command...), nil
}

func rndExecuteImpl(command []string, cwd string, timeout, outputLimit, memoryLimit int) (string, string, error) {
	if err := os.MkdirAll(filepath.Join(cwd, "empty-home"), 0700); err != nil {
		return "", "", rndErr("sandbox_start_failed", "failed to create sandbox home: %v", err)
	}
	outFile, err := os.CreateTemp(cwd, ".guard-stdout-")
	if err != nil {
		return "", "", rndErr("sandbox_start_failed", "failed to create sandbox output: %v", err)
	}
	outPath := outFile.Name()
	defer os.Remove(outPath)
	errFile, err := os.CreateTemp(cwd, ".guard-stderr-")
	if err != nil {
		outFile.Close()
		return "", "", rndErr("sandbox_start_failed", "failed to create sandbox output: %v", err)
	}
	errPath := errFile.Name()
	defer os.Remove(errPath)

	finalCommand, limitErr := rndSandboxLimits(command, memoryLimit, outputLimit, timeout)
	if limitErr != nil {
		outFile.Close()
		errFile.Close()
		return "", "", limitErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, finalCommand[0], finalCommand[1:]...)
	process.Dir = cwd
	process.Env = rndExecutionEnvironment(cwd)
	process.Stdin = nil
	process.Stdout = outFile
	process.Stderr = errFile
	startErr := process.Start()
	if startErr != nil {
		outFile.Close()
		errFile.Close()
		return "", "", rndErr("sandbox_start_failed",
			"failed to start sandboxed helm: %v", startErr)
	}
	waitErr := process.Wait()
	outFile.Close()
	errFile.Close()
	if ctx.Err() == context.DeadlineExceeded {
		return "", "", rndErr("render_timeout", "helm render timed out inside bubblewrap")
	}

	outInfo, outStatErr := os.Stat(outPath)
	errInfo, errStatErr := os.Stat(errPath)
	if outStatErr != nil || errStatErr != nil {
		return "", "", rndErr("sandbox_start_failed", "failed to inspect sandbox output")
	}
	if outInfo.Size() > int64(outputLimit) || errInfo.Size() > int64(outputLimit) {
		return "", "", rndErrDetails("output_too_large",
			"sandboxed helm output exceeded the size limit",
			M{"stdout_bytes": outInfo.Size(), "stderr_bytes": errInfo.Size(), "limit": outputLimit})
	}
	stdoutRaw, err := os.ReadFile(outPath)
	if err != nil {
		return "", "", rndErr("sandbox_start_failed", "failed to read sandbox output: %v", err)
	}
	stderrRaw, err := os.ReadFile(errPath)
	if err != nil {
		return "", "", rndErr("sandbox_start_failed", "failed to read sandbox output: %v", err)
	}
	stdout := strings.ToValidUTF8(string(stdoutRaw), "\uFFFD")
	stderr := strings.ToValidUTF8(string(stderrRaw), "\uFFFD")
	if waitErr != nil {
		exitCode := -1
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			exitCode = exitError.ExitCode()
		} else {
			return "", "", rndErr("sandbox_start_failed",
				"failed to start sandboxed helm: %v", waitErr)
		}
		summary := rndHelmFailureSummary(stderr)
		return "", "", rndErr("helm_failed",
			"sandboxed helm failed with exit %d: %s", exitCode, summary)
	}
	return stdout, stderr, nil
}

func rndHelmFailureSummary(stderr string) string {
	trimmed := strings.TrimSpace(stderr)
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	summary := strings.Join(lines, " ")
	runes := []rune(summary)
	if len(runes) > 1500 {
		summary = string(runes[:1500])
	}
	return summary
}

func rndFixturePaths(tree string, config M) ([]string, error) {
	mode := ""
	if raw, present := config["renderer_mode"]; present {
		mode = rndPyStr(raw)
	}
	requested := false
	if value, present := config["allow_pre_rendered"]; present {
		if flag, ok := value.(bool); ok && flag {
			requested = true
		}
	}
	if mode == "prebuilt" || mode == "fixture" || mode == "rendered" {
		requested = true
	}
	if value, present := config["pre_rendered"]; present {
		switch v := value.(type) {
		case nil:
		case bool:
			if !v {
				break
			}
			requested = true
		default:
			if number, ok := v.(float64); ok && number == 0 {
				break
			}
			if integer, ok := rndIntValue(v); ok && integer == 0 {
				break
			}
			requested = true
		}
	}
	if !requested {
		return nil, nil
	}
	if rndIsLinux() && !rndTruthy(config["fixture_mode"]) {
		return nil, rndErr("pre_rendered_forbidden",
			"pre-rendered inputs are fixture-only and disabled on Linux production hosts")
	}
	supplied, present := config["pre_rendered"]
	if !present || supplied == nil {
		return []string{tree}, nil
	}
	if flag, ok := supplied.(bool); ok && flag {
		return []string{tree}, nil
	}
	if value, ok := supplied.(string); ok {
		return []string{value}, nil
	}
	if values, ok := supplied.([]string); ok {
		return values, nil
	}
	if values, ok := supplied.([]any); ok {
		paths := make([]string, 0, len(values))
		for _, item := range values {
			text, ok := item.(string)
			if !ok {
				return nil, rndErr("invalid_render_config", "pre_rendered must be a path or list of paths")
			}
			paths = append(paths, text)
		}
		return paths, nil
	}
	return nil, rndErr("invalid_render_config", "pre_rendered must be a path or list of paths")
}

// RenderTree renders charts/demo from tree with gitops/demo/values.yaml.
//
// On production Linux the call always executes inside bubblewrap; failures are
// returned, never silently replaced by unsandboxed Helm.
func RenderTree(tree string, config M) ([]M, error) {
	if config == nil {
		config = M{}
	}
	fixturePaths, err := rndFixturePaths(tree, config)
	if err != nil {
		return nil, err
	}
	if fixturePaths != nil {
		return LoadRenderedManifests(fixturePaths, config)
	}

	settings, err := rndValidateConfig(config)
	if err != nil {
		return nil, err
	}
	if err := rndRequireSandbox(settings); err != nil {
		return nil, err
	}
	originalRoot := tree
	if err := rndAssertNoSymlink(originalRoot, "candidate tree"); err != nil {
		return nil, err
	}
	root, err := rndResolvePath(originalRoot)
	if err != nil {
		return nil, rndErr("tree_missing", "candidate tree does not exist: %v", err)
	}
	if err := rndAssertNoSymlink(root, "candidate tree"); err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, rndErr("tree_missing", "candidate tree must be a directory")
	}

	tempDir, err := os.MkdirTemp("", "change-guard-render-")
	if err != nil {
		return nil, rndErr("sandbox_start_failed", "cannot create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	workdir := filepath.Join(tempDir, "work")
	if err := os.MkdirAll(workdir, 0700); err != nil {
		return nil, rndErr("sandbox_start_failed", "cannot create work directory: %v", err)
	}
	if _, _, err := rndCopyPermittedTree(root, workdir, settings); err != nil {
		return nil, err
	}
	command, err := rndBuildBwrapCommand(settings, workdir)
	if err != nil {
		return nil, err
	}
	stdout, _, err := rndExecute(command, workdir,
		settings["timeout"].(int),
		settings["output_limit"].(int),
		settings["memory_limit"].(int))
	if err != nil {
		return nil, err
	}
	if len([]byte(stdout)) > settings["output_limit"].(int) {
		return nil, rndErr("output_too_large", "helm output exceeded the configured size limit")
	}
	documents, err := rndLoadYAMLDocuments(stdout, "helm output", rndMaxManifestDocuments)
	if err != nil {
		return nil, err
	}
	resources, err := rndFlattenManifests(documents, "helm output")
	if err != nil {
		return nil, err
	}
	for _, object := range resources {
		metadata, _ := object["metadata"].(M)
		annotations, _ := metadata["annotations"].(M)
		if annotations == nil {
			continue
		}
		if _, present := annotations["helm.sh/hook"]; present {
			return nil, rndErr("hooks_forbidden",
				"Helm/Argo hooks are forbidden in the protected demo chart")
		}
		if _, present := annotations["argocd.argoproj.io/hook"]; present {
			return nil, rndErr("hooks_forbidden",
				"Helm/Argo hooks are forbidden in the protected demo chart")
		}
	}
	return resources, nil
}

// rndDigestManifests returns a stable, order-independent digest of rendered
// resources. It is kept for parity with the Python renderer helper.
func rndDigestManifests(resources []M) string {
	encoded := make([]string, 0, len(resources))
	for _, resource := range resources {
		value, err := CanonicalJSON(resource)
		if err != nil {
			return ""
		}
		encoded = append(encoded, string(value))
	}
	sort.Strings(encoded)
	hash := sha256.Sum256([]byte("[" + strings.Join(encoded, ",") + "]"))
	return hex.EncodeToString(hash[:])
}
