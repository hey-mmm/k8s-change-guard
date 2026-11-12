package guard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func rndTestWithLinux(t *testing.T, candidates []string) {
	t.Helper()
	previousLinux := rndIsLinux
	previousCandidates := rndPrlimitCandidates
	rndIsLinux = func() bool { return true }
	rndPrlimitCandidates = candidates
	t.Cleanup(func() {
		rndIsLinux = previousLinux
		rndPrlimitCandidates = previousCandidates
	})
}

func TestSandboxLimitsFailClosedWithoutTrustedPrlimit(t *testing.T) {
	rndTestWithLinux(t, []string{filepath.Join(t.TempDir(), "missing-prlimit")})
	command := []string{"/usr/bin/bwrap", "--", "helm", "template"}
	wrapped, err := rndSandboxLimits(command, 1024*1024*1024, 4*1024*1024, 30)
	if err == nil {
		t.Fatal("resource limits were silently dropped")
	}
	if wrapped != nil {
		t.Fatalf("expected no command on failure, got %v", wrapped)
	}
	var renderErr *RenderError
	if !errors.As(err, &renderErr) || renderErr.Code != "sandbox_limits_unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSandboxLimitsWrapTrustedPrlimit(t *testing.T) {
	prlimit := filepath.Join(t.TempDir(), "prlimit")
	if err := os.WriteFile(prlimit, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rndTestWithLinux(t, []string{prlimit})
	command := []string{"/usr/bin/bwrap", "--", "helm", "template"}
	wrapped, err := rndSandboxLimits(command, 1024*1024*1024, 4*1024*1024, 30)
	if err != nil {
		t.Fatal(err)
	}
	expectedPrefix := []string{
		prlimit,
		"--as=1073741824",
		"--fsize=4194304",
		"--cpu=35",
		"--nofile=128",
		"--nproc=128",
		"--",
	}
	if len(wrapped) != len(expectedPrefix)+len(command) {
		t.Fatalf("unexpected wrapped command length: %v", wrapped)
	}
	for index, expected := range expectedPrefix {
		if wrapped[index] != expected {
			t.Fatalf("prefix[%d] = %q, want %q", index, wrapped[index], expected)
		}
	}
	for index, expected := range command {
		if wrapped[len(expectedPrefix)+index] != expected {
			t.Fatalf("command[%d] was not preserved", index)
		}
	}
}

func TestSandboxLimitsNonLinuxPassThrough(t *testing.T) {
	previous := rndIsLinux
	rndIsLinux = func() bool { return false }
	t.Cleanup(func() { rndIsLinux = previous })
	command := []string{"bwrap", "--", "helm"}
	wrapped, err := rndSandboxLimits(command, 1024, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != len(command) {
		t.Fatalf("non-Linux command changed: %v", wrapped)
	}
}

func TestExecuteRefusesToRunWithoutTrustedPrlimit(t *testing.T) {
	rndTestWithLinux(t, []string{filepath.Join(t.TempDir(), "missing-prlimit")})
	_, _, err := rndExecuteImpl([]string{"/bin/true"}, t.TempDir(), 5, 4096, 64*1024*1024)
	if err == nil {
		t.Fatal("sandboxed execution ran without resource-limit enforcement")
	}
	var renderErr *RenderError
	if !errors.As(err, &renderErr) || renderErr.Code != "sandbox_limits_unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionRenderNeverFallsBackUnsandboxed(t *testing.T) {
	previous := rndIsLinux
	rndIsLinux = func() bool { return false }
	t.Cleanup(func() { rndIsLinux = previous })
	_, err := RenderTree(t.TempDir(), M{})
	if err == nil {
		t.Fatal("production rendering accepted an unsandboxed host")
	}
	var renderErr *RenderError
	if !errors.As(err, &renderErr) || renderErr.Code != "bwrap_required" {
		t.Fatalf("unexpected error: %v", err)
	}
}
