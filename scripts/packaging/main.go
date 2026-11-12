// Command packaging writes a deterministic release tarball for the Go guard.
//
// It is a build-time helper, not part of the service runtime.  The archive
// contains exactly one static Linux binary, the knowledge bundle, the example
// configuration, and the README.  File names, modes, mtimes, owner/group and
// gzip metadata are normalized so repeated builds of identical inputs produce
// identical bytes.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type entry struct {
	name string
	path string
	dir  bool
	mode int64
}

func main() {
	stage := flag.String("stage", "", "staging directory")
	output := flag.String("output", "", "output tarball")
	version := flag.String("version", "", "release version")
	arch := flag.String("arch", "amd64", "Linux architecture")
	flag.Parse()
	if *stage == "" || *output == "" {
		fail(errors.New("--stage and --output are required"))
	}
	stageAbsolute, err := filepath.Abs(*stage)
	if err != nil {
		fail(err)
	}
	outputAbsolute, err := filepath.Abs(*output)
	if err != nil {
		fail(err)
	}
	info, err := os.Stat(stageAbsolute)
	if err != nil || !info.IsDir() {
		fail(errors.New("staging directory is missing"))
	}
	for _, required := range []string{"k8s-change-guard", "knowledge", "config.example.yaml"} {
		if _, err := os.Lstat(filepath.Join(stageAbsolute, required)); err != nil {
			fail(fmt.Errorf("staging directory is missing %s", required))
		}
	}
	entries, err := collect(stageAbsolute)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(outputAbsolute), 0755); err != nil {
		fail(err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(outputAbsolute), ".release-*.tmp")
	if err != nil {
		fail(err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	counter := &countingWriter{destination: io.MultiWriter(temporary, digest)}
	gzipWriter, err := gzip.NewWriterLevel(counter, gzip.BestCompression)
	if err != nil {
		_ = temporary.Close()
		fail(err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	gzipWriter.Header.OS = 255
	gzipWriter.Header.Name = ""
	tarWriter := tar.NewWriter(gzipWriter)
	for _, item := range entries {
		header := &tar.Header{
			Name:     item.name,
			Mode:     item.mode,
			Uid:      0,
			Gid:      0,
			Size:     0,
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeDir,
			Format:   tar.FormatPAX,
		}
		if !item.dir {
			header.Typeflag = tar.TypeReg
			fileInfo, err := os.Stat(item.path)
			if err != nil {
				_ = tarWriter.Close()
				_ = gzipWriter.Close()
				_ = temporary.Close()
				fail(err)
			}
			header.Size = fileInfo.Size()
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = temporary.Close()
			fail(err)
		}
		if item.dir {
			continue
		}
		file, err := os.Open(item.path)
		if err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = temporary.Close()
			fail(err)
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = temporary.Close()
			fail(errors.New("cannot read a staged file"))
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		_ = temporary.Close()
		fail(err)
	}
	if err := gzipWriter.Close(); err != nil {
		_ = temporary.Close()
		fail(err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		fail(err)
	}
	if err := temporary.Close(); err != nil {
		fail(err)
	}
	if err := os.Chmod(temporaryPath, 0644); err != nil {
		fail(err)
	}
	if err := os.Rename(temporaryPath, outputAbsolute); err != nil {
		fail(err)
	}
	result := map[string]any{
		"status":   "ok",
		"version":  *version,
		"arch":     *arch,
		"artifact": outputAbsolute,
		"sha256":   hex.EncodeToString(digest.Sum(nil)),
		"bytes":    counter.count,
		"files":    countFiles(entries),
	}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}

func collect(root string) ([]entry, error) {
	var entries []entry
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to package symlink: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") {
			return fmt.Errorf("unsafe archive path: %s", relative)
		}
		if info.IsDir() {
			entries = append(entries, entry{name: relative + "/", path: path, dir: true, mode: 0755})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to package non-regular file: %s", path)
		}
		mode := int64(0644)
		if relative == "k8s-change-guard" {
			mode = 0755
		}
		entries = append(entries, entry{name: relative, path: path, mode: mode})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].name < entries[right].name })
	return entries, nil
}

func countFiles(entries []entry) int {
	count := 0
	for _, item := range entries {
		if !item.dir {
			count++
		}
	}
	return count
}

type countingWriter struct {
	destination io.Writer
	count       int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	written, err := writer.destination.Write(data)
	writer.count += int64(written)
	return written, err
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "build-release:", err)
	os.Exit(1)
}
