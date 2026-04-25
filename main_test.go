package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveTargetPath(t *testing.T) {
	root := t.TempDir()

	path, err := resolveTargetPath(root, "assets/file.txt")
	if err != nil {
	t.Fatalf("resolveTargetPath returned error: %v", err)
	}
	if want := filepath.Join(root, "assets/file.txt"); path != want {
		t.Fatalf("resolveTargetPath = %q, want %q", path, want)
	}

	if _, err := resolveTargetPath(root, "../escape.txt"); err == nil {
		t.Fatal("expected path traversal to fail")
	}
}

func TestParseChecksum(t *testing.T) {
	hashText := strings.Repeat("a", 64)

	hash, err := parseChecksum([]byte(hashText + "\n"))
	if err != nil {
		t.Fatalf("parseChecksum returned error: %v", err)
	}
	if hash != hashText {
		t.Fatalf("parseChecksum = %q, want %q", hash, hashText)
	}
}

func TestParseChecksumInvalid(t *testing.T) {
	_, err := parseChecksum([]byte("not-a-hash file.txt\n"))
	if err == nil {
		t.Fatal("expected invalid checksum to fail")
	}
}

func TestExecutableDir(t *testing.T) {
	dir, err := executableDir()
	if err != nil {
		t.Fatalf("executableDir returned error: %v", err)
	}
	if dir == "" {
		t.Fatal("expected executableDir to return a path")
	}
}

func TestRunnerSyncFile(t *testing.T) {
	root := t.TempDir()
	content := []byte("fresh content")
	hash := sha256.Sum256(content)
	hashText := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact.txt":
			_, _ = w.Write(content)
		case "/artifact.txt.sha256":
			_, _ = w.Write([]byte(hashText))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logFile, err := os.OpenFile(filepath.Join(root, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	defer logFile.Close()

	r := runner{
		rootDir: root,
		client:  server.Client(),
		logFile: logFile,
	}

	file := FileConfig{
		Path: "downloads/artifact.txt",
		URL:  server.URL + "/artifact.txt",
	}

	if err := r.syncFile(context.Background(), file, "test-agent"); err != nil {
		t.Fatalf("first syncFile returned error: %v", err)
	}

	target := filepath.Join(root, file.Path)
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("downloaded content = %q, want %q", string(got), string(content))
	}

	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if err := r.syncFile(context.Background(), file, "test-agent"); err != nil {
		t.Fatalf("second syncFile returned error: %v", err)
	}

	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile returned error after update: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("updated content = %q, want %q", string(got), string(content))
	}

	logContent, err := os.ReadFile(filepath.Join(root, logFileName))
	if err != nil {
		t.Fatalf("ReadFile log returned error: %v", err)
	}
	logText := string(logContent)
	if !strings.Contains(logText, "DOWNLOADED downloads/artifact.txt") {
		t.Fatalf("log missing download entry: %q", logText)
	}
	if !strings.Contains(logText, "UPDATED downloads/artifact.txt") {
		t.Fatalf("log missing update entry: %q", logText)
	}
}

func TestRunnerSyncFileChecksumError(t *testing.T) {
	root := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact.txt":
			_, _ = w.Write([]byte("fresh content"))
		case "/artifact.txt.sha256":
			_, _ = w.Write([]byte("broken\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logFile, err := os.OpenFile(filepath.Join(root, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	defer logFile.Close()

	r := runner{
		rootDir: root,
		client:  server.Client(),
		logFile: logFile,
	}

	err = r.syncFile(context.Background(), FileConfig{Path: "artifact.txt", URL: server.URL + "/artifact.txt"}, "test-agent")
	if err == nil {
		t.Fatal("expected checksum parsing error")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, []byte("files:\n  - path: ../x\n    url: ftp://example.com/x\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := loadConfig(configPath)
	if err == nil {
		t.Fatal("expected invalid config to fail")
	}
}

func TestParseChecksum_StandardFormat(t *testing.T) {
	hashText := strings.Repeat("c", 64)
	// Standard sha256sum output: "<hash>  filename" or "<hash> *filename"
	for _, input := range []string{
		hashText + "  file.txt",
		hashText + " *file.txt",
		hashText + "  path/to/file",
	} {
		hash, err := parseChecksum([]byte(input))
		if err != nil {
			t.Fatalf("parseChecksum(%q) returned error: %v", input, err)
		}
		if hash != hashText {
			t.Fatalf("parseChecksum(%q) = %q, want %q", input, hash, hashText)
		}
	}
}

func TestParseChecksum_Empty(t *testing.T) {
	_, err := parseChecksum([]byte(""))
	if err == nil {
		t.Fatal("expected empty checksum to fail")
	}
}

func TestParseChecksum_NonHex(t *testing.T) {
	_, err := parseChecksum([]byte(strings.Repeat("g", 64)))
	if err == nil {
		t.Fatal("expected non-hex checksum to fail")
	}
}

func TestResolveTargetPath_Dot(t *testing.T) {
	_, err := resolveTargetPath("/tmp", ".")
	if err == nil {
		t.Fatal("expected '.' path to fail")
	}
}

func TestResolveTargetPath_Absolute(t *testing.T) {
	_, err := resolveTargetPath("/tmp", "/etc/passwd")
	if err == nil {
		t.Fatal("expected absolute path to fail")
	}
}

func TestLoadConfig_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	yamlContent := "files:\n  - path: data/file.txt\n    url: https://example.com/file.txt\n"
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}
	if len(cfg.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(cfg.Files))
	}
}

func TestLoadConfig_EmptyFiles(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, []byte("files: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := loadConfig(configPath)
	if err == nil {
		t.Fatal("expected empty files to fail")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(configPath, []byte("{{{broken\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := loadConfig(configPath)
	if err == nil {
		t.Fatal("expected invalid YAML to fail")
	}
}

func TestRunnerSyncFile_Non200Status(t *testing.T) {
	root := t.TempDir()
	// Server returns 404 for checksum file (no .sha256 endpoint)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	logFile, _ := os.OpenFile(filepath.Join(root, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	defer logFile.Close()

	r := runner{
		rootDir: root,
		client:  server.Client(),
		logFile: logFile,
	}

	err := r.syncFile(context.Background(), FileConfig{Path: "f.txt", URL: server.URL + "/f.txt"}, "test-agent")
	if err == nil {
		t.Fatal("expected error from 404 checksum response")
	}
}

func TestRunnerSyncFile_HashMismatch(t *testing.T) {
	root := t.TempDir()
	content := []byte("real content")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/file.txt":
			_, _ = w.Write(content)
		case "/file.txt.sha256":
			// Return a hash that doesn't match content
			_, _ = w.Write([]byte(strings.Repeat("d", 64)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logFile, _ := os.OpenFile(filepath.Join(root, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	defer logFile.Close()

	r := runner{
		rootDir: root,
		client:  server.Client(),
		logFile: logFile,
	}

	err := r.syncFile(context.Background(), FileConfig{Path: "file.txt", URL: server.URL + "/file.txt"}, "test-agent")
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestFileSHA256NotExist(t *testing.T) {
	_, err := fileSHA256(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected missing file error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}
