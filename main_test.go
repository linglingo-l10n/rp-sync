package main

import (
	"crypto/sha256"
	"encoding/hex"
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

	hash, err := parseChecksum([]byte(hashText+"\n"), "nested/file-b.txt", "https://example.com/file-b.txt")
	if err != nil {
		t.Fatalf("parseChecksum returned error: %v", err)
	}
	if hash != hashText {
		t.Fatalf("parseChecksum = %q, want %q", hash, hashText)
	}
}

func TestParseChecksumInvalid(t *testing.T) {
	_, err := parseChecksum([]byte("not-a-hash file.txt\n"), "file.txt", "https://example.com/file.txt")
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

	if err := r.syncFile(file, "test-agent"); err != nil {
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

	if err := r.syncFile(file, "test-agent"); err != nil {
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

	err = r.syncFile(FileConfig{Path: "artifact.txt", URL: server.URL + "/artifact.txt"}, "test-agent")
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

func TestFileSHA256NotExist(t *testing.T) {
	_, err := fileSHA256(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected missing file error")
	}
	if !os.IsNotExist(err) && !errorsIs(err, fs.ErrNotExist) {
		t.Fatalf("expected not exist error, got %v", err)
	}
}

func errorsIs(err, target error) bool {
	return err != nil && target != nil && os.IsNotExist(err)
}
