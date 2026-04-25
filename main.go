package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const configFileName = "sync.yaml"
const logFileName = "sync.log"

type Config struct {
	TimeoutSeconds int          `yaml:"timeout_seconds"`
	UserAgent      string       `yaml:"user_agent"`
	Files          []FileConfig `yaml:"files"`
}

type FileConfig struct {
	Path string `yaml:"path"`
	URL  string `yaml:"url"`
}

type runner struct {
	rootDir string
	client  *http.Client
	config  Config
	logFile *os.File
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	execDir, err := executableDir()
	if err != nil {
		return fmt.Errorf("resolve executable directory: %w", err)
	}
	if err := os.Chdir(execDir); err != nil {
		return fmt.Errorf("change working directory: %w", err)
	}

	logFile, err := os.OpenFile(filepath.Join(execDir, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()

	cfg, err := loadConfig(filepath.Join(execDir, configFileName))
	if err != nil {
		writeLog(logFile, "ERROR startup: %v", err)
		return err
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = "rp-sync/1.0"
	}

	r := runner{
		rootDir: execDir,
		client: &http.Client{
			Timeout: timeout,
		},
		config:  cfg,
		logFile: logFile,
	}

	var failed bool
	for _, file := range cfg.Files {
		if err := r.syncFile(file, userAgent); err != nil {
			failed = true
			r.logf("ERROR %s: %v", file.Path, err)
			fmt.Fprintf(os.Stderr, "- %s: %v\n", file.Path, err)
		}
	}

	if failed {
		writeLog(logFile, "ERROR sync finished with failures")
		return errors.New("one or more files failed")
	}

	writeLog(logFile, "SYNC completed successfully")
	return nil
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("config file %q not found", configFileName)
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if len(cfg.Files) == 0 {
		return Config{}, errors.New("config.files must not be empty")
	}

	for i, file := range cfg.Files {
		if strings.TrimSpace(file.Path) == "" {
			return Config{}, fmt.Errorf("files[%d].path must not be empty", i)
		}
		if strings.TrimSpace(file.URL) == "" {
			return Config{}, fmt.Errorf("files[%d].url must not be empty", i)
		}
		parsed, err := url.Parse(file.URL)
		if err != nil {
			return Config{}, fmt.Errorf("files[%d].url is invalid: %w", i, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return Config{}, fmt.Errorf("files[%d].url must use http or https", i)
		}
	}

	return cfg, nil
}

func (r runner) syncFile(file FileConfig, userAgent string) error {
	targetPath, err := resolveTargetPath(r.rootDir, file.Path)
	if err != nil {
		return err
	}

	checksumURL := file.URL + ".sha256"
	expectedHash, err := r.fetchExpectedHash(file, checksumURL, userAgent)
	if err != nil {
		return err
	}

	currentHash, err := fileSHA256(targetPath)
	if err == nil && strings.EqualFold(currentHash, expectedHash) {
		r.logf("UP-TO-DATE %s", file.Path)
		fmt.Printf("up-to-date %s\n", file.Path)
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("calculate local sha256: %w", err)
	}

	state := "updated"
	if errors.Is(err, os.ErrNotExist) {
		state = "downloaded"
	}

	if err := r.downloadVerifiedFile(targetPath, file.URL, expectedHash, userAgent); err != nil {
		return err
	}

	r.logf("%s %s", strings.ToUpper(state), file.Path)
	fmt.Printf("%s %s\n", state, file.Path)
	return nil
}

func resolveTargetPath(rootDir, relPath string) (string, error) {
	cleanPath := filepath.Clean(relPath)
	if cleanPath == "." {
		return "", errors.New("path must point to a file")
	}
	if filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path %q must be relative", relPath)
	}

	fullPath := filepath.Join(rootDir, cleanPath)
	rel, err := filepath.Rel(rootDir, fullPath)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", relPath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes working directory", relPath)
	}
	return fullPath, nil
}

func (r runner) fetchExpectedHash(file FileConfig, checksumURL, userAgent string) (string, error) {
	body, err := r.get(checksumURL, userAgent)
	if err != nil {
		return "", fmt.Errorf("fetch checksum: %w", err)
	}

	hash, err := parseChecksum(body, file.Path, file.URL)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func parseChecksum(data []byte, configuredPath, fileURL string) (string, error) {
	hash := strings.ToLower(strings.TrimSpace(string(data)))
	if hash == "" {
		return "", errors.New("checksum file is empty")
	}
	if len(hash) != sha256.Size*2 {
		return "", fmt.Errorf("invalid sha256 value %q", strings.TrimSpace(string(data)))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", fmt.Errorf("invalid sha256 value %q", strings.TrimSpace(string(data)))
	}
	return hash, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func executableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", err
	}
	return filepath.Dir(execPath), nil
}

func (r runner) downloadVerifiedFile(targetPath, fileURL, expectedHash, userAgent string) error {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download file: unexpected status %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(targetPath), filepath.Base(targetPath)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	h := sha256.New()
	writer := io.MultiWriter(tempFile, h)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		tempFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("downloaded file sha256 mismatch: expected %s got %s", expectedHash, actualHash)
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("replace target file: %w", err)
	}
	return nil
}

func (r runner) get(rawURL, userAgent string) ([]byte, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

func (r runner) logf(format string, args ...any) {
	writeLog(r.logFile, format, args...)
}

func writeLog(logFile *os.File, format string, args ...any) {
	if logFile == nil {
		return
	}
	_, _ = fmt.Fprintf(logFile, "%s %s\n", time.Now().Format(time.DateTime), fmt.Sprintf(format, args...))
}
