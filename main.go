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

// maxBodySize limits HTTP response bodies to prevent memory exhaustion.
// Checksum files are small; downloaded files may be larger.
const (
	maxChecksumBodySize  = 4 << 10   // 4 KB
	maxDownloadBodySize  = 500 << 20 // 500 MB
)

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

	ctx := context.Background()

	var failed bool
	for _, file := range cfg.Files {
		if err := r.syncFile(ctx, file, userAgent); err != nil {
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

func (r runner) syncFile(ctx context.Context, file FileConfig, userAgent string) error {
	targetPath, err := resolveTargetPath(r.rootDir, file.Path)
	if err != nil {
		return err
	}

	checksumURL := file.URL + ".sha256"
	expectedHash, err := r.fetchExpectedHash(ctx, checksumURL, userAgent)
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

	if err := r.downloadVerifiedFile(ctx, targetPath, file.URL, expectedHash, userAgent); err != nil {
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

func (r runner) fetchExpectedHash(ctx context.Context, checksumURL, userAgent string) (string, error) {
	body, err := r.get(ctx, checksumURL, userAgent)
	if err != nil {
		return "", fmt.Errorf("fetch checksum: %w", err)
	}

	hash, err := parseChecksum(body)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func parseChecksum(data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", errors.New("checksum file is empty")
	}
	// Support standard sha256sum format: "<hash>  <filename>" or "<hash> *<filename>"
	hash := strings.ToLower(strings.Fields(text)[0])
	if len(hash) != sha256.Size*2 {
		return "", fmt.Errorf("invalid sha256 value %q", hash)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", fmt.Errorf("invalid sha256 value %q", hash)
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

func (r runner) downloadVerifiedFile(ctx context.Context, targetPath, fileURL, expectedHash, userAgent string) error {
	resp, err := r.retryGet(ctx, fileURL, userAgent)
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
	if _, err := io.Copy(writer, io.LimitReader(resp.Body, maxDownloadBodySize)); err != nil {
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

func (r runner) get(ctx context.Context, rawURL, userAgent string) ([]byte, error) {
	resp, err := r.retryGet(ctx, rawURL, userAgent)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

func (r runner) retryGet(ctx context.Context, rawURL, userAgent string) (*http.Response, error) {
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
			r.logf("RETRY %s (attempt %d/%d): %v", rawURL, attempt+1, maxRetries, lastErr)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}

		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error %s", resp.Status)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
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
