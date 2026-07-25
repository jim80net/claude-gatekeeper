package releaseverify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureTag = "v9.8.7"

type fixtureOptions struct {
	missingAsset      string
	badChecksum       bool
	downloadedVersion string
	hostVersion       string
	pluginVersion     string
	doctorExit        int
	failHarness       string
}

func TestVerifyHappyPath(t *testing.T) {
	result := runFixture(t, fixtureOptions{})
	if !result.OK {
		t.Fatalf("result = %#v", result)
	}
	for _, name := range []string{
		"release", "assets", "checksum", "archive",
		"downloaded version", "host version", "plugin version", "doctor",
		"claude canary", "codex canary", "grok canary",
	} {
		assertCheck(t, result, name, true)
	}

	var human bytes.Buffer
	if err := WriteTable(&human, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "PASS") {
		t.Fatalf("human report = %q", human.String())
	}
	var machine bytes.Buffer
	if err := WriteJSON(&machine, result); err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.OK || decoded.Tag != fixtureTag {
		t.Fatalf("JSON report = %#v", decoded)
	}
	if decoded.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", decoded.ExitCode)
	}
}

func TestVerifyFailureMatrix(t *testing.T) {
	tests := []struct {
		name      string
		options   fixtureOptions
		checkName string
	}{
		{
			name:      "missing asset",
			options:   fixtureOptions{missingAsset: "claude-gatekeeper_windows_arm64.zip"},
			checkName: "assets",
		},
		{
			name:      "checksum mismatch",
			options:   fixtureOptions{badChecksum: true},
			checkName: "checksum",
		},
		{
			name:      "downloaded stamp mismatch",
			options:   fixtureOptions{downloadedVersion: "0.0.1"},
			checkName: "downloaded version",
		},
		{
			name:      "stale host binary",
			options:   fixtureOptions{hostVersion: "0.0.1"},
			checkName: "host version",
		},
		{
			name:      "stale plugin binary",
			options:   fixtureOptions{pluginVersion: "0.0.1"},
			checkName: "plugin version",
		},
		{
			name:      "doctor failure",
			options:   fixtureOptions{doctorExit: 2},
			checkName: "doctor",
		},
		{
			name:      "claude canary",
			options:   fixtureOptions{failHarness: "claude"},
			checkName: "claude canary",
		},
		{
			name:      "codex canary",
			options:   fixtureOptions{failHarness: "codex"},
			checkName: "codex canary",
		},
		{
			name:      "grok canary",
			options:   fixtureOptions{failHarness: "grok"},
			checkName: "grok canary",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runFixture(t, test.options)
			if result.OK {
				t.Fatalf("result unexpectedly passed: %#v", result)
			}
			assertCheck(t, result, test.checkName, false)
			if test.name == "doctor failure" && result.ExitCode != 2 {
				t.Fatalf("exit code = %d, want Doctor exit 2", result.ExitCode)
			}
		})
	}
}

func TestVerifyRejectsDraftRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"draft":true,"assets":[]}`, fixtureTag)
	}))
	defer server.Close()
	binary := writeFakeBinary(t, fixtureScript("9.8.7", 0, ""))
	result, err := Verify(context.Background(), Options{
		Tag:          fixtureTag,
		HostBinary:   binary,
		PluginBinary: binary,
		APIBase:      server.URL,
		HTTPClient:   server.Client(),
		GOOS:         "linux",
		GOARCH:       "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCheck(t, result, "release", false)
}

func TestVerifyRejectsMissingRelease(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	binary := writeFakeBinary(t, fixtureScript("9.8.7", 0, ""))
	_, err := Verify(context.Background(), Options{
		Tag:          fixtureTag,
		HostBinary:   binary,
		PluginBinary: binary,
		APIBase:      server.URL,
		HTTPClient:   server.Client(),
		GOOS:         "linux",
		GOARCH:       "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want missing-release failure", err)
	}
}

func TestVerifyRequiresExplicitLivePaths(t *testing.T) {
	_, err := Verify(context.Background(), Options{Tag: fixtureTag})
	if err == nil || !strings.Contains(err.Error(), "--host-binary") {
		t.Fatalf("error = %v", err)
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gz)
	data := []byte("not allowed")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "../escape", Mode: 0644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bad.tar.gz")
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGzip(path, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("error = %v", err)
	}
}

func runFixture(t *testing.T, options fixtureOptions) Result {
	t.Helper()
	version := strings.TrimPrefix(fixtureTag, "v")
	if options.downloadedVersion == "" {
		options.downloadedVersion = version
	}
	if options.hostVersion == "" {
		options.hostVersion = version
	}
	if options.pluginVersion == "" {
		options.pluginVersion = version
	}

	archive := makeTarGzip(t, fixtureScript(options.downloadedVersion, 0, options.failHarness))
	sum := sha256.Sum256(archive)
	checksum := hex.EncodeToString(sum[:])
	if options.badChecksum {
		checksum = strings.Repeat("0", sha256.Size*2)
	}
	checksumBody := checksum + "  claude-gatekeeper_linux_amd64.tar.gz\n"

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/"+defaultRepo+"/releases/tags/"+fixtureTag:
			var assets []githubAsset
			for _, name := range expectedAssets() {
				if name == options.missingAsset {
					continue
				}
				assets = append(assets, githubAsset{Name: name, URL: server.URL + "/assets/" + name})
			}
			_ = json.NewEncoder(w).Encode(githubRelease{TagName: fixtureTag, Assets: assets})
		case request.URL.Path == "/assets/claude-gatekeeper_linux_amd64.tar.gz":
			_, _ = w.Write(archive)
		case request.URL.Path == "/assets/checksums.txt":
			_, _ = w.Write([]byte(checksumBody))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	host := writeFakeBinary(t, fixtureScript(options.hostVersion, 0, ""))
	plugin := writeFakeBinary(t, fixtureScript(options.pluginVersion, options.doctorExit, ""))
	result, err := Verify(context.Background(), Options{
		Tag:          fixtureTag,
		HostBinary:   host,
		PluginBinary: plugin,
		MinSurfaces:  3,
		APIBase:      server.URL,
		HTTPClient:   server.Client(),
		GOOS:         "linux",
		GOARCH:       "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func fixtureScript(version string, doctorExit int, failHarness string) string {
	return fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "claude-gatekeeper %s" >&2
  exit 0
fi
if [ "$1" = "doctor" ]; then
  if [ %d -eq 0 ]; then
    echo '{"ok":true}'
  else
    echo '{"ok":false}'
  fi
  exit %d
fi
harness=claude
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--harness" ]; then
    harness=$2
    shift 2
    continue
  fi
  shift
done
read -r input
if [ "$harness" = "%s" ]; then
  echo '{}'
  exit 0
fi
if [ "$harness" = "grok" ]; then
  echo '{"decision":"deny","reason":"release verifier canary"}'
  exit 2
fi
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"release verifier canary"}}'
exit 0
`, version, doctorExit, doctorExit, failHarness)
}

func writeFakeBinary(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "claude-gatekeeper")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeTarGzip(t *testing.T, script string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gz)
	data := []byte(script)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "bin/claude-gatekeeper",
		Mode: 0755,
		Size: int64(len(data)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func assertCheck(t *testing.T, result Result, name string, want bool) {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			if check.OK != want {
				t.Fatalf("%s = %#v, want OK=%v", name, check, want)
			}
			return
		}
	}
	t.Fatalf("missing check %q in %#v", name, result)
}
