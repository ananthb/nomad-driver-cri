// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	nomadAddr  = "http://127.0.0.1:4646"
	testJobHCL = `
job "cri-integration-test" {
  datacenters = ["dc1"]
  type        = "batch"

  group "test" {
    count = 1

    task "alpine" {
      driver = "cri"

      config {
        image   = "docker.io/library/alpine:latest"
        command = "/bin/sh"
        args    = ["-c", "echo 'Hello from CRI driver!' && sleep 5"]
      }

      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
`
	serviceJobHCL = `
job "cri-service-test" {
  datacenters = ["dc1"]
  type        = "service"

  group "web" {
    count = 1

    task "nginx" {
      driver = "cri"

      config {
        image = "docker.io/library/nginx:alpine"
      }

      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
`
)

// TestNomadIntegration runs a full integration test with Nomad and containerd
func TestNomadIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Integration test requires root privileges")
	}

	// Check for required binaries
	requireBinary(t, "containerd")
	requireBinary(t, "nomad")

	// Find the plugin binary
	pluginPath := findPluginBinary(t)
	t.Logf("Using plugin: %s", pluginPath)

	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "nomad-cri-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pluginDir := filepath.Join(tmpDir, "plugins")
	dataDir := filepath.Join(tmpDir, "data")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))
	require.NoError(t, os.MkdirAll(dataDir, 0755))

	// Copy plugin to plugin dir
	require.NoError(t, copyFile(pluginPath, filepath.Join(pluginDir, "nomad-driver-cri")))

	// Start containerd if not running
	containerdProc := startContainerdIfNeeded(t, tmpDir)
	if containerdProc != nil {
		defer stopProcess(containerdProc)
	}

	// Wait for containerd socket
	waitForSocket(t, "/run/containerd/containerd.sock", 30*time.Second)

	// Start Nomad
	nomadProc := startNomad(t, pluginDir, dataDir)
	defer stopProcess(nomadProc)

	// Wait for Nomad to be ready
	waitForNomad(t, 60*time.Second)

	// Wait for CRI driver to be detected
	waitForCRIDriver(t, 30*time.Second)

	// Run the batch job test
	t.Run("BatchJob", func(t *testing.T) {
		testBatchJob(t)
	})

	// Run the service job test
	t.Run("ServiceJob", func(t *testing.T) {
		testServiceJob(t)
	})
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	_, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("Required binary %q not found in PATH", name)
	}
}

func findPluginBinary(t *testing.T) string {
	t.Helper()

	// Check common locations
	locations := []string{
		"../plugins/nomad-driver-cri",
		"./plugins/nomad-driver-cri",
		"../result/bin/nomad-driver-cri",
		"./result/bin/nomad-driver-cri",
	}

	// Also check if PLUGIN_PATH env var is set
	if p := os.Getenv("PLUGIN_PATH"); p != "" {
		locations = append([]string{p}, locations...)
	}

	for _, loc := range locations {
		absPath, err := filepath.Abs(loc)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	// Try to build it
	t.Log("Plugin not found, attempting to build...")
	cmd := exec.Command("go", "build", "-o", "../plugins/nomad-driver-cri", "..")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build plugin: %v\n%s", err, out)
	}

	absPath, _ := filepath.Abs("../plugins/nomad-driver-cri")
	return absPath
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func startContainerdIfNeeded(t *testing.T, tmpDir string) *exec.Cmd {
	t.Helper()

	// Check if containerd is already running
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		t.Log("containerd already running")
		return nil
	}

	t.Log("Starting containerd...")

	configPath := filepath.Join(tmpDir, "containerd.toml")
	config := `
version = 2
root = "/var/lib/containerd"
state = "/run/containerd"

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.9"
`
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0644))

	cmd := exec.Command("containerd", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	return cmd
}

func waitForSocket(t *testing.T, socketPath string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			t.Logf("Socket %s is ready", socketPath)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Socket %s not ready after %v", socketPath, timeout)
}

func startNomad(t *testing.T, pluginDir, dataDir string) *exec.Cmd {
	t.Helper()

	t.Log("Starting Nomad...")

	// Create minimal Nomad config just for plugin configuration
	// Use -dev mode for simplified server/client setup
	configPath := filepath.Join(dataDir, "nomad.hcl")
	config := fmt.Sprintf(`
plugin_dir = %q

plugin "nomad-driver-cri" {
  config {
    socket_path        = "/run/containerd/containerd.sock"
    image_pull_timeout = "5m"
  }
}
`, pluginDir)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0644))

	// Use -dev mode for easier startup, -config for plugin config
	cmd := exec.Command("nomad", "agent", "-dev", "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())

	return cmd
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	// Kill the process group
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)

	// Wait a bit for graceful shutdown
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func waitForNomad(t *testing.T, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(nomadAddr + "/v1/status/leader")
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 && len(body) > 2 {
				t.Log("Nomad is ready")
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Nomad not ready after timeout")
}

func waitForCRIDriver(t *testing.T, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(nomadAddr + "/v1/nodes")
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), `"cri"`) {
				t.Log("CRI driver detected")
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("CRI driver not detected after timeout")
}

func testBatchJob(t *testing.T) {
	t.Helper()

	// Submit the job
	jobID := submitJob(t, testJobHCL)
	defer purgeJob(t, jobID)

	// Wait for the job to complete
	waitForJobStatus(t, jobID, "dead", 2*time.Minute)

	// Verify the job completed successfully
	status := getJobStatus(t, jobID)
	require.Contains(t, status, `"Status":"dead"`)
}

func testServiceJob(t *testing.T) {
	t.Helper()

	// Submit the job
	jobID := submitJob(t, serviceJobHCL)
	defer purgeJob(t, jobID)

	// Wait for the job to be running
	waitForJobStatus(t, jobID, "running", 2*time.Minute)

	// Let it run for a bit
	time.Sleep(5 * time.Second)

	// Verify the job is still running
	status := getJobStatus(t, jobID)
	require.Contains(t, status, `"Status":"running"`)
}

func submitJob(t *testing.T, jobHCL string) string {
	t.Helper()

	// Extract job name from HCL
	var jobID string
	for _, line := range strings.Split(jobHCL, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "job ") {
			// Extract job name from: job "name" {
			parts := strings.Split(line, "\"")
			if len(parts) >= 2 {
				jobID = parts[1]
				break
			}
		}
	}
	if jobID == "" {
		t.Fatal("Could not extract job ID from HCL")
	}

	// Submit job using nomad CLI
	cmd := exec.Command("nomad", "job", "run", "-detach", "-")
	cmd.Stdin = strings.NewReader(jobHCL)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "NOMAD_ADDR="+nomadAddr)

	err := cmd.Run()
	if err != nil {
		t.Fatalf("Failed to submit job: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	t.Logf("Job %s submitted: %s", jobID, strings.TrimSpace(stdout.String()))
	return jobID
}

func purgeJob(t *testing.T, jobID string) {
	t.Helper()

	cmd := exec.Command("nomad", "job", "stop", "-purge", jobID)
	cmd.Env = append(os.Environ(), "NOMAD_ADDR="+nomadAddr)
	_ = cmd.Run() // Ignore errors during cleanup
}

func waitForJobStatus(t *testing.T, jobID, expectedStatus string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status := getJobStatus(t, jobID)
		if strings.Contains(status, fmt.Sprintf(`"Status":"%s"`, expectedStatus)) {
			t.Logf("Job %s reached status: %s", jobID, expectedStatus)
			return
		}
		time.Sleep(2 * time.Second)
	}

	// Print final status for debugging
	status := getJobStatus(t, jobID)
	t.Fatalf("Job %s did not reach status %s within timeout. Current status: %s", jobID, expectedStatus, status)
}

func getJobStatus(t *testing.T, jobID string) string {
	t.Helper()

	resp, err := http.Get(fmt.Sprintf("%s/v1/job/%s", nomadAddr, jobID))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(body)
}

// TestNomadExec tests executing commands in running containers
func TestNomadExec(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Integration test requires root privileges")
	}

	// This test assumes Nomad is already running from TestNomadIntegration
	// Check if Nomad is available
	resp, err := http.Get(nomadAddr + "/v1/status/leader")
	if err != nil {
		t.Skip("Nomad not running, skipping exec test")
	}
	resp.Body.Close()

	// Submit a long-running job
	jobHCL := `
job "exec-test" {
  datacenters = ["dc1"]
  type        = "service"

  group "test" {
    task "alpine" {
      driver = "cri"

      config {
        image   = "docker.io/library/alpine:latest"
        command = "/bin/sh"
        args    = ["-c", "while true; do sleep 1; done"]
      }

      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
`

	jobID := submitJob(t, jobHCL)
	defer purgeJob(t, jobID)

	// Wait for job to be running
	waitForJobStatus(t, jobID, "running", 2*time.Minute)

	// Get allocation ID
	allocID := getAllocID(t, jobID)
	require.NotEmpty(t, allocID)

	// Execute a command
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nomad", "alloc", "exec", allocID, "echo", "hello")
	cmd.Env = append(os.Environ(), "NOMAD_ADDR="+nomadAddr)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "exec failed: %s", string(output))
	require.Contains(t, string(output), "hello")
}

func getAllocID(t *testing.T, jobID string) string {
	t.Helper()

	resp, err := http.Get(fmt.Sprintf("%s/v1/job/%s/allocations", nomadAddr, jobID))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Simple parsing - find first allocation ID
	content := string(body)
	if idx := strings.Index(content, `"ID":"`); idx >= 0 {
		start := idx + 6
		end := strings.Index(content[start:], `"`)
		if end > 0 {
			return content[start : start+end]
		}
	}

	return ""
}
