// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ananthb/nomad-driver-cri/cri"
	"github.com/ananthb/nomad-driver-cri/driver"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	dtestutil "github.com/hashicorp/nomad/plugins/drivers/testutils"
	"github.com/hashicorp/nomad/testutil"
	"github.com/stretchr/testify/require"
)

const (
	// Default CRI socket path
	defaultSocketPath = "/run/containerd/containerd.sock"

	// Test image - small alpine image
	testImage = "docker.io/library/alpine:latest"

	// Busybox for simpler tests
	busyboxImage = "docker.io/library/busybox:latest"

	// Default CNI config directory
	cniConfigDir = "/etc/cni/net.d"
)

var (
	// containerdCmd holds the containerd process if we started it
	containerdCmd *exec.Cmd
	// containerdTmpDir holds the temp directory for containerd config
	containerdTmpDir string
)

// TestMain sets up the test environment, starting containerd if needed
func TestMain(m *testing.M) {
	// Check if we have root privileges
	if os.Getuid() != 0 {
		fmt.Println("Integration tests require root privileges, skipping containerd setup")
		os.Exit(m.Run())
	}

	// Find runc path - if it's in nix store, we need to configure containerd
	runcPath, err := exec.LookPath("runc")
	if err != nil {
		fmt.Println("runc not found in PATH, tests will likely fail")
		os.Exit(m.Run())
	}

	// Check if runc is in a non-standard location (nix store)
	needsContainerdRestart := strings.Contains(runcPath, "/nix/store/")

	// Check if containerd socket already exists
	if _, err := os.Stat(defaultSocketPath); err == nil {
		if !needsContainerdRestart {
			fmt.Println("Using existing containerd (runc in standard location)")
			os.Exit(m.Run())
		}
		fmt.Printf("Existing containerd found, but runc is in nix store (%s)\n", runcPath)
		fmt.Println("Stopping existing containerd to reconfigure...")
		stopExistingContainerd()
	}

	// Start our own containerd with proper runc path configuration
	if err := startContainerd(); err != nil {
		fmt.Printf("Failed to start containerd: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	stopContainerd()

	os.Exit(code)
}

// stopExistingContainerd stops any running containerd process
func stopExistingContainerd() {
	// Try to find and kill existing containerd
	cmd := exec.Command("pkill", "-f", "containerd")
	_ = cmd.Run()

	// Wait for socket to disappear
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(defaultSocketPath); os.IsNotExist(err) {
			fmt.Println("Existing containerd stopped")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println("Warning: Could not stop existing containerd")
}

// startContainerd starts a containerd instance with proper configuration
func startContainerd() error {
	// Check for containerd binary
	containerdPath, err := exec.LookPath("containerd")
	if err != nil {
		return fmt.Errorf("containerd not found: %w", err)
	}

	// Find runc path
	runcPath, err := exec.LookPath("runc")
	if err != nil {
		return fmt.Errorf("runc not found: %w", err)
	}

	fmt.Printf("Using containerd: %s\n", containerdPath)
	fmt.Printf("Using runc: %s\n", runcPath)

	// Create temp directory for config
	containerdTmpDir, err = os.MkdirTemp("", "cri-integration-test")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Write containerd config with explicit runc path
	configPath := filepath.Join(containerdTmpDir, "containerd.toml")
	config := fmt.Sprintf(`
version = 2
root = "/var/lib/containerd"
state = "/run/containerd"

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.9"

[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  BinaryName = %q
`, runcPath)

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Start containerd
	containerdCmd = exec.Command(containerdPath, "-c", configPath)
	containerdCmd.Stdout = os.Stdout
	containerdCmd.Stderr = os.Stderr
	containerdCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := containerdCmd.Start(); err != nil {
		return fmt.Errorf("failed to start containerd: %w", err)
	}

	fmt.Printf("Started containerd (PID %d)\n", containerdCmd.Process.Pid)

	// Wait for socket to be ready
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(defaultSocketPath); err == nil {
			fmt.Println("Containerd socket is ready")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	stopContainerd()
	return fmt.Errorf("containerd socket not ready after 30s")
}

// stopContainerd stops the containerd process if we started it
func stopContainerd() {
	if containerdCmd == nil || containerdCmd.Process == nil {
		return
	}

	fmt.Println("Stopping containerd...")

	// Send SIGTERM
	syscall.Kill(-containerdCmd.Process.Pid, syscall.SIGTERM)

	// Wait for graceful shutdown
	done := make(chan error)
	go func() {
		done <- containerdCmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-containerdCmd.Process.Pid, syscall.SIGKILL)
		<-done
	}

	// Cleanup temp directory
	if containerdTmpDir != "" {
		os.RemoveAll(containerdTmpDir)
	}

	fmt.Println("Containerd stopped")
}

// checkCNIAvailable checks if CNI is configured and available
func checkCNIAvailable(t *testing.T) {
	t.Helper()

	// Check if CNI config directory exists and has config files
	entries, err := os.ReadDir(cniConfigDir)
	if err != nil || len(entries) == 0 {
		t.Skipf("CNI not configured (no config files in %s), skipping test that requires pod networking", cniConfigDir)
	}
}

// testDriverHarness creates a test harness for the CRI driver
func testDriverHarness(t *testing.T) *dtestutil.DriverHarness {
	t.Helper()

	socketPath := os.Getenv("CRI_SOCKET_PATH")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	// Check if socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skipf("CRI socket not found at %s, skipping integration test", socketPath)
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "cri-driver-test",
		Level: hclog.Debug,
	})

	d := driver.NewPlugin(logger)
	harness := dtestutil.NewDriverHarness(t, d)

	// Configure the driver using MessagePack encoding
	driverConfig := driver.PluginConfig{
		SocketPath:       socketPath,
		ImagePullTimeout: "5m",
		StatsInterval:    "1s",
		GC: &driver.GCConfig{
			Container:  true,
			PodSandbox: true,
		},
		RecoverStopped: false,
	}

	// Encode config as MessagePack
	var encodedConfig []byte
	err := base.MsgPackEncode(&encodedConfig, &driverConfig)
	require.NoError(t, err)

	config := &base.Config{
		PluginConfig: encodedConfig,
	}

	require.NoError(t, harness.SetConfig(config))

	return harness
}

// newTaskConfig creates a new task config with resources
func newTaskConfig(name string) *drivers.TaskConfig {
	return &drivers.TaskConfig{
		ID:            uuid.Generate(),
		Name:          name,
		AllocID:       uuid.Generate(),
		JobName:       "test-job",
		TaskGroupName: "test-group",
		Namespace:     "default",
		Resources: &drivers.Resources{
			NomadResources: &structs.AllocatedTaskResources{
				Cpu:    structs.AllocatedCpuResources{CpuShares: 100},
				Memory: structs.AllocatedMemoryResources{MemoryMB: 64},
			},
		},
	}
}

// waitForTaskRunning waits for a task to reach running state
func waitForTaskRunning(t *testing.T, harness *dtestutil.DriverHarness, taskID string) {
	t.Helper()

	testutil.WaitForResult(func() (bool, error) {
		status, err := harness.InspectTask(taskID)
		if err != nil {
			return false, err
		}
		if status.State != drivers.TaskStateRunning {
			return false, fmt.Errorf("task not running yet, state: %s", status.State)
		}
		return true, nil
	}, func(err error) {
		t.Fatalf("task never reached running state: %v", err)
	})
}

// waitForTaskExited waits for a task to exit
func waitForTaskExited(t *testing.T, harness *dtestutil.DriverHarness, taskID string, timeout time.Duration) *drivers.ExitResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ch, err := harness.WaitTask(ctx, taskID)
	require.NoError(t, err)

	select {
	case result := <-ch:
		return result
	case <-ctx.Done():
		t.Fatalf("task did not exit within timeout")
		return nil
	}
}

func TestDriver_Fingerprint(t *testing.T) {
	harness := testDriverHarness(t)
	defer harness.Kill()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fpCh, err := harness.Fingerprint(ctx)
	require.NoError(t, err)

	select {
	case fp := <-fpCh:
		require.Equal(t, drivers.HealthStateHealthy, fp.Health)
		require.NotEmpty(t, fp.Attributes["driver.cri.version"])
		require.NotEmpty(t, fp.Attributes["driver.cri.runtime_name"])

		runtimeName, _ := fp.Attributes["driver.cri.runtime_name"].GetString()
		runtimeVersion, _ := fp.Attributes["driver.cri.runtime_version"].GetString()
		t.Logf("Runtime: %s, Version: %s", runtimeName, runtimeVersion)
	case <-ctx.Done():
		t.Fatal("fingerprint timeout")
	}
}

func TestDriver_StartTask_SimpleCommand(t *testing.T) {
	checkCNIAvailable(t) // CRI containers require CNI for networking
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "echo hello && sleep 1"},
	}

	task := newTaskConfig("test-simple")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(t, err)
	require.NotNil(t, handle)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	// Wait for task to start running
	waitForTaskRunning(t, harness, task.ID)

	// Wait for task to exit
	result := waitForTaskExited(t, harness, task.ID, 30*time.Second)
	require.NotNil(t, result)
	require.Equal(t, 0, result.ExitCode)
}

func TestDriver_StartTask_LongRunning(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-longrunning")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(t, err)
	require.NotNil(t, handle)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	// Wait for task to start running
	waitForTaskRunning(t, harness, task.ID)

	// Verify task is running
	status, err := harness.InspectTask(task.ID)
	require.NoError(t, err)
	require.Equal(t, drivers.TaskStateRunning, status.State)
	require.NotEmpty(t, status.DriverAttributes["container_id"])
	require.NotEmpty(t, status.DriverAttributes["pod_sandbox_id"])
}

func TestDriver_StopTask(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "trap 'exit 0' TERM; while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-stop")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		_ = harness.DestroyTask(task.ID, true)
	}()

	waitForTaskRunning(t, harness, task.ID)

	// Stop the task
	require.NoError(t, harness.StopTask(task.ID, 10*time.Second, "SIGTERM"))

	// Wait for exit
	result := waitForTaskExited(t, harness, task.ID, 15*time.Second)
	require.NotNil(t, result)
}

func TestDriver_ExecTask(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-exec")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	waitForTaskRunning(t, harness, task.ID)

	// Execute a command
	result, err := harness.ExecTask(task.ID, []string{"echo", "hello"}, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, 0, result.ExitResult.ExitCode)
	require.Contains(t, string(result.Stdout), "hello")
}

func TestDriver_TaskStats(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-stats")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	waitForTaskRunning(t, harness, task.ID)

	// Get stats
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	statsCh, err := harness.TaskStats(ctx, task.ID, 1*time.Second)
	require.NoError(t, err)

	select {
	case stats := <-statsCh:
		require.NotNil(t, stats)
		require.NotNil(t, stats.ResourceUsage)
		require.NotNil(t, stats.ResourceUsage.MemoryStats)
		t.Logf("Memory RSS: %d bytes", stats.ResourceUsage.MemoryStats.RSS)
	case <-ctx.Done():
		t.Fatal("stats timeout")
	}
}

func TestDriver_TaskWithMounts(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	// Create a temp directory to mount
	tmpDir, err := os.MkdirTemp("", "cri-driver-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write a test file
	testFile := tmpDir + "/test.txt"
	require.NoError(t, os.WriteFile(testFile, []byte("hello from host"), 0644))

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "cat /mnt/test.txt"},
		Mounts: []driver.MountConfig{
			{
				HostPath:      tmpDir,
				ContainerPath: "/mnt",
				Readonly:      true,
			},
		},
	}

	task := newTaskConfig("test-mounts")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err = harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	// Wait for task to complete
	result := waitForTaskExited(t, harness, task.ID, 30*time.Second)
	require.NotNil(t, result)
	require.Equal(t, 0, result.ExitCode)
}

func TestDriver_TaskWithEnvVars(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "echo $MY_VAR"},
		ExtraEnv: map[string]string{
			"MY_VAR": "test_value",
		},
	}

	task := newTaskConfig("test-env")
	task.Env = map[string]string{
		"NOMAD_VAR": "nomad_value",
	}
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	result := waitForTaskExited(t, harness, task.ID, 30*time.Second)
	require.NotNil(t, result)
	require.Equal(t, 0, result.ExitCode)
}

func TestDriver_TaskWithCapabilities(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "cat /proc/self/status | grep Cap"},
		Capabilities: &driver.CapabilitiesConfig{
			Drop: []string{"ALL"},
			Add:  []string{"NET_BIND_SERVICE"},
		},
	}

	task := newTaskConfig("test-caps")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, harness.DestroyTask(task.ID, true))
	}()

	result := waitForTaskExited(t, harness, task.ID, 30*time.Second)
	require.NotNil(t, result)
	require.Equal(t, 0, result.ExitCode)
}

func TestDriver_DestroyRunningTask(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-destroy")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.NoError(t, err)

	waitForTaskRunning(t, harness, task.ID)

	// Force destroy while running
	require.NoError(t, harness.DestroyTask(task.ID, true))

	// Verify task is gone
	_, err = harness.InspectTask(task.ID)
	require.Error(t, err)
}

func TestDriver_RecoverTask(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   busyboxImage,
		Command: "/bin/sh",
		Args:    []string{"-c", "while true; do sleep 1; done"},
	}

	task := newTaskConfig("test-recover")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(t, err)

	defer func() {
		_ = harness.DestroyTask(task.ID, true)
	}()

	waitForTaskRunning(t, harness, task.ID)

	// Simulate recovery by calling RecoverTask with the handle
	require.NoError(t, harness.RecoverTask(handle))

	// Verify task is still running after recovery
	status, err := harness.InspectTask(task.ID)
	require.NoError(t, err)
	require.Equal(t, drivers.TaskStateRunning, status.State)
}

func TestDriver_NonExistentImage(t *testing.T) {
	checkCNIAvailable(t)
	harness := testDriverHarness(t)
	defer harness.Kill()

	taskCfg := &driver.TaskConfig{
		Image:   "docker.io/library/this-image-does-not-exist-12345:latest",
		Command: "/bin/sh",
		Args:    []string{"-c", "echo hello"},
	}

	task := newTaskConfig("test-bad-image")
	require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

	// Create allocation directory structure
	cleanup := harness.MkAllocDir(task, false)
	defer cleanup()

	_, _, err := harness.StartTask(task)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to pull image")
}

func TestDriver_TaskExitCode(t *testing.T) {
	checkCNIAvailable(t)

	tests := []struct {
		name     string
		exitCode int
	}{
		{"exit-0", 0},
		{"exit-1", 1},
		{"exit-42", 42},
		{"exit-255", 255},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := testDriverHarness(t)
			defer harness.Kill()

			taskCfg := &driver.TaskConfig{
				Image:   busyboxImage,
				Command: "/bin/sh",
				Args:    []string{"-c", fmt.Sprintf("exit %d", tc.exitCode)},
			}

			task := newTaskConfig(tc.name)
			require.NoError(t, task.EncodeConcreteDriverConfig(taskCfg))

			// Create allocation directory structure
			cleanup := harness.MkAllocDir(task, false)
			defer cleanup()

			_, _, err := harness.StartTask(task)
			require.NoError(t, err)

			defer func() {
				_ = harness.DestroyTask(task.ID, true)
			}()

			result := waitForTaskExited(t, harness, task.ID, 30*time.Second)
			require.NotNil(t, result)
			require.Equal(t, tc.exitCode, result.ExitCode)
		})
	}
}

// TestCRIClient_Basic tests the CRI client directly
func TestCRIClient_Basic(t *testing.T) {
	socketPath := os.Getenv("CRI_SOCKET_PATH")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skipf("CRI socket not found at %s", socketPath)
	}

	logger := hclog.NewNullLogger()
	client := cri.NewClient(logger)

	ctx := context.Background()
	require.NoError(t, client.Connect(ctx, socketPath))
	defer client.Close()

	// Test version
	version, err := client.Version(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, version.Version)
	require.NotEmpty(t, version.RuntimeName)
	t.Logf("Connected to %s %s", version.RuntimeName, version.RuntimeVersion)

	// Test status
	status, err := client.Status(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
}
