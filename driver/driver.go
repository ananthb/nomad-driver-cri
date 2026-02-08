// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ananthb/nomad-driver-cri/cri"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/structs"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// pluginName is the name of the plugin
	pluginName = "cri"

	// pluginVersion is the version of the plugin
	pluginVersion = "0.1.0"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// taskHandleVersion is the version of task handle which this driver sets
	taskHandleVersion = 1

	// containerMonitorInterval is the interval at which we check container status
	containerMonitorInterval = 2 * time.Second

	// Known CRI socket paths for auto-detection
	containerdSocketPath = "/run/containerd/containerd.sock"
	crioSocketPath       = "/run/crio/crio.sock"
)

var (
	// pluginInfo is the response returned for the PluginInfo RPC
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     pluginVersion,
		Name:              pluginName,
	}

	// capabilities is returned by the Capabilities RPC and indicates what features are supported
	capabilities = &drivers.Capabilities{
		SendSignals: true,
		Exec:        true,
		FSIsolation: drivers.FSIsolationImage,
		NetIsolationModes: []drivers.NetIsolationMode{
			drivers.NetIsolationModeHost,
			drivers.NetIsolationModeGroup,
		},
		MountConfigs: drivers.MountConfigSupportAll,
	}
)

// Driver is the CRI driver implementation
type Driver struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that
	// an event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the plugin configuration set by the SetConfig RPC
	config *PluginConfig

	// nomadConfig is the client config from Nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in-memory datastore mapping task IDs to handles
	tasks *taskStore

	// criClient is the CRI gRPC client
	criClient *cri.Client

	// ctx is the context for the driver
	ctx context.Context

	// cancel is the cancel function for the driver context
	cancel context.CancelFunc

	// logger is the hclog logger
	logger hclog.Logger

	// signalShutdown is called when the driver is shutting down
	signalShutdown context.CancelFunc
}

// taskStore provides a thread-safe way to store task handles
type taskStore struct {
	store map[string]*taskHandle
	lock  sync.RWMutex
}

func newTaskStore() *taskStore {
	return &taskStore{store: map[string]*taskHandle{}}
}

func (ts *taskStore) Set(id string, handle *taskHandle) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	ts.store[id] = handle
}

func (ts *taskStore) Get(id string) (*taskHandle, bool) {
	ts.lock.RLock()
	defer ts.lock.RUnlock()
	h, ok := ts.store[id]
	return h, ok
}

func (ts *taskStore) Delete(id string) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	delete(ts.store, id)
}

// NewPlugin creates a new CRI driver plugin
func NewPlugin(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	return &Driver{
		eventer: eventer.NewEventer(ctx, logger),
		config:  &PluginConfig{},
		tasks:   newTaskStore(),
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger.Named(pluginName),
	}
}

// PluginInfo returns information about the plugin
func (d *Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the plugin configuration schema
func (d *Driver) ConfigSchema() (*hclspec.Spec, error) {
	return pluginConfigSpec, nil
}

// SetConfig applies the plugin configuration
func (d *Driver) SetConfig(cfg *base.Config) error {
	var config PluginConfig
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return fmt.Errorf("failed to decode driver config: %w", err)
		}
	}

	// Auto-detect CRI socket if not configured
	if config.SocketPath == "" {
		socketPath, err := detectCRISocket()
		if err != nil {
			return fmt.Errorf("socket_path not configured and auto-detection failed: %w", err)
		}
		config.SocketPath = socketPath
		d.logger.Warn("socket_path not configured, auto-detected CRI socket", "path", socketPath)
	}
	if config.ImagePullTimeout == "" {
		config.ImagePullTimeout = "5m"
	}
	if config.StatsInterval == "" {
		config.StatsInterval = "1s"
	}
	if config.GC == nil {
		config.GC = &GCConfig{
			Container:  true,
			PodSandbox: true,
		}
	}

	d.config = &config
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	// Initialize CRI client
	d.criClient = cri.NewClient(d.logger)
	if err := d.criClient.Connect(d.ctx, config.SocketPath); err != nil {
		d.logger.Warn("failed to connect to CRI runtime on SetConfig", "error", err)
		// Don't fail - fingerprinting will detect runtime availability
	}

	return nil
}

// detectCRISocket attempts to find an available CRI socket.
// It checks for containerd first, then cri-o.
func detectCRISocket() (string, error) {
	// Check containerd socket first
	if _, err := os.Stat(containerdSocketPath); err == nil {
		return containerdSocketPath, nil
	}

	// Check cri-o socket
	if _, err := os.Stat(crioSocketPath); err == nil {
		return crioSocketPath, nil
	}

	return "", fmt.Errorf("no CRI socket found at %s or %s", containerdSocketPath, crioSocketPath)
}

// TaskConfigSchema returns the task configuration schema
func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

// Capabilities returns the features supported by the driver
func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

// Fingerprint returns a channel that will be used to send health updates
func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)
	ticker := time.NewTicker(fingerprintPeriod)
	defer ticker.Stop()

	// Send initial fingerprint immediately
	select {
	case ch <- d.buildFingerprint():
	case <-ctx.Done():
		return
	case <-d.ctx.Done():
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ch <- d.buildFingerprint()
		}
	}
}

func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes:        map[string]*structs.Attribute{},
		Health:            drivers.HealthStateUndetected,
		HealthDescription: "",
	}

	// Check if socket exists
	if _, err := os.Stat(d.config.SocketPath); os.IsNotExist(err) {
		fp.Health = drivers.HealthStateUnhealthy
		fp.HealthDescription = fmt.Sprintf("CRI socket not found: %s", d.config.SocketPath)
		return fp
	}

	// Try to connect if not connected
	if d.criClient == nil {
		d.criClient = cri.NewClient(d.logger)
	}

	// Get runtime version
	version, err := d.criClient.Version(d.ctx)
	if err != nil {
		// Try to reconnect
		if connErr := d.criClient.Connect(d.ctx, d.config.SocketPath); connErr != nil {
			fp.Health = drivers.HealthStateUnhealthy
			fp.HealthDescription = fmt.Sprintf("Failed to connect to CRI runtime: %v", connErr)
			return fp
		}
		version, err = d.criClient.Version(d.ctx)
		if err != nil {
			fp.Health = drivers.HealthStateUnhealthy
			fp.HealthDescription = fmt.Sprintf("Failed to get CRI version: %v", err)
			return fp
		}
	}

	fp.Health = drivers.HealthStateHealthy
	fp.HealthDescription = "CRI runtime is available"
	fp.Attributes["driver.cri.version"] = structs.NewStringAttribute(version.Version)
	fp.Attributes["driver.cri.runtime_name"] = structs.NewStringAttribute(version.RuntimeName)
	fp.Attributes["driver.cri.runtime_version"] = structs.NewStringAttribute(version.RuntimeVersion)
	fp.Attributes["driver.cri.socket_path"] = structs.NewStringAttribute(d.config.SocketPath)

	return fp
}

// RecoverTask recreates the driver state for a task from a TaskHandle
func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	if handle == nil {
		return fmt.Errorf("handle cannot be nil")
	}

	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil // Already recovered
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state: %w", err)
	}

	// Check if container still exists
	status, err := d.criClient.ContainerStatus(d.ctx, taskState.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to get container status during recovery: %w", err)
	}

	// If container is not running and we don't want to recover stopped containers, skip
	if status.Status.State != runtimeapi.ContainerState_CONTAINER_RUNNING && !d.config.RecoverStopped {
		return fmt.Errorf("container is not running")
	}

	// Rebuild the task handle
	h := &taskHandle{
		containerID:  taskState.ContainerID,
		podSandboxID: taskState.PodSandboxID,
		logger:       d.logger.With("task_name", handle.Config.Name, "alloc_id", handle.Config.AllocID),
		criClient:    d.criClient,
		taskConfig:   handle.Config,
		startedAt:    taskState.StartedAt,
		doneCh:       make(chan struct{}),
	}

	// Set process state based on container state
	switch status.Status.State {
	case runtimeapi.ContainerState_CONTAINER_RUNNING:
		h.procState = drivers.TaskStateRunning
	case runtimeapi.ContainerState_CONTAINER_EXITED:
		h.procState = drivers.TaskStateExited
		h.exitResult = &drivers.ExitResult{
			ExitCode: int(status.Status.ExitCode),
		}
		if status.Status.FinishedAt > 0 {
			h.completedAt = time.Unix(0, status.Status.FinishedAt)
		}
	default:
		h.procState = drivers.TaskStateUnknown
	}

	d.tasks.Set(handle.Config.ID, h)

	// Start monitoring goroutine for running containers
	if h.procState == drivers.TaskStateRunning {
		go h.run(d.ctx)
	}

	return nil
}

// StartTask starts executing a task
func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var taskConfig TaskConfig
	if err := cfg.DecodeDriverConfig(&taskConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %w", err)
	}

	d.logger.Info("starting task", "task_id", cfg.ID, "alloc_id", cfg.AllocID, "image", taskConfig.Image)

	// Pull image if needed
	pullTimeout, err := time.ParseDuration(d.config.ImagePullTimeout)
	if err != nil {
		pullTimeout = 5 * time.Minute
	}
	pullCtx, pullCancel := context.WithTimeout(d.ctx, pullTimeout)
	defer pullCancel()

	var authConfig *runtimeapi.AuthConfig
	if taskConfig.Auth != nil {
		authConfig = &runtimeapi.AuthConfig{
			Username:      taskConfig.Auth.Username,
			Password:      taskConfig.Auth.Password,
			Auth:          taskConfig.Auth.Auth,
			ServerAddress: taskConfig.Auth.ServerAddress,
			IdentityToken: taskConfig.Auth.IdentityToken,
			RegistryToken: taskConfig.Auth.RegistryToken,
		}
	}

	_, err = d.criClient.PullImage(pullCtx, taskConfig.Image, authConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pull image: %w", err)
	}

	// Create pod sandbox
	sandboxConfig := d.buildPodSandboxConfig(cfg, &taskConfig)
	podSandboxID, err := d.criClient.CreatePodSandbox(d.ctx, sandboxConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pod sandbox: %w", err)
	}

	// Create container
	containerConfig := d.buildContainerConfig(cfg, &taskConfig)
	containerID, err := d.criClient.CreateContainer(d.ctx, podSandboxID, containerConfig, sandboxConfig)
	if err != nil {
		// Cleanup pod sandbox on failure
		_ = d.criClient.RemovePodSandbox(d.ctx, podSandboxID)
		return nil, nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Start container
	if err := d.criClient.StartContainer(d.ctx, containerID); err != nil {
		// Cleanup on failure
		_ = d.criClient.RemoveContainer(d.ctx, containerID)
		_ = d.criClient.RemovePodSandbox(d.ctx, podSandboxID)
		return nil, nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Create task handle
	h := &taskHandle{
		containerID:  containerID,
		podSandboxID: podSandboxID,
		logger:       d.logger.With("task_name", cfg.Name, "alloc_id", cfg.AllocID),
		criClient:    d.criClient,
		taskConfig:   cfg,
		procState:    drivers.TaskStateRunning,
		startedAt:    time.Now(),
		doneCh:       make(chan struct{}),
	}

	d.tasks.Set(cfg.ID, h)

	// Start monitoring goroutine
	go h.run(d.ctx)

	// Create driver handle
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	// Store state for recovery
	if err := handle.SetDriverState(&TaskState{
		ContainerID:  containerID,
		PodSandboxID: podSandboxID,
		TaskConfig:   cfg,
		StartedAt:    h.startedAt,
	}); err != nil {
		d.logger.Error("failed to set driver state", "error", err)
	}

	// Build driver network info
	var driverNet *drivers.DriverNetwork
	if taskConfig.NetworkMode == "host" {
		driverNet = &drivers.DriverNetwork{
			PortMap: map[string]int{},
		}
	}

	return handle, driverNet, nil
}

// buildPodSandboxConfig creates the pod sandbox configuration
func (d *Driver) buildPodSandboxConfig(cfg *drivers.TaskConfig, taskConfig *TaskConfig) *runtimeapi.PodSandboxConfig {
	hostname := taskConfig.Hostname
	if hostname == "" {
		hostname = cfg.Name
	}

	labels := map[string]string{
		"io.nomad.alloc_id":   cfg.AllocID,
		"io.nomad.job_name":   cfg.JobName,
		"io.nomad.task_group": cfg.TaskGroupName,
		"io.nomad.task_name":  cfg.Name,
		"io.nomad.namespace":  cfg.Namespace,
	}
	for k, v := range taskConfig.Labels {
		labels[k] = v
	}

	annotations := map[string]string{}
	for k, v := range taskConfig.Annotations {
		annotations[k] = v
	}

	sandboxConfig := &runtimeapi.PodSandboxConfig{
		Metadata: &runtimeapi.PodSandboxMetadata{
			Name:      cfg.Name,
			Uid:       cfg.AllocID,
			Namespace: cfg.Namespace,
			Attempt:   0,
		},
		Hostname:     hostname,
		LogDirectory: cfg.TaskDir().LogDir,
		Labels:       labels,
		Annotations:  annotations,
		Linux:        &runtimeapi.LinuxPodSandboxConfig{},
	}

	// Configure DNS
	if taskConfig.DNS != nil {
		sandboxConfig.DnsConfig = &runtimeapi.DNSConfig{
			Servers:  taskConfig.DNS.Servers,
			Searches: taskConfig.DNS.Searches,
			Options:  taskConfig.DNS.Options,
		}
	}

	// Configure network namespace
	switch taskConfig.NetworkMode {
	case "host":
		sandboxConfig.Linux.SecurityContext = &runtimeapi.LinuxSandboxSecurityContext{
			NamespaceOptions: &runtimeapi.NamespaceOption{
				Network: runtimeapi.NamespaceMode_NODE,
				Pid:     runtimeapi.NamespaceMode_CONTAINER,
				Ipc:     runtimeapi.NamespaceMode_POD,
			},
		}
	default:
		sandboxConfig.Linux.SecurityContext = &runtimeapi.LinuxSandboxSecurityContext{
			NamespaceOptions: &runtimeapi.NamespaceOption{
				Network: runtimeapi.NamespaceMode_POD,
				Pid:     runtimeapi.NamespaceMode_CONTAINER,
				Ipc:     runtimeapi.NamespaceMode_POD,
			},
		}
	}

	// Port mappings
	for _, pm := range taskConfig.PortMappings {
		proto := runtimeapi.Protocol_TCP
		if pm.Protocol == "udp" {
			proto = runtimeapi.Protocol_UDP
		}
		sandboxConfig.PortMappings = append(sandboxConfig.PortMappings, &runtimeapi.PortMapping{
			Protocol:      proto,
			ContainerPort: pm.ContainerPort,
			HostPort:      pm.HostPort,
		})
	}

	return sandboxConfig
}

// buildContainerConfig creates the container configuration
func (d *Driver) buildContainerConfig(cfg *drivers.TaskConfig, taskConfig *TaskConfig) *runtimeapi.ContainerConfig {
	containerConfig := &runtimeapi.ContainerConfig{
		Metadata: &runtimeapi.ContainerMetadata{
			Name:    cfg.Name,
			Attempt: 0,
		},
		Image: &runtimeapi.ImageSpec{
			Image: taskConfig.Image,
		},
		LogPath: fmt.Sprintf("%s.log", cfg.Name),
		Linux:   &runtimeapi.LinuxContainerConfig{},
		Labels: map[string]string{
			"io.nomad.alloc_id":   cfg.AllocID,
			"io.nomad.job_name":   cfg.JobName,
			"io.nomad.task_group": cfg.TaskGroupName,
			"io.nomad.task_name":  cfg.Name,
		},
		Annotations: map[string]string{},
	}

	// Command and args
	if taskConfig.Command != "" {
		containerConfig.Command = []string{taskConfig.Command}
	}
	if len(taskConfig.Args) > 0 {
		containerConfig.Args = taskConfig.Args
	}

	// Working directory
	if taskConfig.WorkingDir != "" {
		containerConfig.WorkingDir = taskConfig.WorkingDir
	}

	// Environment variables - merge Nomad env with extra env
	envVars := make([]*runtimeapi.KeyValue, 0)
	for k, v := range cfg.Env {
		envVars = append(envVars, &runtimeapi.KeyValue{Key: k, Value: v})
	}
	for k, v := range taskConfig.ExtraEnv {
		envVars = append(envVars, &runtimeapi.KeyValue{Key: k, Value: v})
	}
	containerConfig.Envs = envVars

	// Mounts
	mounts := make([]*runtimeapi.Mount, 0)

	// Add task directory mounts
	mounts = append(mounts, &runtimeapi.Mount{
		ContainerPath: "/alloc",
		HostPath:      cfg.TaskDir().SharedAllocDir,
		Readonly:      false,
	})
	mounts = append(mounts, &runtimeapi.Mount{
		ContainerPath: "/local",
		HostPath:      cfg.TaskDir().LocalDir,
		Readonly:      false,
	})
	mounts = append(mounts, &runtimeapi.Mount{
		ContainerPath: "/secrets",
		HostPath:      cfg.TaskDir().SecretsDir,
		Readonly:      true,
	})

	// Add user-defined mounts
	for _, m := range taskConfig.Mounts {
		mount := &runtimeapi.Mount{
			ContainerPath: m.ContainerPath,
			HostPath:      m.HostPath,
			Readonly:      m.Readonly,
		}
		switch m.Propagation {
		case "private":
			mount.Propagation = runtimeapi.MountPropagation_PROPAGATION_PRIVATE
		case "host-to-container":
			mount.Propagation = runtimeapi.MountPropagation_PROPAGATION_HOST_TO_CONTAINER
		case "bidirectional":
			mount.Propagation = runtimeapi.MountPropagation_PROPAGATION_BIDIRECTIONAL
		}
		mounts = append(mounts, mount)
	}
	containerConfig.Mounts = mounts

	// Devices
	devices := make([]*runtimeapi.Device, 0)
	for _, dev := range taskConfig.Devices {
		devices = append(devices, &runtimeapi.Device{
			ContainerPath: dev.ContainerPath,
			HostPath:      dev.HostPath,
			Permissions:   dev.Permissions,
		})
	}
	containerConfig.Devices = devices

	// Security context
	securityContext := &runtimeapi.LinuxContainerSecurityContext{
		Privileged:     taskConfig.Privileged,
		ReadonlyRootfs: taskConfig.ReadonlyRootfs,
	}

	// Capabilities
	if taskConfig.Capabilities != nil {
		securityContext.Capabilities = &runtimeapi.Capability{
			AddCapabilities:  taskConfig.Capabilities.Add,
			DropCapabilities: taskConfig.Capabilities.Drop,
		}
	}

	// Linux security context
	if taskConfig.Linux != nil && taskConfig.Linux.SecurityContext != nil {
		sc := taskConfig.Linux.SecurityContext
		if sc.RunAsUser != 0 {
			securityContext.RunAsUser = &runtimeapi.Int64Value{Value: sc.RunAsUser}
		}
		if sc.RunAsGroup != 0 {
			securityContext.RunAsGroup = &runtimeapi.Int64Value{Value: sc.RunAsGroup}
		}
		securityContext.SupplementalGroups = sc.SupplementalGroups
		securityContext.NoNewPrivs = sc.NoNewPrivs
		securityContext.MaskedPaths = sc.MaskedPaths
		securityContext.ReadonlyPaths = sc.ReadonlyPaths

		if sc.SELinuxOptions != nil {
			securityContext.SelinuxOptions = &runtimeapi.SELinuxOption{
				User:  sc.SELinuxOptions.User,
				Role:  sc.SELinuxOptions.Role,
				Type:  sc.SELinuxOptions.Type,
				Level: sc.SELinuxOptions.Level,
			}
		}

		if sc.SeccompProfilePath != "" {
			securityContext.Seccomp = &runtimeapi.SecurityProfile{
				ProfileType:  runtimeapi.SecurityProfile_Localhost,
				LocalhostRef: sc.SeccompProfilePath,
			}
		}

		if sc.AppArmorProfile != "" {
			securityContext.Apparmor = &runtimeapi.SecurityProfile{
				ProfileType:  runtimeapi.SecurityProfile_Localhost,
				LocalhostRef: sc.AppArmorProfile,
			}
		}
	}

	containerConfig.Linux.SecurityContext = securityContext

	// Resource limits from Nomad task resources
	if cfg.Resources != nil {
		resources := &runtimeapi.LinuxContainerResources{}
		if cfg.Resources.NomadResources != nil {
			if cfg.Resources.NomadResources.Cpu.CpuShares > 0 {
				resources.CpuShares = cfg.Resources.NomadResources.Cpu.CpuShares
			}
			if cfg.Resources.NomadResources.Memory.MemoryMB > 0 {
				resources.MemoryLimitInBytes = cfg.Resources.NomadResources.Memory.MemoryMB * 1024 * 1024
			}
		}
		if cfg.Resources.LinuxResources != nil {
			if cfg.Resources.LinuxResources.CPUShares > 0 {
				resources.CpuShares = cfg.Resources.LinuxResources.CPUShares
			}
			if cfg.Resources.LinuxResources.MemoryLimitBytes > 0 {
				resources.MemoryLimitInBytes = cfg.Resources.LinuxResources.MemoryLimitBytes
			}
			if cfg.Resources.LinuxResources.CpusetCpus != "" {
				resources.CpusetCpus = cfg.Resources.LinuxResources.CpusetCpus
			}
		}
		containerConfig.Linux.Resources = resources
	}

	return containerConfig
}

// WaitTask returns a channel that signals when the task completes
func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	ch := make(chan *drivers.ExitResult)
	go func() {
		defer close(ch)
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-handle.doneCh:
			ch <- handle.exitResult
		}
	}()

	return ch, nil
}

// StopTask stops a running task
func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return fmt.Errorf("task with ID %q not found", taskID)
	}

	d.logger.Info("stopping task", "task_id", taskID, "timeout", timeout, "signal", signal)

	// Stop the container with the timeout
	err := d.criClient.StopContainer(d.ctx, handle.containerID, int64(timeout.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

// DestroyTask cleans up a task
func (d *Driver) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil // Already destroyed
	}

	d.logger.Info("destroying task", "task_id", taskID, "force", force)

	// If force, stop immediately
	if force && handle.procState == drivers.TaskStateRunning {
		_ = d.criClient.StopContainer(d.ctx, handle.containerID, 0)
	}

	// Remove container
	if d.config.GC.Container {
		if err := d.criClient.RemoveContainer(d.ctx, handle.containerID); err != nil {
			d.logger.Warn("failed to remove container", "error", err)
		}
	}

	// Remove pod sandbox
	if d.config.GC.PodSandbox {
		if err := d.criClient.StopPodSandbox(d.ctx, handle.podSandboxID); err != nil {
			d.logger.Warn("failed to stop pod sandbox", "error", err)
		}
		if err := d.criClient.RemovePodSandbox(d.ctx, handle.podSandboxID); err != nil {
			d.logger.Warn("failed to remove pod sandbox", "error", err)
		}
	}

	d.tasks.Delete(taskID)
	return nil
}

// InspectTask returns the task status
func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return handle.TaskStatus(), nil
}

// TaskStats returns resource usage statistics for a task
func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return handle.Stats(ctx, d.criClient, interval)
}

// TaskEvents returns a channel for task events
func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

// SignalTask sends a signal to a task
func (d *Driver) SignalTask(taskID string, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return fmt.Errorf("task with ID %q not found", taskID)
	}

	d.logger.Debug("signaling task", "task_id", taskID, "signal", signal)

	// CRI doesn't have a direct signal API, so we use ExecSync with kill
	// For SIGTERM/SIGKILL, we can use StopContainer
	switch signal {
	case "SIGTERM", "TERM", "15":
		return d.criClient.StopContainer(d.ctx, handle.containerID, 30)
	case "SIGKILL", "KILL", "9":
		return d.criClient.StopContainer(d.ctx, handle.containerID, 0)
	default:
		// For other signals, we need to exec kill inside the container
		_, err := d.criClient.ExecSync(d.ctx, handle.containerID, []string{"kill", "-s", signal, "1"}, 5)
		return err
	}
}

// ExecTask executes a command in a running task
func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	d.logger.Debug("executing command in task", "task_id", taskID, "cmd", cmd)

	resp, err := d.criClient.ExecSync(d.ctx, handle.containerID, cmd, int64(timeout.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("failed to exec command: %w", err)
	}

	return &drivers.ExecTaskResult{
		Stdout: resp.Stdout,
		Stderr: resp.Stderr,
		ExitResult: &drivers.ExitResult{
			ExitCode: int(resp.ExitCode),
		},
	}, nil
}

// ExecTaskStreaming executes a command with streaming I/O
func (d *Driver) ExecTaskStreaming(ctx context.Context, taskID string, opts *drivers.ExecOptions) (*drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	d.logger.Debug("streaming exec in task", "task_id", taskID, "cmd", opts.Command)

	// For streaming exec, we use ExecSync for now as full streaming requires
	// setting up a streaming server
	resp, err := d.criClient.ExecSync(d.ctx, handle.containerID, opts.Command, 300)
	if err != nil {
		return nil, fmt.Errorf("failed to exec command: %w", err)
	}

	// Write output to the provided streams
	if opts.Stdout != nil {
		_, _ = opts.Stdout.Write(resp.Stdout)
	}
	if opts.Stderr != nil {
		_, _ = opts.Stderr.Write(resp.Stderr)
	}

	return &drivers.ExitResult{
		ExitCode: int(resp.ExitCode),
	}, nil
}

// Shutdown is called when the plugin is shutting down
func (d *Driver) Shutdown() {
	d.logger.Info("shutting down CRI driver")
	d.cancel()
	if d.criClient != nil {
		_ = d.criClient.Close()
	}
}
