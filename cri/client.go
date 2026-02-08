// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package cri

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// DefaultTimeout is the default timeout for CRI operations
	DefaultTimeout = 2 * time.Minute

	// DefaultConnectionTimeout is the timeout for establishing gRPC connection
	DefaultConnectionTimeout = 30 * time.Second
)

// Client wraps the CRI gRPC client for runtime and image services
type Client struct {
	conn           *grpc.ClientConn
	runtimeService runtimeapi.RuntimeServiceClient
	imageService   runtimeapi.ImageServiceClient
	logger         hclog.Logger
	socketPath     string
}

// NewClient creates a new CRI client
func NewClient(logger hclog.Logger) *Client {
	return &Client{
		logger: logger.Named("cri-client"),
	}
}

// Connect establishes a gRPC connection to the CRI socket
func (c *Client) Connect(ctx context.Context, socketPath string) error {
	c.socketPath = socketPath
	c.logger.Debug("connecting to CRI socket", "path", socketPath)

	// Parse the socket path
	addr, err := parseEndpoint(socketPath)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}

	// Set up connection with timeout
	connCtx, cancel := context.WithTimeout(ctx, DefaultConnectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(connCtx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to CRI socket %s: %w", socketPath, err)
	}

	c.conn = conn
	c.runtimeService = runtimeapi.NewRuntimeServiceClient(conn)
	c.imageService = runtimeapi.NewImageServiceClient(conn)

	c.logger.Info("connected to CRI runtime", "socket", socketPath)
	return nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Version returns the runtime version information
func (c *Client) Version(ctx context.Context) (*runtimeapi.VersionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.Version(ctx, &runtimeapi.VersionRequest{})
}

// PullImage pulls a container image
func (c *Client) PullImage(ctx context.Context, image string, auth *runtimeapi.AuthConfig) (string, error) {
	c.logger.Debug("pulling image", "image", image)

	imageSpec := &runtimeapi.ImageSpec{
		Image: image,
	}

	resp, err := c.imageService.PullImage(ctx, &runtimeapi.PullImageRequest{
		Image: imageSpec,
		Auth:  auth,
	})
	if err != nil {
		return "", fmt.Errorf("failed to pull image %s: %w", image, err)
	}

	c.logger.Info("pulled image", "image", image, "ref", resp.ImageRef)
	return resp.ImageRef, nil
}

// ImageStatus returns the status of an image
func (c *Client) ImageStatus(ctx context.Context, image string) (*runtimeapi.ImageStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.imageService.ImageStatus(ctx, &runtimeapi.ImageStatusRequest{
		Image: &runtimeapi.ImageSpec{
			Image: image,
		},
	})
}

// CreatePodSandbox creates a new pod sandbox
func (c *Client) CreatePodSandbox(ctx context.Context, config *runtimeapi.PodSandboxConfig) (string, error) {
	c.logger.Debug("creating pod sandbox", "name", config.Metadata.Name)

	resp, err := c.runtimeService.RunPodSandbox(ctx, &runtimeapi.RunPodSandboxRequest{
		Config: config,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create pod sandbox: %w", err)
	}

	c.logger.Info("created pod sandbox", "id", resp.PodSandboxId, "name", config.Metadata.Name)
	return resp.PodSandboxId, nil
}

// StopPodSandbox stops a pod sandbox
func (c *Client) StopPodSandbox(ctx context.Context, podSandboxID string) error {
	c.logger.Debug("stopping pod sandbox", "id", podSandboxID)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	_, err := c.runtimeService.StopPodSandbox(ctx, &runtimeapi.StopPodSandboxRequest{
		PodSandboxId: podSandboxID,
	})
	if err != nil {
		return fmt.Errorf("failed to stop pod sandbox %s: %w", podSandboxID, err)
	}

	c.logger.Info("stopped pod sandbox", "id", podSandboxID)
	return nil
}

// RemovePodSandbox removes a pod sandbox
func (c *Client) RemovePodSandbox(ctx context.Context, podSandboxID string) error {
	c.logger.Debug("removing pod sandbox", "id", podSandboxID)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	_, err := c.runtimeService.RemovePodSandbox(ctx, &runtimeapi.RemovePodSandboxRequest{
		PodSandboxId: podSandboxID,
	})
	if err != nil {
		return fmt.Errorf("failed to remove pod sandbox %s: %w", podSandboxID, err)
	}

	c.logger.Info("removed pod sandbox", "id", podSandboxID)
	return nil
}

// PodSandboxStatus returns the status of a pod sandbox
func (c *Client) PodSandboxStatus(ctx context.Context, podSandboxID string) (*runtimeapi.PodSandboxStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.PodSandboxStatus(ctx, &runtimeapi.PodSandboxStatusRequest{
		PodSandboxId: podSandboxID,
		Verbose:      true,
	})
}

// ListPodSandbox lists pod sandboxes matching the filter
func (c *Client) ListPodSandbox(ctx context.Context, filter *runtimeapi.PodSandboxFilter) ([]*runtimeapi.PodSandbox, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	resp, err := c.runtimeService.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pod sandboxes: %w", err)
	}

	return resp.Items, nil
}

// CreateContainer creates a new container in a pod sandbox
func (c *Client) CreateContainer(ctx context.Context, podSandboxID string, config *runtimeapi.ContainerConfig, sandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	c.logger.Debug("creating container", "name", config.Metadata.Name, "pod", podSandboxID)

	resp, err := c.runtimeService.CreateContainer(ctx, &runtimeapi.CreateContainerRequest{
		PodSandboxId:  podSandboxID,
		Config:        config,
		SandboxConfig: sandboxConfig,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	c.logger.Info("created container", "id", resp.ContainerId, "name", config.Metadata.Name)
	return resp.ContainerId, nil
}

// StartContainer starts a container
func (c *Client) StartContainer(ctx context.Context, containerID string) error {
	c.logger.Debug("starting container", "id", containerID)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	_, err := c.runtimeService.StartContainer(ctx, &runtimeapi.StartContainerRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", containerID, err)
	}

	c.logger.Info("started container", "id", containerID)
	return nil
}

// StopContainer stops a running container with a grace period
func (c *Client) StopContainer(ctx context.Context, containerID string, timeout int64) error {
	c.logger.Debug("stopping container", "id", containerID, "timeout", timeout)

	// Use a longer context timeout to allow for the container stop timeout
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second+30*time.Second)
	defer cancel()

	_, err := c.runtimeService.StopContainer(ctx, &runtimeapi.StopContainerRequest{
		ContainerId: containerID,
		Timeout:     timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerID, err)
	}

	c.logger.Info("stopped container", "id", containerID)
	return nil
}

// RemoveContainer removes a container
func (c *Client) RemoveContainer(ctx context.Context, containerID string) error {
	c.logger.Debug("removing container", "id", containerID)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	_, err := c.runtimeService.RemoveContainer(ctx, &runtimeapi.RemoveContainerRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("failed to remove container %s: %w", containerID, err)
	}

	c.logger.Info("removed container", "id", containerID)
	return nil
}

// ContainerStatus returns the status of a container
func (c *Client) ContainerStatus(ctx context.Context, containerID string) (*runtimeapi.ContainerStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
}

// ListContainers lists containers matching the filter
func (c *Client) ListContainers(ctx context.Context, filter *runtimeapi.ContainerFilter) ([]*runtimeapi.Container, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	resp, err := c.runtimeService.ListContainers(ctx, &runtimeapi.ListContainersRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return resp.Containers, nil
}

// ExecSync executes a command in a container synchronously
func (c *Client) ExecSync(ctx context.Context, containerID string, cmd []string, timeout int64) (*runtimeapi.ExecSyncResponse, error) {
	c.logger.Debug("executing command", "container", containerID, "cmd", cmd)

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	return c.runtimeService.ExecSync(execCtx, &runtimeapi.ExecSyncRequest{
		ContainerId: containerID,
		Cmd:         cmd,
		Timeout:     timeout,
	})
}

// Exec prepares a streaming exec request and returns the URL
func (c *Client) Exec(ctx context.Context, containerID string, cmd []string, tty bool, stdin bool) (*runtimeapi.ExecResponse, error) {
	c.logger.Debug("preparing exec", "container", containerID, "cmd", cmd, "tty", tty)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.Exec(ctx, &runtimeapi.ExecRequest{
		ContainerId: containerID,
		Cmd:         cmd,
		Tty:         tty,
		Stdin:       stdin,
		Stdout:      true,
		Stderr:      !tty,
	})
}

// Attach prepares a streaming attach request and returns the URL
func (c *Client) Attach(ctx context.Context, containerID string, tty bool, stdin bool) (*runtimeapi.AttachResponse, error) {
	c.logger.Debug("preparing attach", "container", containerID, "tty", tty)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.Attach(ctx, &runtimeapi.AttachRequest{
		ContainerId: containerID,
		Tty:         tty,
		Stdin:       stdin,
		Stdout:      true,
		Stderr:      !tty,
	})
}

// ContainerStats returns stats for a container
func (c *Client) ContainerStats(ctx context.Context, containerID string) (*runtimeapi.ContainerStats, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	resp, err := c.runtimeService.ContainerStats(ctx, &runtimeapi.ContainerStatsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}

	return resp.Stats, nil
}

// ListContainerStats returns stats for multiple containers
func (c *Client) ListContainerStats(ctx context.Context, filter *runtimeapi.ContainerStatsFilter) ([]*runtimeapi.ContainerStats, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	resp, err := c.runtimeService.ListContainerStats(ctx, &runtimeapi.ListContainerStatsRequest{
		Filter: filter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list container stats: %w", err)
	}

	return resp.Stats, nil
}

// UpdateContainerResources updates resource constraints for a container
func (c *Client) UpdateContainerResources(ctx context.Context, containerID string, resources *runtimeapi.ContainerResources) error {
	c.logger.Debug("updating container resources", "container", containerID)

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	_, err := c.runtimeService.UpdateContainerResources(ctx, &runtimeapi.UpdateContainerResourcesRequest{
		ContainerId: containerID,
		Linux:       resources.Linux,
	})
	if err != nil {
		return fmt.Errorf("failed to update container resources: %w", err)
	}

	return nil
}

// Status returns the status of the runtime
func (c *Client) Status(ctx context.Context) (*runtimeapi.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	return c.runtimeService.Status(ctx, &runtimeapi.StatusRequest{
		Verbose: true,
	})
}

// parseEndpoint parses the CRI socket endpoint
func parseEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		// Try as a plain path
		return endpoint, nil
	}

	switch u.Scheme {
	case "unix":
		return u.Path, nil
	case "":
		return endpoint, nil
	default:
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

// IsRunning checks if a container is running
func (c *Client) IsRunning(ctx context.Context, containerID string) (bool, error) {
	status, err := c.ContainerStatus(ctx, containerID)
	if err != nil {
		return false, err
	}

	if status.Status == nil {
		return false, nil
	}

	return status.Status.State == runtimeapi.ContainerState_CONTAINER_RUNNING, nil
}

// WaitContainerTerminated waits for a container to terminate and returns the exit code
func (c *Client) WaitContainerTerminated(ctx context.Context, containerID string, pollInterval time.Duration) (int32, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-ticker.C:
			status, err := c.ContainerStatus(ctx, containerID)
			if err != nil {
				c.logger.Warn("failed to get container status while waiting", "error", err)
				continue
			}

			if status.Status == nil {
				continue
			}

			if status.Status.State == runtimeapi.ContainerState_CONTAINER_EXITED {
				return status.Status.ExitCode, nil
			}
		}
	}
}
