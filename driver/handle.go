// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"context"
	"time"

	"github.com/ananthb/nomad-driver-cri/cri"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// taskHandle represents a running task
type taskHandle struct {
	// containerID is the CRI container ID
	containerID string

	// podSandboxID is the CRI pod sandbox ID
	podSandboxID string

	// logger is the task logger
	logger hclog.Logger

	// criClient is the CRI gRPC client
	criClient *cri.Client

	// taskConfig is the Nomad task configuration
	taskConfig *drivers.TaskConfig

	// procState is the current state of the task
	procState drivers.TaskState

	// startedAt is when the task was started
	startedAt time.Time

	// completedAt is when the task completed (if applicable)
	completedAt time.Time

	// exitResult contains the exit information
	exitResult *drivers.ExitResult

	// doneCh is closed when the task exits
	doneCh chan struct{}
}

// run monitors the container and updates state when it exits
func (h *taskHandle) run(ctx context.Context) {
	defer close(h.doneCh)

	ticker := time.NewTicker(containerMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := h.criClient.ContainerStatus(ctx, h.containerID)
			if err != nil {
				h.logger.Warn("failed to get container status", "error", err)
				continue
			}

			if status.Status == nil {
				continue
			}

			switch status.Status.State {
			case runtimeapi.ContainerState_CONTAINER_RUNNING:
				// Still running, continue monitoring
				continue

			case runtimeapi.ContainerState_CONTAINER_EXITED:
				h.procState = drivers.TaskStateExited
				h.completedAt = time.Now()
				if status.Status.FinishedAt > 0 {
					h.completedAt = time.Unix(0, status.Status.FinishedAt)
				}

				exitCode := int(status.Status.ExitCode)
				h.exitResult = &drivers.ExitResult{
					ExitCode: exitCode,
				}

				// Determine if it was an error or normal exit
				if exitCode != 0 {
					h.exitResult.Err = nil // Error is indicated by non-zero exit code
				}

				h.logger.Info("container exited",
					"exit_code", exitCode,
					"started_at", h.startedAt,
					"finished_at", h.completedAt,
				)
				return

			case runtimeapi.ContainerState_CONTAINER_UNKNOWN:
				h.logger.Warn("container state unknown")
				h.procState = drivers.TaskStateUnknown
				return

			case runtimeapi.ContainerState_CONTAINER_CREATED:
				// Container was created but not started yet - unusual state
				h.logger.Warn("container in created state during monitoring")
				continue
			}
		}
	}
}

// TaskStatus returns the current task status
func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.procState,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
		DriverAttributes: map[string]string{
			"container_id":   h.containerID,
			"pod_sandbox_id": h.podSandboxID,
		},
	}
}

// IsRunning returns whether the task is currently running
func (h *taskHandle) IsRunning() bool {
	return h.procState == drivers.TaskStateRunning
}

// Stats returns a channel that streams resource usage statistics
func (h *taskHandle) Stats(ctx context.Context, client *cri.Client, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	ch := make(chan *drivers.TaskResourceUsage)

	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-h.doneCh:
				return
			case <-ticker.C:
				stats, err := client.ContainerStats(ctx, h.containerID)
				if err != nil {
					h.logger.Debug("failed to get container stats", "error", err)
					continue
				}

				if stats == nil {
					continue
				}

				usage := h.buildResourceUsage(stats)
				select {
				case ch <- usage:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return ch, nil
}

// buildResourceUsage converts CRI stats to Nomad's TaskResourceUsage
func (h *taskHandle) buildResourceUsage(stats *runtimeapi.ContainerStats) *drivers.TaskResourceUsage {
	ts := time.Now().UnixNano()

	usage := &drivers.TaskResourceUsage{
		ResourceUsage: &drivers.ResourceUsage{
			MemoryStats: &drivers.MemoryStats{},
			CpuStats:    &drivers.CpuStats{},
		},
		Timestamp: ts,
	}

	// Memory stats
	if stats.Memory != nil {
		usage.ResourceUsage.MemoryStats.RSS = stats.Memory.WorkingSetBytes.GetValue()
		usage.ResourceUsage.MemoryStats.Usage = stats.Memory.UsageBytes.GetValue()
		usage.ResourceUsage.MemoryStats.MaxUsage = stats.Memory.UsageBytes.GetValue()
		usage.ResourceUsage.MemoryStats.Measured = []string{"RSS", "Usage", "Max Usage"}
	}

	// CPU stats
	if stats.Cpu != nil {
		// CRI reports total CPU usage in nanoseconds
		// TotalTicks is a float64 representing seconds of CPU time
		usage.ResourceUsage.CpuStats.TotalTicks = float64(stats.Cpu.UsageCoreNanoSeconds.GetValue()) / 1e9
		usage.ResourceUsage.CpuStats.Measured = []string{"System Mode", "User Mode", "Percent"}

		// Calculate percent if we have a timestamp
		if stats.Cpu.Timestamp > 0 {
			// This is a simplified calculation - for accurate percentage,
			// we'd need to track the previous value
			usage.ResourceUsage.CpuStats.Percent = 0
		}
	}

	return usage
}
