// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"context"
	"time"

	"github.com/ananthb/nomad-driver-cri/cri"
	"github.com/hashicorp/nomad/plugins/drivers"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// StatsCollector collects resource statistics for containers
type StatsCollector struct {
	client      *cri.Client
	containerID string
	interval    time.Duration

	// Track previous CPU values for percentage calculation
	prevCPUNanos int64
	prevTime     time.Time
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector(client *cri.Client, containerID string, interval time.Duration) *StatsCollector {
	return &StatsCollector{
		client:      client,
		containerID: containerID,
		interval:    interval,
	}
}

// Collect returns a channel that streams resource usage statistics
func (sc *StatsCollector) Collect(ctx context.Context) (<-chan *drivers.TaskResourceUsage, error) {
	ch := make(chan *drivers.TaskResourceUsage)

	go func() {
		defer close(ch)
		ticker := time.NewTicker(sc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, err := sc.client.ContainerStats(ctx, sc.containerID)
				if err != nil {
					continue
				}

				if stats == nil {
					continue
				}

				usage := sc.buildResourceUsage(stats)
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
func (sc *StatsCollector) buildResourceUsage(stats *runtimeapi.ContainerStats) *drivers.TaskResourceUsage {
	now := time.Now()
	ts := now.UnixNano()

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
		cpuNanos := int64(stats.Cpu.UsageCoreNanoSeconds.GetValue())
		usage.ResourceUsage.CpuStats.TotalTicks = float64(cpuNanos) / 1e9
		usage.ResourceUsage.CpuStats.Measured = []string{"System Mode", "User Mode", "Percent"}

		// Calculate CPU percentage
		if sc.prevTime.IsZero() {
			sc.prevCPUNanos = cpuNanos
			sc.prevTime = now
		} else {
			elapsed := now.Sub(sc.prevTime).Nanoseconds()
			if elapsed > 0 {
				cpuDelta := cpuNanos - sc.prevCPUNanos
				// Percentage of one CPU core
				usage.ResourceUsage.CpuStats.Percent = float64(cpuDelta) / float64(elapsed) * 100
			}
			sc.prevCPUNanos = cpuNanos
			sc.prevTime = now
		}
	}

	return usage
}
