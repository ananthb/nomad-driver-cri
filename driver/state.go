// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"time"

	"github.com/hashicorp/nomad/plugins/drivers"
)

// TaskState is the state which is encoded in the handle returned in
// StartTask. This information is needed to rebuild the task state and handler
// during recovery.
type TaskState struct {
	// ContainerID is the CRI container ID
	ContainerID string

	// PodSandboxID is the CRI pod sandbox ID
	PodSandboxID string

	// TaskConfig is the original task configuration
	TaskConfig *drivers.TaskConfig

	// StartedAt is when the task was started
	StartedAt time.Time
}

// ReattachConfig contains the information needed to reattach to a running
// container. This is used for recovery after Nomad agent restart.
type ReattachConfig struct {
	ContainerID  string `json:"container_id"`
	PodSandboxID string `json:"pod_sandbox_id"`
}
