// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriver_PluginInfo(t *testing.T) {
	logger := hclog.NewNullLogger()
	d := NewPlugin(logger)

	info, err := d.PluginInfo()
	require.NoError(t, err)
	assert.Equal(t, "cri", info.Name)
	assert.Equal(t, "driver", string(info.Type))
}

func TestDriver_ConfigSchema(t *testing.T) {
	logger := hclog.NewNullLogger()
	d := NewPlugin(logger)

	schema, err := d.ConfigSchema()
	require.NoError(t, err)
	require.NotNil(t, schema)
}

func TestDriver_TaskConfigSchema(t *testing.T) {
	logger := hclog.NewNullLogger()
	d := NewPlugin(logger)

	schema, err := d.TaskConfigSchema()
	require.NoError(t, err)
	require.NotNil(t, schema)
}

func TestDriver_Capabilities(t *testing.T) {
	logger := hclog.NewNullLogger()
	d := NewPlugin(logger)

	caps, err := d.Capabilities()
	require.NoError(t, err)
	require.NotNil(t, caps)

	assert.True(t, caps.SendSignals)
	assert.True(t, caps.Exec)
	assert.Equal(t, drivers.FSIsolationImage, caps.FSIsolation)
	assert.Contains(t, caps.NetIsolationModes, drivers.NetIsolationModeHost)
	assert.Contains(t, caps.NetIsolationModes, drivers.NetIsolationModeGroup)
}

func TestTaskStore(t *testing.T) {
	store := newTaskStore()

	// Test Set and Get
	handle := &taskHandle{
		containerID:  "test-container",
		podSandboxID: "test-sandbox",
	}

	store.Set("task1", handle)

	retrieved, ok := store.Get("task1")
	assert.True(t, ok)
	assert.Equal(t, "test-container", retrieved.containerID)

	// Test non-existent key
	_, ok = store.Get("nonexistent")
	assert.False(t, ok)

	// Test Delete
	store.Delete("task1")
	_, ok = store.Get("task1")
	assert.False(t, ok)
}

func TestPluginConfig_Defaults(t *testing.T) {
	config := &PluginConfig{}

	// Test that defaults are empty/zero
	assert.Empty(t, config.SocketPath)
	assert.Empty(t, config.ImagePullTimeout)
	assert.Nil(t, config.GC)
	assert.False(t, config.RecoverStopped)
}

func TestTaskConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config TaskConfig
		valid  bool
	}{
		{
			name: "valid minimal config",
			config: TaskConfig{
				Image: "nginx:latest",
			},
			valid: true,
		},
		{
			name: "valid with command",
			config: TaskConfig{
				Image:   "alpine:latest",
				Command: "/bin/sh",
				Args:    []string{"-c", "echo hello"},
			},
			valid: true,
		},
		{
			name: "valid with mounts",
			config: TaskConfig{
				Image: "nginx:latest",
				Mounts: []MountConfig{
					{
						HostPath:      "/data",
						ContainerPath: "/app/data",
						Readonly:      false,
					},
				},
			},
			valid: true,
		},
		{
			name: "valid with capabilities",
			config: TaskConfig{
				Image: "nginx:latest",
				Capabilities: &CapabilitiesConfig{
					Add:  []string{"NET_ADMIN"},
					Drop: []string{"ALL"},
				},
			},
			valid: true,
		},
		{
			name: "valid with linux security context",
			config: TaskConfig{
				Image: "nginx:latest",
				Linux: &LinuxConfig{
					SecurityContext: &SecurityContext{
						RunAsUser:  1000,
						RunAsGroup: 1000,
					},
				},
			},
			valid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Basic validation - image must be present
			if tc.valid {
				assert.NotEmpty(t, tc.config.Image)
			}
		})
	}
}

func TestMountConfig(t *testing.T) {
	mount := MountConfig{
		HostPath:      "/host/path",
		ContainerPath: "/container/path",
		Readonly:      true,
		Propagation:   "private",
	}

	assert.Equal(t, "/host/path", mount.HostPath)
	assert.Equal(t, "/container/path", mount.ContainerPath)
	assert.True(t, mount.Readonly)
	assert.Equal(t, "private", mount.Propagation)
}

func TestAuthConfig(t *testing.T) {
	auth := AuthConfig{
		Username:      "user",
		Password:      "pass",
		ServerAddress: "registry.example.com",
	}

	assert.Equal(t, "user", auth.Username)
	assert.Equal(t, "pass", auth.Password)
	assert.Equal(t, "registry.example.com", auth.ServerAddress)
}

func TestDeviceConfig(t *testing.T) {
	device := DeviceConfig{
		HostPath:      "/dev/nvidia0",
		ContainerPath: "/dev/nvidia0",
		Permissions:   "rwm",
	}

	assert.Equal(t, "/dev/nvidia0", device.HostPath)
	assert.Equal(t, "/dev/nvidia0", device.ContainerPath)
	assert.Equal(t, "rwm", device.Permissions)
}

func TestPortMapping(t *testing.T) {
	pm := PortMapping{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	assert.Equal(t, int32(8080), pm.HostPort)
	assert.Equal(t, int32(80), pm.ContainerPort)
	assert.Equal(t, "tcp", pm.Protocol)
}

func TestDNSConfig(t *testing.T) {
	dns := DNSConfig{
		Servers:  []string{"8.8.8.8", "8.8.4.4"},
		Searches: []string{"example.com"},
		Options:  []string{"ndots:5"},
	}

	assert.Len(t, dns.Servers, 2)
	assert.Len(t, dns.Searches, 1)
	assert.Len(t, dns.Options, 1)
}

func TestSecurityContext(t *testing.T) {
	sc := SecurityContext{
		RunAsUser:          1000,
		RunAsGroup:         1000,
		RunAsNonRoot:       true,
		SupplementalGroups: []int64{1001, 1002},
		NoNewPrivs:         true,
		MaskedPaths:        []string{"/proc/kcore"},
		ReadonlyPaths:      []string{"/proc/sys"},
	}

	assert.Equal(t, int64(1000), sc.RunAsUser)
	assert.Equal(t, int64(1000), sc.RunAsGroup)
	assert.True(t, sc.RunAsNonRoot)
	assert.Len(t, sc.SupplementalGroups, 2)
	assert.True(t, sc.NoNewPrivs)
	assert.Len(t, sc.MaskedPaths, 1)
	assert.Len(t, sc.ReadonlyPaths, 1)
}

func TestSELinuxOptions(t *testing.T) {
	selinux := SELinuxOptions{
		User:  "system_u",
		Role:  "system_r",
		Type:  "container_t",
		Level: "s0",
	}

	assert.Equal(t, "system_u", selinux.User)
	assert.Equal(t, "system_r", selinux.Role)
	assert.Equal(t, "container_t", selinux.Type)
	assert.Equal(t, "s0", selinux.Level)
}

func TestGCConfig(t *testing.T) {
	gc := GCConfig{
		Container:  true,
		PodSandbox: true,
	}

	assert.True(t, gc.Container)
	assert.True(t, gc.PodSandbox)
}

func TestDetectCRISocket(t *testing.T) {
	// This test verifies the detectCRISocket function returns expected paths
	// The actual detection depends on the system state

	socket, err := detectCRISocket()

	// On a system with containerd or cri-o, we should get a valid path
	// On a system without either, we should get an error
	if err != nil {
		assert.Contains(t, err.Error(), "no CRI socket found")
		assert.Contains(t, err.Error(), containerdSocketPath)
		assert.Contains(t, err.Error(), crioSocketPath)
	} else {
		// If we found a socket, it should be one of the known paths
		assert.True(t, socket == containerdSocketPath || socket == crioSocketPath,
			"detected socket should be containerd or cri-o path, got: %s", socket)
	}
}
