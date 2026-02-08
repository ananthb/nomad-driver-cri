// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package cri

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := NewClient(logger)

	require.NotNil(t, client)
	assert.NotNil(t, client.logger)
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected string
		wantErr  bool
	}{
		{
			name:     "unix socket with scheme",
			endpoint: "unix:///run/containerd/containerd.sock",
			expected: "/run/containerd/containerd.sock",
			wantErr:  false,
		},
		{
			name:     "plain path",
			endpoint: "/run/containerd/containerd.sock",
			expected: "/run/containerd/containerd.sock",
			wantErr:  false,
		},
		{
			name:     "cri-o socket",
			endpoint: "/run/crio/crio.sock",
			expected: "/run/crio/crio.sock",
			wantErr:  false,
		},
		{
			name:     "unix scheme without slashes",
			endpoint: "unix:/var/run/containerd.sock",
			expected: "/var/run/containerd.sock",
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseEndpoint(tc.endpoint)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestClient_Close_NoConnection(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := NewClient(logger)

	// Should not panic when closing without connection
	err := client.Close()
	assert.NoError(t, err)
}

func TestDefaultTimeout(t *testing.T) {
	assert.Equal(t, int64(2*60*1e9), DefaultTimeout.Nanoseconds())
}

func TestDefaultConnectionTimeout(t *testing.T) {
	assert.Equal(t, int64(30*1e9), DefaultConnectionTimeout.Nanoseconds())
}
