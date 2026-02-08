// Copyright (c) Ananth Bhaskararaman
// SPDX-License-Identifier: MPL-2.0

package driver

import (
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
)

var (
	// pluginConfigSpec is the hcl specification for the driver plugin config
	pluginConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"socket_path": hclspec.NewDefault(
			hclspec.NewAttr("socket_path", "string", false),
			hclspec.NewLiteral(`"/run/containerd/containerd.sock"`),
		),
		"image_pull_timeout": hclspec.NewDefault(
			hclspec.NewAttr("image_pull_timeout", "string", false),
			hclspec.NewLiteral(`"5m"`),
		),
		"stats_interval": hclspec.NewDefault(
			hclspec.NewAttr("stats_interval", "string", false),
			hclspec.NewLiteral(`"1s"`),
		),
		"gc": hclspec.NewBlock("gc", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"container": hclspec.NewDefault(
				hclspec.NewAttr("container", "bool", false),
				hclspec.NewLiteral("true"),
			),
			"pod_sandbox": hclspec.NewDefault(
				hclspec.NewAttr("pod_sandbox", "bool", false),
				hclspec.NewLiteral("true"),
			),
		})),
		"recover_stopped": hclspec.NewDefault(
			hclspec.NewAttr("recover_stopped", "bool", false),
			hclspec.NewLiteral("false"),
		),
	})

	// taskConfigSpec is the hcl specification for the task config
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":       hclspec.NewAttr("image", "string", true),
		"command":     hclspec.NewAttr("command", "string", false),
		"args":        hclspec.NewAttr("args", "list(string)", false),
		"working_dir": hclspec.NewAttr("working_dir", "string", false),
		"hostname":    hclspec.NewAttr("hostname", "string", false),

		// Authentication for private registries
		"auth": hclspec.NewBlock("auth", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"username":       hclspec.NewAttr("username", "string", false),
			"password":       hclspec.NewAttr("password", "string", false),
			"auth":           hclspec.NewAttr("auth", "string", false),
			"server_address": hclspec.NewAttr("server_address", "string", false),
			"identity_token": hclspec.NewAttr("identity_token", "string", false),
			"registry_token": hclspec.NewAttr("registry_token", "string", false),
		})),

		// Volume mounts
		"mounts": hclspec.NewBlockList("mounts", hclspec.NewObject(map[string]*hclspec.Spec{
			"host_path":      hclspec.NewAttr("host_path", "string", true),
			"container_path": hclspec.NewAttr("container_path", "string", true),
			"readonly":       hclspec.NewDefault(hclspec.NewAttr("readonly", "bool", false), hclspec.NewLiteral("false")),
			"propagation":    hclspec.NewAttr("propagation", "string", false),
		})),

		// Environment variables (in addition to Nomad's env stanza)
		"extra_env": hclspec.NewAttr("extra_env", "map(string)", false),

		// Security settings
		"privileged":      hclspec.NewDefault(hclspec.NewAttr("privileged", "bool", false), hclspec.NewLiteral("false")),
		"readonly_rootfs": hclspec.NewDefault(hclspec.NewAttr("readonly_rootfs", "bool", false), hclspec.NewLiteral("false")),

		"capabilities": hclspec.NewBlock("capabilities", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"add":  hclspec.NewAttr("add", "list(string)", false),
			"drop": hclspec.NewAttr("drop", "list(string)", false),
		})),

		// Linux-specific settings
		"linux": hclspec.NewBlock("linux", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"security_context": hclspec.NewBlock("security_context", false, hclspec.NewObject(map[string]*hclspec.Spec{
				"run_as_user":         hclspec.NewAttr("run_as_user", "number", false),
				"run_as_group":        hclspec.NewAttr("run_as_group", "number", false),
				"run_as_non_root":     hclspec.NewDefault(hclspec.NewAttr("run_as_non_root", "bool", false), hclspec.NewLiteral("false")),
				"supplemental_groups": hclspec.NewAttr("supplemental_groups", "list(number)", false),
				"selinux_options": hclspec.NewBlock("selinux_options", false, hclspec.NewObject(map[string]*hclspec.Spec{
					"user":  hclspec.NewAttr("user", "string", false),
					"role":  hclspec.NewAttr("role", "string", false),
					"type":  hclspec.NewAttr("type", "string", false),
					"level": hclspec.NewAttr("level", "string", false),
				})),
				"seccomp_profile_path": hclspec.NewAttr("seccomp_profile_path", "string", false),
				"apparmor_profile":     hclspec.NewAttr("apparmor_profile", "string", false),
				"no_new_privs":         hclspec.NewDefault(hclspec.NewAttr("no_new_privs", "bool", false), hclspec.NewLiteral("false")),
				"masked_paths":         hclspec.NewAttr("masked_paths", "list(string)", false),
				"readonly_paths":       hclspec.NewAttr("readonly_paths", "list(string)", false),
			})),
		})),

		// Network mode
		"network_mode": hclspec.NewDefault(
			hclspec.NewAttr("network_mode", "string", false),
			hclspec.NewLiteral(`""`),
		),

		// DNS configuration
		"dns": hclspec.NewBlock("dns", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"servers":  hclspec.NewAttr("servers", "list(string)", false),
			"searches": hclspec.NewAttr("searches", "list(string)", false),
			"options":  hclspec.NewAttr("options", "list(string)", false),
		})),

		// Labels and annotations
		"labels":      hclspec.NewAttr("labels", "map(string)", false),
		"annotations": hclspec.NewAttr("annotations", "map(string)", false),

		// Port mappings (for host network mode)
		"port_mappings": hclspec.NewBlockList("port_mappings", hclspec.NewObject(map[string]*hclspec.Spec{
			"host_port":      hclspec.NewAttr("host_port", "number", true),
			"container_port": hclspec.NewAttr("container_port", "number", true),
			"protocol":       hclspec.NewDefault(hclspec.NewAttr("protocol", "string", false), hclspec.NewLiteral(`"tcp"`)),
		})),

		// Logging configuration
		"log_driver":  hclspec.NewAttr("log_driver", "string", false),
		"log_options": hclspec.NewAttr("log_options", "map(string)", false),

		// Devices
		"devices": hclspec.NewBlockList("devices", hclspec.NewObject(map[string]*hclspec.Spec{
			"host_path":      hclspec.NewAttr("host_path", "string", true),
			"container_path": hclspec.NewAttr("container_path", "string", true),
			"permissions":    hclspec.NewDefault(hclspec.NewAttr("permissions", "string", false), hclspec.NewLiteral(`"rwm"`)),
		})),
	})
)

// PluginConfig contains plugin-level configuration
type PluginConfig struct {
	SocketPath       string    `codec:"socket_path"`
	ImagePullTimeout string    `codec:"image_pull_timeout"`
	StatsInterval    string    `codec:"stats_interval"`
	GC               *GCConfig `codec:"gc"`
	RecoverStopped   bool      `codec:"recover_stopped"`
}

// GCConfig contains garbage collection settings
type GCConfig struct {
	Container  bool `codec:"container"`
	PodSandbox bool `codec:"pod_sandbox"`
}

// TaskConfig contains task-level configuration
type TaskConfig struct {
	Image      string   `codec:"image"`
	Command    string   `codec:"command"`
	Args       []string `codec:"args"`
	WorkingDir string   `codec:"working_dir"`
	Hostname   string   `codec:"hostname"`

	// Authentication
	Auth *AuthConfig `codec:"auth"`

	// Volume mounts
	Mounts []MountConfig `codec:"mounts"`

	// Extra environment variables
	ExtraEnv map[string]string `codec:"extra_env"`

	// Security
	Privileged     bool                `codec:"privileged"`
	ReadonlyRootfs bool                `codec:"readonly_rootfs"`
	Capabilities   *CapabilitiesConfig `codec:"capabilities"`

	// Linux-specific
	Linux *LinuxConfig `codec:"linux"`

	// Network
	NetworkMode string `codec:"network_mode"`

	// DNS
	DNS *DNSConfig `codec:"dns"`

	// Labels and annotations
	Labels      map[string]string `codec:"labels"`
	Annotations map[string]string `codec:"annotations"`

	// Port mappings
	PortMappings []PortMapping `codec:"port_mappings"`

	// Logging
	LogDriver  string            `codec:"log_driver"`
	LogOptions map[string]string `codec:"log_options"`

	// Devices
	Devices []DeviceConfig `codec:"devices"`
}

// AuthConfig contains authentication for private registries
type AuthConfig struct {
	Username      string `codec:"username"`
	Password      string `codec:"password"`
	Auth          string `codec:"auth"`
	ServerAddress string `codec:"server_address"`
	IdentityToken string `codec:"identity_token"`
	RegistryToken string `codec:"registry_token"`
}

// MountConfig contains volume mount configuration
type MountConfig struct {
	HostPath      string `codec:"host_path"`
	ContainerPath string `codec:"container_path"`
	Readonly      bool   `codec:"readonly"`
	Propagation   string `codec:"propagation"`
}

// CapabilitiesConfig contains Linux capabilities configuration
type CapabilitiesConfig struct {
	Add  []string `codec:"add"`
	Drop []string `codec:"drop"`
}

// LinuxConfig contains Linux-specific configuration
type LinuxConfig struct {
	SecurityContext *SecurityContext `codec:"security_context"`
}

// SecurityContext contains security settings
type SecurityContext struct {
	RunAsUser          int64           `codec:"run_as_user"`
	RunAsGroup         int64           `codec:"run_as_group"`
	RunAsNonRoot       bool            `codec:"run_as_non_root"`
	SupplementalGroups []int64         `codec:"supplemental_groups"`
	SELinuxOptions     *SELinuxOptions `codec:"selinux_options"`
	SeccompProfilePath string          `codec:"seccomp_profile_path"`
	AppArmorProfile    string          `codec:"apparmor_profile"`
	NoNewPrivs         bool            `codec:"no_new_privs"`
	MaskedPaths        []string        `codec:"masked_paths"`
	ReadonlyPaths      []string        `codec:"readonly_paths"`
}

// SELinuxOptions contains SELinux configuration
type SELinuxOptions struct {
	User  string `codec:"user"`
	Role  string `codec:"role"`
	Type  string `codec:"type"`
	Level string `codec:"level"`
}

// DNSConfig contains DNS configuration
type DNSConfig struct {
	Servers  []string `codec:"servers"`
	Searches []string `codec:"searches"`
	Options  []string `codec:"options"`
}

// PortMapping contains port mapping configuration
type PortMapping struct {
	HostPort      int32  `codec:"host_port"`
	ContainerPort int32  `codec:"container_port"`
	Protocol      string `codec:"protocol"`
}

// DeviceConfig contains device configuration
type DeviceConfig struct {
	HostPath      string `codec:"host_path"`
	ContainerPath string `codec:"container_path"`
	Permissions   string `codec:"permissions"`
}
