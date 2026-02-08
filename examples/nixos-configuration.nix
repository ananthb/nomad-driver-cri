# Example NixOS configuration for nomad-driver-cri
#
# Usage in your flake.nix:
#
# {
#   inputs = {
#     nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
#     nomad-driver-cri.url = "github:anthonyrisinger/nomad-driver-cri";
#   };
#
#   outputs = { self, nixpkgs, nomad-driver-cri }: {
#     nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
#       system = "x86_64-linux";
#       modules = [
#         nomad-driver-cri.nixosModules.default
#         ./configuration.nix
#       ];
#     };
#   };
# }

{ config, pkgs, lib, ... }:

{
  # Enable the CRI driver with default settings
  # This will:
  # - Install the plugin to /var/lib/nomad/plugins
  # - Enable and configure containerd
  # - Configure Nomad to use the CRI plugin
  services.nomad-driver-cri = {
    enable = true;

    # Optional: customize settings
    # socketPath = "/run/containerd/containerd.sock";
    # imagePullTimeout = "10m";
    # statsInterval = "2s";

    # Garbage collection settings
    # gc = {
    #   container = true;
    #   podSandbox = true;
    # };

    # Whether to recover stopped containers on Nomad restart
    # recoverStopped = false;

    # Extra plugin configuration
    # extraPluginConfig = {
    #   allow_privileged = true;
    # };
  };

  # Configure Nomad as a server (for single-node setup)
  services.nomad.settings = {
    server = {
      enabled = true;
      bootstrap_expect = 1;
    };

    client = {
      enabled = true;
    };
  };

  # Open firewall for Nomad (optional)
  networking.firewall.allowedTCPPorts = [
    4646  # Nomad HTTP API
    4647  # Nomad RPC
    4648  # Nomad Serf WAN
  ];
}
