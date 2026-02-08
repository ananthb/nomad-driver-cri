# Example flake.nix showing how to use nomad-driver-cri in your NixOS configuration
#
# Save this as flake.nix in your NixOS configuration directory

{
  description = "My NixOS configuration with Nomad CRI driver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Add the nomad-driver-cri flake
    nomad-driver-cri = {
      url = "github:anthonyrisinger/nomad-driver-cri";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nomad-driver-cri }: {
    nixosConfigurations = {
      # Replace 'myhost' with your hostname
      myhost = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          # Import the CRI driver module
          nomad-driver-cri.nixosModules.default

          # Your hardware configuration
          # ./hardware-configuration.nix

          # Inline configuration
          ({ config, pkgs, ... }: {
            # Basic system configuration
            networking.hostName = "myhost";
            system.stateVersion = "24.05";

            # Enable the CRI driver
            services.nomad-driver-cri = {
              enable = true;

              # Use containerd as the CRI runtime (default)
              enableContainerd = true;

              # Automatically configure Nomad (default)
              configureNomad = true;

              # Custom settings
              socketPath = "/run/containerd/containerd.sock";
              imagePullTimeout = "5m";
            };

            # Additional Nomad configuration
            services.nomad.settings = {
              datacenter = "dc1";

              server = {
                enabled = true;
                bootstrap_expect = 1;
              };

              client = {
                enabled = true;
              };
            };
          })
        ];
      };
    };
  };
}
