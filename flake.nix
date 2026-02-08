{
  description = "Nomad CRI Task Driver - works with any CRI-compliant container runtime";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # Version from git or fallback
        version = self.shortRev or self.dirtyShortRev or "dev";

        # Source filtering to exclude unnecessary files
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              name = baseNameOf path;
            in
            !(name == "plugins" || name == "result" || name == ".git" ||
              name == "coverage.out" || name == "coverage.html");
        };

        # Build the Go binary
        nomad-driver-cri = pkgs.buildGoModule {
          pname = "nomad-driver-cri";
          inherit version src;

          vendorHash = "sha256-sxBiZuxgGI+iCO4ojW9Wa+v2Obi8irVk6+TMBi3NDQ0=";

          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
          ];

          # Run unit tests (not integration tests)
          doCheck = true;
          checkFlags = [ "-v" ];

          # Skip integration tests that require CRI runtime
          preCheck = ''
            export HOME=$TMPDIR
          '';

          meta = with pkgs.lib; {
            description = "Nomad task driver for CRI-compliant container runtimes";
            homepage = "https://github.com/ananthb/nomad-driver-cri";
            license = licenses.mpl20;
            maintainers = [ ];
            platforms = platforms.linux;
          };
        };

        # Build with tests explicitly run
        nomad-driver-cri-tested = nomad-driver-cri.overrideAttrs (old: {
          doCheck = true;
        });
      in
      {
        # Packages
        packages = {
          default = nomad-driver-cri;
          inherit nomad-driver-cri;
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          name = "nomad-driver-cri-dev";

          buildInputs = with pkgs; [
            # Go toolchain
            go
            gopls
            golangci-lint
            delve

            # Nomad for testing
            nomad

            # Container runtime for testing
            containerd
            runc # OCI runtime
            cri-tools # crictl
            cni-plugins # CNI networking plugins

            # Utilities
            jq
            yq-go
          ];

          shellHook = ''
            echo "Nomad CRI Driver Development Environment"
            echo ""
            echo "Nix commands:"
            echo "  nix build                    - Build the plugin"
            echo "  nix flake check              - Run all checks (build, fmt, unit tests)"
            echo "  nix develop                  - Enter dev shell"
            echo ""
            echo "Go commands:"
            echo "  go build -o plugins/nomad-driver-cri .   - Build locally"
            echo "  go test -v ./cri/... ./driver/...        - Run unit tests"
            echo "  go test -v -tags=integration ./...       - Run integration tests (requires containerd)"
            echo "  go fmt ./...                             - Format code"
            echo "  go vet ./...                             - Run vet"
            echo "  golangci-lint run ./...                  - Run linter"
            echo ""
            echo "Integration testing (requires running containerd):"
            echo "  sudo containerd &"
            echo "  go test -v -tags=integration ./integration/..."
            echo ""
            echo "Go version: $(go version)"
          '';

          CGO_ENABLED = "0";
          GOFLAGS = "-trimpath";
        };

        # Checks for CI (Garnix will run these)
        checks = {
          # Build check with unit tests
          build = nomad-driver-cri;

          # Format check
          fmt = pkgs.runCommandLocal "check-fmt" {
            inherit src;
            nativeBuildInputs = [ pkgs.go ];
          } ''
            export HOME=$TMPDIR
            cd $src
            unformatted=$(gofmt -l .)
            if [ -n "$unformatted" ]; then
              echo "Unformatted files:"
              echo "$unformatted"
              echo ""
              echo "Run 'go fmt ./...' to fix"
              exit 1
            fi
            touch $out
          '';
        };

        # Apps
        apps.default = flake-utils.lib.mkApp {
          drv = nomad-driver-cri;
        };
      }
    ) // {
      # Overlays
      overlays.default = final: prev: {
        nomad-driver-cri = self.packages.${prev.system}.nomad-driver-cri;
      };

      # NixOS module
      nixosModules.default = { config, lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];

        # Set the default package from this flake
        services.nomad-driver-cri.package = lib.mkDefault self.packages.${pkgs.system}.nomad-driver-cri;
      };
    };
}
