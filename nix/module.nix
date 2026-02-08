# Copyright (c) Ananth Bhaskararaman
# SPDX-License-Identifier: MPL-2.0

{ config, lib, pkgs, ... }:

let
  cfg = config.services.nomad-driver-cri;
in
{
  options.services.nomad-driver-cri = {
    enable = lib.mkEnableOption "Nomad CRI task driver";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.nomad-driver-cri;
      defaultText = lib.literalExpression "pkgs.nomad-driver-cri";
      description = "The nomad-driver-cri package to use.";
    };

    pluginDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/nomad/plugins";
      description = "Directory where Nomad plugins are installed.";
    };

    socketPath = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to the CRI runtime socket.
        If null, the driver will auto-detect the socket path.
      '';
    };

    imagePullTimeout = lib.mkOption {
      type = lib.types.str;
      default = "5m";
      description = "Timeout for pulling container images.";
    };

    statsInterval = lib.mkOption {
      type = lib.types.str;
      default = "1s";
      description = "Interval for collecting container statistics.";
    };

    gc = {
      container = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Garbage collect stopped containers.";
      };

      podSandbox = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Garbage collect unused pod sandboxes.";
      };
    };

    recoverStopped = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Recover stopped containers on Nomad restart.";
    };

    criServiceUnit = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Systemd unit name of the CRI service that Nomad should depend on.
        Set to null if you don't want Nomad to depend on a specific service.
      '';
      example = "containerd.service";
    };

    configureNomad = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Automatically configure Nomad to use this plugin.";
    };

    extraPluginConfig = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Extra configuration to pass to the CRI plugin.";
      example = lib.literalExpression ''
        {
          allow_privileged = true;
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Ensure the plugin package is available
    environment.systemPackages = [ cfg.package ];

    # Install plugin to plugin directory
    systemd.tmpfiles.rules = [
      "d ${cfg.pluginDir} 0755 root root -"
      "L+ ${cfg.pluginDir}/nomad-driver-cri - - - - ${cfg.package}/bin/nomad-driver-cri"
    ];

    # Configure Nomad to use the plugin
    services.nomad = lib.mkIf cfg.configureNomad {
      enable = true;

      settings = {
        plugin_dir = cfg.pluginDir;

        plugin = [{
          cri = [{
            config = {
              image_pull_timeout = cfg.imagePullTimeout;
              stats_interval = cfg.statsInterval;
              recover_stopped = cfg.recoverStopped;
              gc = {
                container = cfg.gc.container;
                pod_sandbox = cfg.gc.podSandbox;
              };
            } // (lib.optionalAttrs (cfg.socketPath != null) {
              socket_path = cfg.socketPath;
            }) // cfg.extraPluginConfig;
          }];
        }];
      };
    };

    # Ensure Nomad starts after the CRI service
    systemd.services.nomad = lib.mkIf (cfg.configureNomad && cfg.criServiceUnit != null) {
      after = [ cfg.criServiceUnit ];
      requires = [ cfg.criServiceUnit ];
    };
  };
}
