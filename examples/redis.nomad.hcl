# Example Redis job using the CRI driver
#
# Deploy with:
#   nomad job run examples/redis.nomad.hcl
#
# Verify:
#   nomad job status redis
#   nomad alloc logs <alloc-id>
#   nomad alloc exec <alloc-id> redis-cli ping

job "redis" {
  datacenters = ["dc1"]
  type        = "service"

  group "cache" {
    count = 1

    network {
      port "redis" {
        static = 6379
      }
    }

    task "redis" {
      driver = "cri"

      config {
        image = "docker.io/library/redis:7-alpine"

        # Port mappings
        port_mappings {
          host_port      = 6379
          container_port = 6379
          protocol       = "tcp"
        }

        # Volume mount for data persistence
        mounts {
          host_path      = "/opt/redis/data"
          container_path = "/data"
          readonly       = false
        }

        # Security settings
        readonly_rootfs = false
        privileged      = false

        capabilities {
          drop = ["ALL"]
          add  = ["SETGID", "SETUID"]
        }

        # Run as non-root
        linux {
          security_context {
            run_as_user  = 999
            run_as_group = 999
          }
        }

        # Labels
        labels = {
          "app"         = "redis"
          "environment" = "development"
        }
      }

      resources {
        cpu    = 500
        memory = 256
      }

      service {
        name = "redis"
        port = "redis"

        check {
          type     = "tcp"
          port     = "redis"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
