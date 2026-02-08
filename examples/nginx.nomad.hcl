# Example nginx job using the CRI driver
#
# Deploy with:
#   nomad job run examples/nginx.nomad.hcl
#
# Test with:
#   curl http://localhost:8080

job "nginx" {
  datacenters = ["dc1"]
  type        = "service"

  group "web" {
    count = 1

    network {
      port "http" {
        static = 8080
      }
    }

    task "nginx" {
      driver = "cri"

      config {
        image = "docker.io/library/nginx:alpine"

        port_mappings {
          host_port      = 8080
          container_port = 80
          protocol       = "tcp"
        }
      }

      resources {
        cpu    = 200
        memory = 128
      }

      service {
        name = "nginx"
        port = "http"

        check {
          type     = "http"
          path     = "/"
          port     = "http"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
