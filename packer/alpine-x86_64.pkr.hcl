packer {
  required_plugins {
    qemu = {
      version = "~> 1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "alpine_version" {
  type    = string
  default = "3.23.3"
}

variable "iso_url" {
  type    = string
  default = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-virt-3.23.3-x86_64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:366285bfa4d25429e0a9d1c5cbe3c2e35e84e1ad5e0620e8b5a20b5e39e7e02b"
}

variable "agent_binary" {
  type        = string
  description = "Path to izanagi-agent binary (x86_64-unknown-linux-musl)"
}

variable "disk_size" {
  type    = string
  default = "2G"
}

variable "memory" {
  type    = number
  default = 2048
}

variable "cpus" {
  type    = number
  default = 2
}

source "qemu" "alpine" {
  iso_url      = var.iso_url
  iso_checksum = var.iso_checksum

  output_directory = "output-x86_64"
  vm_name          = "alpine-x86_64.qcow2"

  disk_size      = var.disk_size
  format         = "qcow2"
  accelerator    = "kvm"
  cpu_model      = "host"
  memory         = var.memory
  cpus           = var.cpus
  net_device     = "virtio-net"
  disk_interface = "virtio"

  headless         = true
  use_default_display = false
  boot_wait        = "10s"
  boot_key_interval = "50ms"
  shutdown_command = "poweroff"

  communicator = "ssh"
  ssh_username = "root"
  ssh_password = "izanagi"
  ssh_timeout  = "10m"

  http_directory = "http"

  boot_command = [
    "root<enter><wait5>",
    "ifconfig eth0 up && udhcpc -i eth0<enter><wait5>",
    "wget -qO /tmp/answers http://{{ .HTTPIP }}:{{ .HTTPPort }}/answers<enter><wait3>",
    "wget -qO /tmp/setup.sh http://{{ .HTTPIP }}:{{ .HTTPPort }}/setup.sh<enter><wait3>",
    "sh /tmp/setup.sh<enter><wait60>",
  ]
}

build {
  sources = ["source.qemu.alpine"]

  # izanagi-agent をコピー
  provisioner "file" {
    source      = var.agent_binary
    destination = "/usr/local/bin/izanagi-agent"
  }

  # agent のセットアップ
  provisioner "shell" {
    inline = [
      "chmod +x /usr/local/bin/izanagi-agent",

      # OpenRC init スクリプト
      "cat > /etc/init.d/izanagi-agent << 'INITEOF'",
      "#!/sbin/openrc-run",
      "name=\"izanagi-agent\"",
      "command=\"/usr/local/bin/izanagi-agent\"",
      "command_background=true",
      "pidfile=\"/run/izanagi-agent.pid\"",
      "output_log=\"/var/log/izanagi-agent.log\"",
      "error_log=\"/var/log/izanagi-agent.log\"",
      "INITEOF",
      "chmod +x /etc/init.d/izanagi-agent",
      "rc-update add izanagi-agent default",

      # クリーンアップ
      "rm -f /var/cache/apk/*",
    ]
  }
}
