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
  default = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/alpine-virt-3.23.3-aarch64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:69223638286cb1c7728e70e6dee133c501490591804656b5051a2c1fa3eaa51f"
}

variable "agent_binary" {
  type        = string
  description = "Path to izanagi-agent binary (aarch64-unknown-linux-musl)"
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

  output_directory = "output"
  vm_name          = "alpine-aarch64.qcow2"

  disk_size = var.disk_size
  format    = "qcow2"

  qemu_binary     = "qemu-system-aarch64"
  machine_type    = "virt"
  accelerator     = "hvf"
  cpu_model       = "host"
  memory          = var.memory
  cpus            = var.cpus

  qemuargs = [
    ["-bios", "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"],
    ["-device", "virtio-net-pci,netdev=user.0"],
    ["-device", "virtio-gpu-pci"],
    ["-device", "usb-ehci"],
    ["-device", "usb-kbd"],
    ["-device", "usb-tablet"],
    ["-boot", "menu=off"],
  ]

  net_device       = "virtio-net-pci"
  disk_interface   = "virtio"
  boot_wait        = "45s"
  boot_key_interval = "100ms"
  shutdown_command  = "poweroff"

  # aarch64 では -boot once=d が使えないため無効化
  cd_files = []
  communicator     = "ssh"
  ssh_username     = "root"
  ssh_password     = "izanagi"
  ssh_timeout      = "10m"
  ssh_port         = 22
  headless = true

  http_directory = "http"

  boot_command = [
    "root<enter><wait5>",
    "ifconfig eth0 up && udhcpc -i eth0<enter><wait5>",
    "wget -qO /tmp/answers http://{{ .HTTPIP }}:{{ .HTTPPort }}/answers<enter><wait3>",
    "printf 'izanagi\\nizanagi\\nno\\n' | ERASE_DISKS=/dev/vda setup-alpine -f /tmp/answers && mount /dev/vda2 /mnt && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /mnt/etc/ssh/sshd_config && echo 9p >> /mnt/etc/modules && echo 9pnet >> /mnt/etc/modules && echo 9pnet_virtio >> /mnt/etc/modules && umount /mnt && reboot<enter>",
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
      # Node.js/npm (デモ用: npm install の監視)
      "apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/v3.23/community nodejs npm curl",

      # 非特権ユーザーを作成（コマンド実行はこのユーザーで行う）
      "adduser -D -h /home/izanagi -s /bin/sh izanagi",
      "mkdir -p /workspace && chown izanagi:izanagi /workspace",

      "chmod +x /usr/local/bin/izanagi-agent",

      # OpenRC init スクリプト
      "cat > /usr/local/bin/izanagi-agent-wrapper << 'WRAPPER'\n#!/bin/sh\nexport IZANAGI_ALLOW_ALL_COMMANDS=1\nexec /usr/local/bin/izanagi-agent\nWRAPPER",
      "chmod +x /usr/local/bin/izanagi-agent-wrapper",
      "cat > /etc/init.d/izanagi-agent << 'INITEOF'\n#!/sbin/openrc-run\nname=\"izanagi-agent\"\ncommand=\"/usr/local/bin/izanagi-agent-wrapper\"\ncommand_background=true\npidfile=\"/run/izanagi-agent.pid\"\noutput_log=\"/var/log/izanagi-agent.log\"\nerror_log=\"/var/log/izanagi-agent.log\"\nINITEOF",
      "chmod +x /etc/init.d/izanagi-agent",
      "rc-update add izanagi-agent default",

      # クリーンアップ
      "rm -f /var/cache/apk/*",
    ]
  }
}
