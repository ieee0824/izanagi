#!/bin/sh
set -e

# setup-alpine を answer file で実行
# パスワード入力 (2回) と "Setup a user?" (no) を自動回答
printf 'izanagi\nizanagi\nno\n' | ERASE_DISKS=/dev/vda setup-alpine -f /tmp/answers

# setup-alpine 完了後にディスクをマウントして設定を変更
# (setup-alpine がアンマウントした後なので再マウントが必要)
mount /dev/vda3 /mnt

# SSH の root ログインを許可
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /mnt/etc/ssh/sshd_config
# sed で置換できなかった場合に備えて追記もする
grep -q '^PermitRootLogin yes' /mnt/etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /mnt/etc/ssh/sshd_config

# 9p カーネルモジュールを有効化（virtio-9p ファイル共有用）
echo "9p" >> /mnt/etc/modules
echo "9pnet" >> /mnt/etc/modules
echo "9pnet_virtio" >> /mnt/etc/modules

# 9p ファイル共有の自動マウント（nofail: 9p デバイスがなくても起動する）
mkdir -p /mnt/workspace
echo "workspace /workspace 9p trans=virtio,version=9p2000.L,nofail 0 0" >> /mnt/etc/fstab

sync
umount /mnt

reboot
