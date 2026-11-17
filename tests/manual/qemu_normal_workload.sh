#!/bin/sh
# Measure guest eBPF/NIC tuple agreement for a real npm install/build/test run.
set -eu
umask 077

run=$(mktemp -d "${1:?artifact parent required}/qemu-normal.XXXXXX")
collector=${2:?collector binary required}
object=${3:?eBPF object required}
node_archive=${4:?verified Node.js linux-x64 archive required}
mkdir -p "$run/root/bin" "$run/root/dev" "$run/root/etc/ssl/certs" \
    "$run/root/opt/node" "$run/root/proc" "$run/root/sys" "$run/root/tmp" \
    "$run/root/usr/bin" "$run/root/workspace"
cp "$(command -v busybox)" "$run/root/bin/busybox"
cp "$collector" "$run/root/bin/collector"
cp "$object" "$run/root/collector.o"
cp /etc/ssl/certs/ca-certificates.crt "$run/root/etc/ssl/certs/"
tar -xJf "$node_archive" --strip-components=1 -C "$run/root/opt/node"
ln -s /bin/busybox "$run/root/usr/bin/env"
ldd "$collector" "$run/root/opt/node/bin/node" |
    awk '/=> \// {print $3} $1 ~ /^\// && $2 ~ /^\(/ {print $1}' | sort -u |
    while IFS= read -r library; do cp --parents "$library" "$run/root"; done
printf '%s\n' '{"private":true,"scripts":{"build":"node -e '\''require(\"is-number\"); console.log(\"build ok\")'\''","test":"node -e '\''if (!require(\"is-number\")(42)) process.exit(1); console.log(\"test ok\")'\''"},"dependencies":{"is-number":"7.0.0"}}' > "$run/root/workspace/package.json"

cat > "$run/root/init" <<'INIT'
#!/bin/busybox sh
set -eu
/bin/busybox --install -s /bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tracefs tracefs /sys/kernel/tracing
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
export PATH=/opt/node/bin:/bin:/usr/bin
export HOME=/tmp
/bin/collector /collector.o /events.jsonl /stop > /collector.log &
collector=$!
for attempt in 1 2 3 4 5; do
    grep -q '^READY$' /collector.log && break
    sleep 1
done
grep -q '^READY$' /collector.log
cd /workspace
/opt/node/bin/node /opt/node/lib/node_modules/npm/bin/npm-cli.js install \
    --cache /tmp/npm-cache --no-audit --no-fund --prefer-online
/opt/node/bin/node /opt/node/lib/node_modules/npm/bin/npm-cli.js run build
/opt/node/bin/node /opt/node/lib/node_modules/npm/bin/npm-cli.js test
sleep 1
touch /stop
wait "$collector"
cat /events.jsonl
echo WITNESS_NORMAL_WORKLOAD_OK
poweroff -f
INIT
chmod +x "$run/root/init"
(cd "$run/root" && find . | cpio --quiet -o -H newc) > "$run/initramfs"
sudo cat "/boot/vmlinuz-$(uname -r)" > "$run/kernel"
timeout 120 qemu-system-x86_64 -machine q35 -m 1024 -display none -nodefaults \
    -serial stdio -no-reboot -kernel "$run/kernel" -initrd "$run/initramfs" \
    -append 'console=ttyS0 rdinit=/init quiet' \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -object "filter-dump,id=witness,netdev=net0,file=$run/guest-nic.pcap,maxlen=256" \
    > "$run/console.log" 2>&1 || { tail -n 50 "$run/console.log"; exit 1; }
grep -F WITNESS_NORMAL_WORKLOAD_OK "$run/console.log"
tr -d '\r' < "$run/console.log" | sed -n '/^{"schema_version":/p' > "$run/events.jsonl"
tcpdump -nn -r "$run/guest-nic.pcap" 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' \
    > "$run/syn.txt"
awk '$2 == "IP" && $3 ~ /^10\.0\.2\.15\./ {
    source = $3; destination = $5; sub(/:$/, "", destination)
    sub(/^10\.0\.2\.15\./, "10.0.2.15:", source)
    count = split(destination, parts, "."); port = parts[count]
    destination = substr(destination, 1, length(destination) - length(port) - 1) ":" port
    print source "\t" destination
}' "$run/syn.txt" | sort -u > "$run/nic-tuples.tsv"
jq -r '.payload.SocketConnect? | select(.) | [.tuple.client, .tuple.local] | @tsv' \
    "$run/events.jsonl" | sort -u > "$run/guest-tuples.tsv"
comm -23 "$run/nic-tuples.tsv" "$run/guest-tuples.tsv" > "$run/nic-only.tsv"
comm -13 "$run/nic-tuples.tsv" "$run/guest-tuples.tsv" > "$run/guest-only.tsv"
jq -n \
    --argjson nic "$(wc -l < "$run/nic-tuples.tsv")" \
    --argjson guest "$(wc -l < "$run/guest-tuples.tsv")" \
    --argjson nic_only "$(wc -l < "$run/nic-only.tsv")" \
    --argjson guest_only "$(wc -l < "$run/guest-only.tsv")" \
    --argjson gaps "$(jq -s '[.[].payload | objects | select(has("ObservationGap"))] | length' "$run/events.jsonl")" \
    '{nic_tcp_flows:$nic, guest_connects:$guest, nic_only:$nic_only, guest_only:$guest_only, gaps:$gaps}' \
    > "$run/result.json"
cat "$run/result.json"
printf '%s\n' "$run"
