#!/bin/sh
# Run on the dedicated Linux QEMU host with passwordless sudo for the kernel copy.
set -eu
umask 077
run=$(mktemp -d "${1:?artifact parent required}/qemu-http.XXXXXX")
collector=${2:?collector binary required}
object=${3:?eBPF object required}
dns_proxy=${4:-}
port=19836
mkdir -p "$run/root/bin" "$run/root/dev" "$run/root/proc" "$run/root/sys" "$run/www"
cp "$(command -v busybox)" "$run/root/bin/busybox"
cp "$collector" "$run/root/bin/collector"
cp "$object" "$run/root/collector.o"
fw_cfg_module=$(modinfo -n qemu_fw_cfg)
case "$fw_cfg_module" in
    *.zst) zstd -q -d -f "$fw_cfg_module" -o "$run/root/qemu_fw_cfg.ko" ;;
    *) cp "$fw_cfg_module" "$run/root/qemu_fw_cfg.ko" ;;
esac
ldd "$collector" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' |
    while IFS= read -r library; do cp --parents "$library" "$run/root"; done
sudo cat "/boot/vmlinuz-$(uname -r)" > "$run/kernel"
printf 'izanagi witness baseline\n' > "$run/www/witness.txt"
head -c 32 /dev/urandom > "$run/fw-cfg-secret"
cat > "$run/root/init" <<'INIT'
#!/bin/busybox sh
set -eu
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t tracefs tracefs /sys/kernel/tracing
/bin/busybox insmod /qemu_fw_cfg.ko
fw_cfg_path=/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.secret/raw
test -r "$fw_cfg_path"
test "$(/bin/busybox wc -c < "$fw_cfg_path")" -gt 0
echo WITNESS_FW_CFG_ROOT_READABLE
/bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
/bin/collector /collector.o /events.jsonl /stop > /collector.log &
collector=$!
for attempt in 1 2 3 4 5; do
    /bin/busybox grep -q '^READY$' /collector.log && break
    /bin/busybox sleep 1
done
/bin/busybox grep -q '^READY$' /collector.log
pids=
for request in 1 2 3 4; do
    /bin/busybox wget -T 5 -O "/body-$request" "http://10.0.2.2:19836/witness.txt?run=$request" &
    pids="$pids $!"
done
for pid in $pids; do wait "$pid"; done
if [ -f /check-dns ]; then
    /bin/busybox timeout 5 /bin/busybox nslookup witness.invalid 10.0.2.2:15353
    echo WITNESS_DNS_OK
fi
/bin/busybox sleep 1
/bin/busybox touch /stop
wait "$collector"
/bin/busybox wget -T 5 -O /body-stopped \
    "http://10.0.2.2:19836/witness.txt?run=stopped&fixture=izanagi-dummy-136"
echo WITNESS_AFTER_COLLECTOR_STOP_OK
/bin/busybox cat /events.jsonl
echo WITNESS_HTTP_OK
/bin/busybox poweroff -f
INIT
chmod +x "$run/root/init"
if [ -n "$dns_proxy" ]; then
    touch "$run/root/check-dns"
    printf '[sandbox]\nbackend="native"\ntracer="none"\n[share]\npaths=[]\nmount_point="/workspace"\n[monitor]\nsyscalls=[]\n[detect]\nsuspicious_paths=[]\nallowed_hosts=["allowed.example"]\n' > "$run/dns.toml"
    "$dns_proxy" --config "$run/dns.toml" --listen 127.0.0.1:15353 \
        --upstream 127.0.0.1:9 > "$run/dns.log" 2>&1 &
    dns_pid=$!
fi
(cd "$run/root" && find . | cpio --quiet -o -H newc) > "$run/initramfs"
python3 -u -m http.server "$port" --bind 127.0.0.1 --directory "$run/www" > "$run/http.log" 2>&1 &
receiver=$!
trap 'rm -f "$run/fw-cfg-secret"; for pid in "$receiver" ${dns_pid:-}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done' EXIT
sleep 1
kill -0 "$receiver"
if [ -n "$dns_proxy" ]; then kill -0 "$dns_pid"; fi
timeout 35 qemu-system-x86_64 -machine q35 -m 512 -display none -nodefaults \
    -serial stdio -no-reboot -kernel "$run/kernel" -initrd "$run/initramfs" \
    -append 'console=ttyS0 rdinit=/init quiet' \
    -fw_cfg "name=opt/izanagi.secret,file=$run/fw-cfg-secret" \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -object "filter-dump,id=witness,netdev=net0,file=$run/guest-nic.pcap,maxlen=256" \
    > "$run/console.log" 2>&1 || { tail -n 30 "$run/console.log"; exit 1; }
grep -F WITNESS_HTTP_OK "$run/console.log"
grep -F WITNESS_FW_CFG_ROOT_READABLE "$run/console.log"
grep -F WITNESS_AFTER_COLLECTOR_STOP_OK "$run/console.log"
if [ -n "$dns_proxy" ]; then
    grep -F WITNESS_DNS_OK "$run/console.log"
    grep -F '[BLOCKED] witness.invalid from' "$run/dns.log"
    tcpdump -ttnn -r "$run/guest-nic.pcap" 'udp port 15353' > "$run/dns-packets.txt"
    test -s "$run/dns-packets.txt"
fi
tcpdump -nn -r "$run/guest-nic.pcap" "tcp port $port" > "$run/tcp.txt"
tcpdump -nnA -r "$run/guest-nic.pcap" "tcp dst port $port" > "$run/requests.txt"
awk '
    $2 == "IP" { client = $3 }
    match($0, /GET \/witness\.txt\?run=[1-4] HTTP\//) {
        split(client, addr, ".")
        id = substr($0, RSTART + 21, 1)
        print id, addr[1]"."addr[2]"."addr[3]"."addr[4]":"addr[5]
    }
' "$run/requests.txt" | sort -u > "$run/request-matches.txt"
for request in 1 2 3 4; do
    test "$(grep -c "^$request " "$run/request-matches.txt")" -eq 1
    test "$(grep -Fc "\"GET /witness.txt?run=$request HTTP/1.1\" 200 " "$run/http.log")" -eq 1
done
test "$(grep -Fc '"GET /witness.txt?run=stopped&fixture=izanagi-dummy-136 HTTP/1.1" 200 ' "$run/http.log")" -eq 1
tcpdump -nnA -r "$run/guest-nic.pcap" "tcp dst port $port" |
    grep -F 'GET /witness.txt?run=stopped&fixture=izanagi-dummy-136 HTTP/' \
    > "$run/after-collector-stop.txt"
test -s "$run/after-collector-stop.txt"
test -s "$run/tcp.txt"
tr -d '\r' < "$run/console.log" | sed -n '/^{"schema_version":/p' > "$run/events.jsonl"
cut -d ' ' -f 2 "$run/request-matches.txt" | sort -u > "$run/clients.txt"
test "$(wc -l < "$run/clients.txt")" -eq 4
cut -d ' ' -f 2 "$run/request-matches.txt" | sort -u | diff "$run/clients.txt" -
jq -es --rawfile clients "$run/clients.txt" --arg local "10.0.2.2:$port" '
    def spans($kind; $client):
        map(.payload | objects | .[$kind] | select(.tuple.client == $client and .tuple.local == $local));
    {local: $local, flows: [
        ($clients | split("\n")[] | select(length > 0)) as $client |
        {client: $client, connects: spans("SocketConnect"; $client) | length,
         writes: spans("SocketWrite"; $client) | map({stream_start, stream_end})}
    ], gaps: map(.payload | objects | select(has("ObservationGap"))) | length}
    | . + {unmatched: [.flows[] | select(.connects != 1 or (.writes | length) == 0)] | length}
' "$run/events.jsonl" > "$run/match.json"
cat "$run/match.json"
printf '%s\n' "$run"
