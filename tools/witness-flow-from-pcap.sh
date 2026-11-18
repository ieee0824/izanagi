#!/bin/sh
# Convert one independently selected TCP stream into audit-witness JSON.
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 PCAP TCP_STREAM GUEST_BOOT_ID GUEST_START_NS GUEST_END_NS FLOW_NUMBER" >&2
    exit 64
fi
pcap=$1
stream=$2
boot=$3
start=$4
end=$5
number=$6
case "$stream:$start:$end:$number" in
    *[!0-9:]*|::*|:*:) echo "numeric arguments must be unsigned integers" >&2; exit 64 ;;
esac
test -n "$boot"
test "$start" -lt "$end"
test "$number" -gt 0
command -v tshark >/dev/null

tshark -n -r "$pcap" -Y "tcp.stream == $stream" -T fields \
    -e ip.src -e ipv6.src -e tcp.srcport \
    -e ip.dst -e ipv6.dst -e tcp.dstport \
    -e tcp.seq -e tcp.len -e tcp.flags.syn -e tcp.flags.ack 2>/dev/null |
awk -F '\t' -v boot="$boot" -v begin="$start" -v finish="$end" -v number="$number" '
function address(v4, v6, port, ip) {
    ip = v4 != "" ? v4 : v6
    return index(ip, ":") ? "[" ip "]:" port : ip ":" port
}
function escape(value) {
    gsub(/\\/, "\\\\", value); gsub(/\"/, "\\\"", value)
    return value
}
($9 == "1" || $9 == "True") && ($10 == "0" || $10 == "False") {
    syns++
    client = address($1, $2, $3)
    remote = address($4, $5, $6)
}
$8 + 0 > 0 {
    packet_client = address($1, $2, $3)
    if (client != "" && packet_client == client) {
        ranges++
        first[ranges] = ($7 + 0) - 1
        last[ranges] = first[ranges] + ($8 + 0)
    }
}
END {
    if (syns != 1 || client == "" || ranges == 0) exit 65
    covered = 0
    for (chosen = 1; chosen <= ranges; chosen++) {
        next_index = 0
        for (i = 1; i <= ranges; i++) {
            if (used[i]) continue
            if (next_index == 0 || first[i] < first[next_index]) next_index = i
        }
        used[next_index] = 1
        if (first[next_index] > covered) exit 66
        if (last[next_index] > covered) covered = last[next_index]
    }
    printf "{\"number\":%s,\"client\":\"%s\",\"remote\":\"%s\",", number, client, remote
    printf "\"outbound_bytes\":%d,\"guest_boot_id\":\"%s\",", covered, escape(boot)
    printf "\"guest_start_ns\":%s,\"guest_end_ns\":%s}\n", begin, finish
}'
