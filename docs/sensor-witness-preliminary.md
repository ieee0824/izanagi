# センサー欠落検知の予備調査 (#136)

2026-11-17。対象 revision: `395cc33ae5e445f159c8e4c0245241556e84eecc`。
本記録はソース調査、既存相関テスト、および専用 Linux VM/QEMU guest での
guest root 攻撃実測をまとめる。個々の結果が適用される信頼境界は各節に記す。

## 最初に修正する前提

現在の HTTP 証拠は guest root から独立していない。
`izanagi-agent/src/sidecar.rs` の `validate_start` は guest loopback の固定ポートを要求し、
`spawn_proxy` が guest 内で HTTP sidecar を起動する。metadata socket も guest の
`/run/izanagi-behavior-*` にある。0700/0600 と root 所有の検査は非 root に対する境界であり、
guest root や kernel 侵害に対する境界ではない。
host に保存された HTTP イベントであっても、その生成元まで host とは限らない。

既存の TCP byte-range 照合は実装上の出発点として利用できるが、root に対する独立証人を
成立させるには host receiver/proxy または guest 外の NIC capture を別途用意する必要がある。
NIC の packet bytes と TCP payload、HTTP request bytes は直接等置しない。
再送、ACK、TLS、接続再利用を分離し、NAT の対応を確定できなければ一意な帰属を主張しない。

## ソースから確認できる攻撃候補

- `izanagi-ebpf/src/writer.rs`: `SOCKET_LAYOUT[0][3] != 1` なら
  `socket_state` は早期 return する。この分岐自体は `lost()` を呼ばない。
  これは socket 観測の抑止候補であり、全 syscall が無音になる証拠ではない。
  後述の実測でrootからの更新とwriter証拠の無警告抑止を確認した。
- `izanagi-ebpf/src/main.rs`: 256 KiB ring と `DROPS` がある。
  `src/ebpf_tracer/linux.rs` は drops を読み、forwarder の欠落も保持する。
  従って overflow を「既存では検知不能」と仮定しない。
- `izanagi-agent/src/config.rs`: QEMU の HMAC secret は fw_cfg の raw file から読む。
  guest root が読めるかは使い捨て VM で確認する。鍵値をログに残さず、
  読み取りの成否と fixture の期待値との一致だけを保存する。

## 実験 3: guest 内検査との比較（机上）

|操作|連番・ハッシュ連鎖|heartbeat|独立した host 通信観測が足すもの|
|---|---|---|---|
|連番付与より前の probe 抑止|欠落が番号に表れない可能性|agent が生存なら通る可能性|実通信があるのに対応イベントがない事実|
|ring overflow|DROPS など別の計数が必要|生存確認では不足|欠落申告に加え、通信との不一致|
|agent 終了|受信停止。無通信だけでは原因不明|期限付きなら停止を検出可能|停止後も続く通信の証拠|
|鍵取得後の偽イベント|攻撃者が有効な列を作れる可能性|応答を偽造可能|host の実通信から外れる偽装を拒否|
|完全に整合する偽イベント|真正性を保証できない|真正性を保証できない|同一の観測になる偽装は識別不能|
|一時 detach 中の非通信操作|生成前の欠落は不明|agent が応答すれば不明|ネットワーク証人のみでは追加の証拠なし|

ハッシュ連鎖は host が保持する既確定の末尾の改変と、今後の列の偽造を区別する。
鍵取得だけで既存接続へ直ちに注入できるとは限らず、接続の所有権・方向別連番・
セッショントークンも実験で確認する。root と kernel 侵害の結果は分ける。

## 実施済み検証

macOS 上で以下を実行し、追加回帰を含む22 tests passed、0 failed。

```sh
cargo test --locked --manifest-path izanagi-telemetry/Cargo.toml --test behavior
```

完全な writer range の正例、不完全・複数 writer の棄権、gap/clock 境界、
identity injection と equivocation の既存相関処理を検証した。
synthetic な入力のテストであり、攻撃成立・独立証人・検知率の実証ではない。

## 実 VM 実験の記録条件

同 revision の agent/object を配置した #62 修正後の使い捨て overlay を使う。
既存 `tests/manual/image_security.py` の legacy root login を攻撃成功として数えない。
root は fixture 専用の制御経路から与える。元イメージとホスト資格情報は変更・共有しない。

各試行は fresh VM とし、攻撃前の通信/イベント成功、攻撃操作の成否、攻撃後の
同一 workload、復旧後の成功を記録する。host 受信側の ground truth を別保存する。
結果表は操作、権限、agent error、monitor 切断、guest event、host witness、
既存ルール、分類状態、検知遅延を別列にし、未実施を失敗や検知不能に置き換えない。
mock 分類器の結果を Jev の精度と呼ばない。

以下では、SOCKET_LAYOUT改変、鍵の可読性、overflowのgap通知、host NIC対応付け、
通常workloadの不一致をこの順で実測した。最終判断は末尾にまとめる。

## Linux 実験環境の準備 (2026-11-18 JST)

SSH alias `codex-target` の Ubuntu 24.04.5 / x86_64 / Linux 6.8.0-147-generic に
`~/izanagi-lab/source`（上記 revision の tracked files の archive）、
`~/izanagi-lab/artifacts`（private directory）を用意した。
Rust stable 1.100.0、nightly-2026-02-12 + rust-src、公式配布 bpf-linker 0.13.0、
LLVM/Clang 18、ビルド依存、bpftool、tcpdump、QEMU 8.2.2 を導入した。
BTF/tracefs が利用可能で、sudo の `kvm-ok` も成功。disk imageではなく同一kernelと
専用initramfsを使うnested QEMU guestを後続試験で作成した。

host (`landlock,ebpf`)、agent (`ebpf`)、HTTP sidecar の debug build、eBPF release build が成功。
eBPF Cargo.lock は archive に含まれないため VM で生成し、object と共に SHA256 を保存した。
最初の bpf-linker ソース build は LLVM link error で失敗し、公式 v0.13.0 の
Linux x86_64 musl tarball に切り替えて解消した。失敗ログも残してある。

- `cargo test --locked --lib --features landlock,ebpf ebpf_tracer::`: 24 passed。
- telemetry の上記 behavior suite: Linux でも22 passed。
- VM にのみ配置した `examples/environment_smoke.rs` で `start_observation` を呼び、
  probe load と telemetry 受信を確認: `EBPF_LOAD_AND_TELEMETRY_OK`。
  終了時に tracer を stop。これは改ざん検知や特定 workload の完全性の実証ではない。

build/test/smoke logs、kernel features、toolchain 情報、source revision、binary hash は
remote `~/izanagi-lab/artifacts/` に保存。常駐 agent は開始していない。

## 実験 1: SOCKET_LAYOUT 改ざん（予備結果）

2026-11-18、同じ Linux VM で `SOCKET_LAYOUT[0]` の validity field
（4番目の u32）を root の `bpftool map update` で 1 から 0 に変更した。
host macOS の loopback HTTP receiver を SSH reverse forwarding で VM の
`127.0.0.1:18081` に公開し、変更前・変更中・復元後にそれぞれ新規 TCP 接続から
17 byte の同一ダミー body を POST した。

最初の Python client 試行は全 phase の通信に成功し、変更中のみ SocketWrite が
0件だった。ただし Python startup のイベント量により ObservationGap
（dropped=45）が生じたため、判定用データから除外した。

最小 C client に替えた再試行（remote artifact: `socket-layout-002`）では
ObservationGap は0件だった。

| phase | host POST | SocketConnect | SocketWrite | SocketLifecycle |
|---|---:|---:|---:|---:|
| before | 1 | 1 | 1 | 1 |
| validity=0 | 1 | 1 | 0 | 1 |
| restored | 1 | 1 | 1 | 1 |

変更中も collector は終了せず、File/Process/Connect/Lifecycle telemetry は継続した。
既存の drop counter による gap 通知も無かった。つまりこの操作はセンサー全体を
停止せず、writer byte-range 証拠だけを無警告で抑止できた。
一方、host の receiver は変更中の POST body を受信しており、独立観測との
「host transfer あり / guest SocketWrite なし」という食い違いは成立した。

script の `finally` で元の16 byte map valueを復元し、結果は
`layout_restored=true`、collector exit 0。終了後は当該 SOCKET_LAYOUT map が
残っていないことも確認した。これは loopback + SSH tunnel の単一試行であり、
QEMU guest/NAT、TLS、通常 workload、検知率や誤検知率の結果ではない。

### bpftool link detach

collector が作成した link 21本を列挙した。tracepoint と
`tcp_sendmsg_locked` の kprobe/kretprobe はすべて `perf_event` link だった。
root から21本すべてに `bpftool link detach id ...` を実行すると、全件が
`Operation not supported` で失敗した。切断前の `/etc/hostname` 読み取りでは
対象 PID のイベントが70件あり、collector を stop・再ロードした後も同じ操作で
70件を取得した。collector を stop すると全 link は解放された。成果物は
`~/izanagi-lab/artifacts/detach-003/`。
この実装・カーネルの組み合わせでは `bpftool link detach` による切断は成立しない。
agent/collector の停止と再ロードは別のベースラインとして扱う。

### 実験 1 の進捗表

| 操作 | 成立 | collector/agent のエラー | host witness との食い違い | 状態 |
|---|---|---|---|---|
| `bpftool link detach` | いいえ。`perf_event` link は未対応 | collector は継続 | 未発生 | 実測済み |
| `SOCKET_LAYOUT` validity 変更 | はい | エラー・gap なし | POST あり / SocketWrite なし | 実測済み |
| collector stop / reload | はい | stop 後に link 解放 | 停止後HTTPをNIC/receiverのみ観測 | 実測済み |
| `PROCESS_GENERATIONS` entry 削除 | はい | collector は継続 | HTTP は届くが通信2/2件が帰属不能 | 実測済み |
| ring overflow | はい。非 root で成立 | ObservationGap を通知 | 直後のPOSTはhost/guest双方で観測 | 実測済み |
| HMAC 鍵読み取り・偽イベント | はい | 正規認証として受理 | 独立転送との照合なし | 実測済み |
| mimicry | 部分成立 | HMACだけでは区別不能 | tuple・byte range・時刻・HTTP内容が必要 | 見積済み |

### ring buffer overflow

UID 65534 (`nobody`) のワーカー4個がそれぞれ10万回 `/dev/null` を open した。
合計40万回を0.428秒で完了し、collector は終了せず
`ObservationGap(dropped=793360, reason=event_loss)` を1件通知した。
root 権限を持たないプロセスが大量イベントを発生させて欠落を起こせる一方、
既存の drop counter で欠落自体は観測できた。保存先は
`~/izanagi-lab/artifacts/overflow-002/`。

対照として UID 65534 の1ワーカー・10回の open では dropped=0だった。
1ワーカー・1000回では dropped=1702となった。この閾値は実行速度、CPU数、
collector の保存処理に依存するため、一般的な容量限界とは扱わない。

再試行 `overflow-004` では同じ非root負荷の直後に、UID 65534の別プロセスが
ダミーbody `izanagi-dummy-136` をPOSTした。dropは794,732、collectorは継続し、
host receiverはbodyを受信した。POSTプロセスの12イベントは全件process帰属済みで、
`SocketConnect`、`SocketWrite`、lifecycleも残った。product HTTP sidecar/proxyを
この試行に含めていないため、既存分類器の最終判定は未測定。Jevも
`classification_unmeasured` と `recovered_with_gap` をともにconfidence 1.0で選んだ。

### process generation map 改ざん

待機中のテストプロセスについて、root から `PROCESS_GENERATIONS` の PID key を
削除してから `/etc/hostname` を open した。削除は成功し、操作も成功、collector
も継続した。最初のファイルのみの試行では、対照の9イベントすべてに process
identity があり、改ざん後は9件中3件が `missing_process_identity` になった。
残る6件は削除前に生成済みの process lifecycle 等だった。成果物は
`~/izanagi-lab/artifacts/map-tamper-002/`。

続く `map-tamper-005` では、同じプロセスが試験専用のダミー資格情報ファイルを
開いた後、独立したlocalhost HTTP receiverへその値をPOSTした。対照は12/12イベントが帰属済みで、通信イベント
2/2件も帰属済みだった。map entry 削除後は12件中6件が帰属不能になり、
`SocketConnect` と `SocketWrite` に相当する通信イベントは2/2件とも帰属不能だった。
一方、HTTP receiver は対照・改ざん後のダミーbody 2要求をともに受信し、collector exit は0。
従って操作・通信の存在は外部証拠で確認できるが、現行の相関入力では送信プロセスを
確定できず棄権すべき状態になる。

### collector 停止と HMAC 鍵

最小 QEMU guest で4本のHTTP通信をguest eBPFとNICで照合した後、collectorを正常に
停止し、5本目を送った。停止前は4/4フローが一致しgapは0。停止後の要求はguest NICと
host HTTP receiverの双方に残ったが、停止済みcollectorから対応telemetryは生成されない。
成果物は `~/izanagi-lab/artifacts/qemu-http.szFiQq/`。現行のイベント分類器だけでは
入力がなく帰属不能だが、独立NICを分母にする不一致検知なら明示的な欠落になる。

同じQEMU経路へランダムな32 byte secretをfw_cfgで渡し、`qemu_fw_cfg` moduleをロード
したguest rootから `/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.secret/raw` が
非空で読めることを、値をログへ出さず確認した。成果物は
`~/izanagi-lab/artifacts/qemu-http.Jtt8v8/`。さらに同じ共有鍵を持つ偽agentが
認証付きHello/Ready/TraceStartedを完了し、任意に作った `Telemetry` をhostの
`VmAgentTracer`へ受理させられる回帰テスト
`compromised_shared_secret_accepts_fabricated_telemetry` を追加し、macOSとLinuxで成功した。
これは鍵漏洩後のHMACがguest rootに対する真正性境界にならないことを示す。

完全なmimicryには、host NICで観測される5-tuple、TCP payload byte数、通信順、
proxyが見られる場合はHTTP method/authority/pathと、guest telemetryのsocket identity・
writer range・process identityを矛盾なく作る必要がある。平文HTTPなら外部証拠が多いが、
TLSやDoHではNICから内容を得られずtuple・packet size・timingまで弱くなる。本試験は
鍵を使った任意telemetry受理までを示し、実転送と完全一致する偽装の成功率は測っていない。

## 送信元の証拠が欠けた場合の回帰検証

合成イベントで HTTP 転送の完了と TCP 接続の記録を残し、送信元を裏づける
`SocketWrite` がないケースを相関テストに追加した。転送完了と転送バイト数は
結果に残り、送信プロセスは確定せず、相関に基づく分類の対象外となった。
`izanagi-telemetry` の behavior テストは22件すべて成功した。

## QEMU の host 側キャプチャ経路

Izanagi の既存 PCAP は agent プロトコルのメッセージを保存する。guest NIC の
観測には QEMU の `filter-dump` を `push_qemu_network` が定義する `net0` に
接続する候補がある。`codex-target` でネットワークを制限し vCPU を停止した
QEMU を起動して、Ethernet 形式・snaplen 96 の PCAP を生成し、`tcpdump` が
読み取れることを確認した。成果物は `~/izanagi-lab/artifacts/qemu-capture.z6RGyY/`。
最初のファイルは24 byte のヘッダーのみ。続いてディスクなし・`restrict=on` の
QEMU をネットワークブートし、同じ host 側経路で DHCP 要求3件と SLIRP の
応答3件を確認した。要求は `0.0.0.0:68` から `255.255.255.255:67`、応答元は
`10.0.2.2:67`。保存先は `~/izanagi-lab/artifacts/qemu-dhcp.V7OSg9/`（952 byte）。
起動時のパケットを guest OS 外で採取できた。Linux guest の TCP イベントとの
照合、NAT 後の通信との対応付け、通常作業での欠落率は未測定。

続いて `tests/manual/qemu_witness_baseline.sh` で Linux 6.8 の最小 guest を
起動した。guest の HTTP GET は成功し、host の loopback receiver が HTTP 200 を
記録した。同じ試行の NIC キャプチャに `10.0.2.15:33684 → 10.0.2.2:19836`
の接続と88 byte の TCP request payload があり、対象ポートで計10パケットを確認した。
保存先は `~/izanagi-lab/artifacts/qemu-http.W99xKj/`。この試行では接続が1本で、
guest 内 telemetry や並行接続時の NAT 前後の照合は未測定。

次の試行では同じ最小 guest に Izanagi の eBPF collector を搭載した。
host NIC の SYN と guest の `SocketConnect` 1件は
`10.0.2.15:33268 → 10.0.2.2:19836` で一致した。guest の `SocketWrite` は
範囲 `[0, 88)`、host NIC のリクエストは TCP payload 88 byte、host receiver は
GET 1件に HTTP 200 を返した。`ObservationGap` は0件。保存先は
`~/izanagi-lab/artifacts/qemu-http.ddrJnm/`。並行接続と通常作業での評価は残る。

同一宛先への4本の GET を並行起動した試行では、NIC の SYN を分母として
4/4接続で guest の `SocketConnect` が一意に対応し、各 `SocketWrite` の
範囲 `[0, 88)` が NIC の TCP payload 88 byte と一致した。照合不能は0/4、
`ObservationGap` は0件で、host receiver は HTTP 200 を4件記録した。
保存先は `~/izanagi-lab/artifacts/qemu-http.a1SxZ2/`。host receiver のログには
NAT 後の送信元ポートがないため、receiver の個別リクエストとの一対一照合は未確認。

試行専用の番号を URL に付けた再試行では、NIC 側の HTTP リクエスト行から
番号と TCP tuple を取り、NAT 後の受信ログにある同じ番号と照合した。
4件すべてで guest eBPF、NIC、HTTP 200 の受信記録が対応し、各 TCP payload は
94 byte、欠落通知は0件だった。保存先は `~/izanagi-lab/artifacts/qemu-http.DyKx7q/`。
この照合は既知の平文 HTTP リクエスト番号を使う。汎用の NAT tuple 対応や
TLS 通信の照合を示す結果ではない。

同じ4接続について、tuple で対応を確定してから、NIC の送信パケットの
UNIX 時刻と `SocketWrite.observed_monotonic_ns` の差を計算した。送信元ポート
50492 の差を基準にすると、50482 は +9.467 ms、50458 は −1.457 ms、
50472 は −1.423 ms で、最大と最小の開きは10.925 ms だった。50482 と
50492 の順序は guest 側と NIC 側で逆転した。
この差には二つの時計のずれと観測点の間の処理時間が含まれる。試行内の
差のばらつきとして扱い、時計同期の精度や汎用の照合窓には外挿しない。
一定のオフセット補正では順序の逆転を解消できないため、同じ宛先への
並行接続では時刻順だけに頼らない。

## DNS の観測範囲

`cargo test --locked --manifest-path izanagi-dns-proxy/Cargo.toml` は22件成功。
統合テストはローカルの guest relay と実 proxy を起動し、UDP/TCP 両方で
テスト問い合わせが proxy に届き、拒否が記録されることを確認した。
このテストは QEMU や Apple Container を起動しない。

現行の `sys_enter_sendto` は汎用 syscall 入力として先頭3引数を取り、
問い合わせ名・DNS transaction ID・送信先 sockaddr は記録しない。
相関用 collector は一般の sendto を専用イベントとして出力しない。
したがってこの経路の現行スキーマだけでは、並行 UDP 問い合わせの proxy 記録を
guest 内の個々のプロセスに一意に帰属させられない。

最小 QEMU guest から `nslookup` で `.invalid` のテスト名を host proxy に送った。
同じ試行で host NIC に DNS の送受信が残り、proxy は問い合わせを2件拒否した。
保存先は `~/izanagi-lab/artifacts/qemu-http.iVhlCq/`。この試行では専用ポートに
直接問い合わせたため、ゲストの通常リゾルバや製品の relay 構成は未検証。

Apple Container では使い捨てイメージで `python3 tests/manual/guest_dns.py container`
が成功した。標準リゾルバと明示的な TCP DNS の両方が製品の guest relay を使い、
host proxy にテスト名の拒否が記録された。仮想 NIC のパケット取得や DNS の
プロセス帰属はこのテストの対象外。

同じ Apple Container DNS スモークを専用の host port 19535 で再実行し、
host の `bridge100` で `192.168.64.0/24` とそのポートに絞って観測した。
標準リゾルバと TCP の両経路が成功し、bridge には UDP の要求・応答と
TCP の接続・データが残った。保存先は `/private/tmp/izanagi-apple-nic.UPErOm/`。
この観測点で relay と host proxy の間の通信を確認できる。guest 内の元の
問い合わせや発行プロセスとの一意な照合は未測定。

## 通常作業の再生データ

`behavior evaluate --manifest tests/fixtures/behavior/boundary-manifest.json` で
既存の合成 `normal-install` と `normal-build` を再生した。両方とも相関のある
方式 C と D は `normal`、方式 B は `unknown`、方式 A は `not_applied`。
方式 C と D はそれぞれ2件中0件が疑わしいと判定された。これは既存分類の
再生結果であり、それ自体はhost witnessの欠落警告や実workloadの誤警告率を測らない。
実際のinstall/build/testによるNIC照合は後段で別に測定した。

通常通信の評価では、guest 側の connect と guest NIC 上の TCP 接続を
送信元・宛先アドレスとポートで照合する。同じ tuple の再利用は接続の生存期間で
区別し、照合不能な通信も分母に残す。NAT 後の host 受信記録は別に集計し、
時刻だけで NAT 前後のプロセスを帰属させない。

この手順を実通信で測るため、公式Node.js v22.23.5配布物をSHA-256検証して最小
QEMU guestへ入れ、公開registryから `is-number@7.0.0` を取得する `npm install`、
ローカルの `npm run build`、`npm test` を連続実行した。NIC上のTCP SYNは2フロー、
guest `SocketConnect`も2件でtupleは2/2一致し、NIC-only 0、guest-only 0だった。
一方、通常作業だけで `ObservationGap` が5件、dropは77、81、82、158、45の合計
443イベント発生した。成果物は `~/izanagi-lab/artifacts/qemu-normal.daphVG/`。
したがってこの1試行のフロー不一致率は0/2だが、イベント欠落率が0とはいえず、
gap通知を攻撃固有の信号として扱えない。

npmのHTTPS通信はHTTP proxyを通らずSLIRP/NATへ直接出た。guest外NICでは宛先IP、
port、packet length、時刻、TCP tupleを取得でき、guest connectと一致したが、TLS内の
registry hostname、URL、request bodyは見えない。独自DNS/DoHも同様に、NICは外側の
resolverへの暗号化フローを証言できても問い合わせ名は証言できない。この範囲では
proxy非経由通信を「通信あり」と検出できるが、内容ベースの流出判定はできない。

## Jev による証拠分類

Jev 1.14.0へ上記の実測事実を同一stateで渡し、既存相関経路の結果を閉じた選択肢で
分類した。`SOCKET_LAYOUT`改変と`PROCESS_GENERATIONS`削除はいずれも
`abstained`（confidence 1.0）、overflowは`gap_only`（1.0）、鍵漏洩後の偽telemetryは
`hmac_not_sufficient`（0.99）だった。collector停止後通信は`unknown`（0.39）で、
既存分類器の判定と将来の不一致検知を一つの選択肢に含めた証拠が弱かったため採用しない。
実測上は「NIC/receiverに通信あり、guest eventなし」であり、既存分類器には帰属可能な
入力がない。Jevの判定は試験結果の代替ではなく、表の分類語を揃えるためだけに用いた。

## 実験1の流出結果まとめ

「hostが気づく」は現行製品が自動警告した意味ではなく、guest外artifactに要求が残り、
照合器が実装されれば不一致を判定できる意味を分けて記す。

| 操作 | 攻撃成立 | 攻撃後のダミー流出 | host外部証拠 | 既存分類/Jev |
|---|---|---|---|---|
| `bpftool link detach` | 不成立（21/21 `Operation not supported`） | 通常probeの対照操作のみ | 不一致なし | 攻撃不成立のため対象外 |
| 一時detach＋非通信操作 | detach不成立。collector stop/reloadなら成立 | 非通信操作はNICでは不可視 | stopでlink解放。非通信欠落を外部ネットワーク証人は検知不能 | 対象外。heartbeat/接続断が必要 |
| `SOCKET_LAYOUT` validity=0 | 成立、無警告 | ダミーPOST成功 | receiverにあり、`SocketWrite`なし | 既存相関は棄権、Jev `abstained` (1.0) |
| `PROCESS_GENERATIONS` entry削除 | 成立、無警告 | ダミーPOST成功 | receiverにあり、通信2/2がprocess帰属不能 | 既存相関は棄権、Jev `abstained` (1.0) |
| ring overflow | 非rootで成立、gap通知あり | overflow直後の非root POST成功 | receiverとguest network event双方にあり | 最終分類未測定、Jev `classification_unmeasured` (1.0) |
| collector/agent停止 | 成立 | 停止後にURLへダミー値を載せたHTTP成功 | NIC/receiverにあり、guest eventなし | 既存分類は入力なし。Jevは`unknown`なので採用せず |
| HMAC鍵読取＋偽telemetry | 鍵読取・任意event受理とも成立 | 実転送と偽eventの同時試行は未実施 | 偽event単独では外部転送なし | Jev `hmac_not_sufficient` (0.99) |
| 完全mimicry | 未実証 | 未実施 | TLS/DoHでは内容証拠が弱い | 必要条件のみ見積もり。成功扱いしない |

ここで未実施としたものを成功・検知不能へ読み替えない。予備実験の判断に必要な反例は、
guest rootが無警告にwriter/process証拠を欠落させられること、共有鍵でeventを偽造できること、
そしてguest外NICがその間の実通信を独立に残せることで得られた。一方、すべての攻撃ごとの
分類精度評価は本実験の課題として残る。

## バックエンド別の結論

| backend | 突き合わせに使えるguest外観測 | guestへの帰属 | 自然な食い違い |
|---|---|---|---|
| QEMU SLIRP/NAT | pre-NAT NICの5-tuple、packet長、時刻、平文ならpayload。host receiver/proxyのrequest | pre-NAT tupleでconnect/writeへ一意対応。NAT後はrequest ID等がなければ時刻だけで結ばない | 4並行HTTPは0/4不一致、npm通常作業は0/2不一致。ただし通常作業で443 event drop、時計差の試行内幅10.925 msと順序逆転あり |
| Apple Container | `bridge100`上のrelay→host proxy UDP/TCPとproxyログ | 現行backendにguest eBPF process/socket telemetryがなく、元processへの一意帰属不可 | 測定したDNS UDP/TCPはいずれもhost側に見えたが、guest eventとの対応率は定義不能（必要なguest側母集団が0） |

Apple Containerでは「不一致0」とは扱わない。host bridgeで通信の存在は証言できるが、
現行構成ではguest processへ戻す識別子がないため、この研究案のprocess attribution対象は
QEMU/Linuxに限定するか、Container backendへ別のguest sensorと安定したflow IDを追加する。

## 完了判断

研究は進める。ただし主張を「guest sensorの完全性を一般に証明する」から、
「QEMU/Linuxのネットワーク転送について、guest外NIC/proxyを分母に、対応する
connect/write/process証拠の欠落を検出する」へ狭める。guest内HTTP sidecarとHMACは
guest rootから独立した証人ではない。非通信操作の一時欠落、TLS/DoHの内容、外部観測と
完全に整合する偽装は検出対象外である。通常作業でもdropが出るため、gap単独では警告せず、
外部転送との具体的な不一致を別の監査状態として保存する。
