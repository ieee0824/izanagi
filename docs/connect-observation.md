# eBPF connect の宛先・戻り値

通常の QEMU / vm-agent ログでも `connect` 開始時の sockaddr を読み、IPv4 / IPv6 の
宛先 IP・ポートを `SyscallArg::Addr` として転送する。IPv6 の scope ID も保持する。
開始イベントの結果は Unknown、終了イベントの結果は syscall の戻り値である。
`EINPROGRESS` は接続成功と扱わず、最終的な TCP 接続確立を証明するものではない。

開始時のアドレスを pid_tgid 単位の上限付きマップに保存し、終了時に回収・削除する。
読み取り不能・短い sockaddr・未対応 family はアドレス不明のままにし、0.0.0.0 等を生成しない。
開始状態がない終了イベントも取得できた戻り値だけを記録し、欠落フラグを立てる。
ring buffer / マップの失敗は既存のドロップカウンタに反映する。全試行の観測を保証しない。

raw ABI を 3 に更新したため、agent と eBPF オブジェクトを同時に更新する。
認証付き wire protocol と RawSyscallEvent の構造体サイズは変更しない。
connect イベントに限り arg2 を IPv6 scope ID に使用する。AF_UNIX と sendto の宛先展開は対象外。

## 再ビルド後の確認

VM を停止してから `make build`、`make install`、`make qemu-image` を実行する。
新しい VM で loopback の HTTP サーバー・クライアントを動かし、次を照合する。

- IPv4 / IPv6 の実際の接続先と `connect(宛先)` ログが一致すること
- blocking connect 成功時に終了値 0 が残ること
- listener のないポートへの接続で ECONNREFUSED が残ること
- 不正な sockaddr と AF_UNIX で偽の IP アドレスを出さないこと
- 別スレッドから異なる宛先へ接続しても結果が混ざらないこと
- allowlist 外の IP に警告が出て、許可 IP には出ないこと

NetworkAllowlistRule は IP 単位の警告であり、通信を遮断するファイアウォールではない。
開始・終了の両方を記録するため、警告件数をそのまま API 試行回数として数えない。
PCAP の HTTP 結果、ファイアウォールによる遮断は引き続き別の観測・制御である。

この変更の単体テスト・クロスコンパイル・eBPF ビルドだけでは Linux verifier と
実機ロードの成功は証明できない。QEMU 実測を完了してから観測可能と確定する。
