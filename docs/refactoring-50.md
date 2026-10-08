# 同用途関数の調査と統合（issue #50）

調査基準: de356eab51a5ff435c053ab0386ef9841611eafe。ルートと全サブクレートの Rust ソースを対象に、関数名の重複およびハッシュ・IP 判定・ログ変換・出力制限の呼び出しを検索し、入力、出力、エラー、副作用、依存方向を比較した。テスト用 fixture と trait の実装は、同名のみを理由とする統合対象にしない。

## 統合した処理

| 処理 | 旧実装 | 共通化先と互換性 |
| --- | --- | --- |
| 内部 IP 判定 | DNS / HTTP の ip_filter | izanagi-common::ip_filter。user feature のみで公開。IPv4、IPv6、IPv4-mapped IPv6 の判定式を維持し、既存テストと範囲境界テストを集約。 |
| SHA-256 文字列化 | 本体 / agent の crypto | 本体の crypto::sha256_hex を agent から再公開。agent は既に本体に依存するため新規依存不要。UTF-8 の既知値もテスト。agent の hex 直接依存を削除。 |
| コマンド出力制限 | MCP exec_capture / agent exec | 本体の exec_output。512 KiB の上限と超過時の改行付き [truncated] を保持。双方の既存境界テストを維持。 |
| 空きポート取得 | QEMU / Apple Container | util::find_available_port。127.0.0.1:0 に bind してポートを返し、リスナーを解放。呼び出し元の TOCTOU リトライ処理は維持。 |

IP 判定を std ユーザー空間モジュールとして既存の izanagi-common に置くことで、HTTP が本体ライブラリ全体に依存することを避ける。common の既定機能は引き続き依存なしの no_std で、eBPF ABI の型・レイアウトは変更しない。SHA-256 や tokio は common に持ち込まない。

## 統合を見送った候補と理由

| 候補 | 相違点 / 判断 |
| --- | --- |
| monotonic_ns（本体 eBPF / agent sidecar / HTTP behavior_forward） | HTTP の変換は飽和演算、他は通常演算。OS と feature の条件も異なる。共通の時計 API とオーバーフロー方針を決める変更は別途検討する。 |
| 本体 sanitize::escape_control_chars / HTTP logger::sanitize_str | 本体は ANSI CSI の内部をまとめて保持し、HTTP は各制御文字を個別に変換する。例えば CSI 中の改行の結果が異なるため、現行ログ互換性を保つこの変更では統合しない。 |
| SHA-256 のその他の利用 | 設定・インスタンス ID は OS パスのバイト列、評価はファイル内容、分類は複合 ID、telemetry は JSON を入力とする。文字列用 helper に変換すると非 UTF-8 パス等の意味が変わる。telemetry から本体への依存は循環するため導入しない。 |
| agent fw_cfg の token / secret 読み込み | 戻り値が String / Vec<u8>、secret のみログ出力がある。共通の file-read wrapper を設けても数行の trim に対して間接化が増えるため現状を維持。 |
| DNS allowlist / network_allowlist / HTTP cert_cache | ドメインのワイルドカード、解決済み IP、証明書用の完全一致と、入力・許可仕様が異なる。統合すると許可範囲の変更につながる。 |
| ログファイルの open / rotate / write_line | 同期 / 非同期、追記、バッファ、ローテーション、権限の扱いが異なる。I/O の共通設計が必要で単純な関数置換は適さない。 |
| Sandbox / Tracer の start / stop / exec / shell 等 | 共通 trait の各バックエンド固有実装、非対応 OS のスタブ、テスト fake。用途は共通でも起動・回収・監視の手順は異なる。 |
| protocol / agent の send / receive | 本体の framing と agent の認証有無を切り替える adapter。既に共通 protocol API に委譲しており、同じフレーム実装を重複して保持していない。 |

上表が未統合候補の追跡記録となる。巨大関数の責務分割は issue #49 に残し、この変更では実施しない。

## 検証

本体、agent、DNS、HTTP の既存テストと共通 IP 判定テストを実行する。CI では common の no_std check / user feature のテスト、Linux の landlock + ebpf、本体と各クレートの整形、Clippy に加え、agent の ebpf feature check と実際の bpfel-unknown-none ビルドを検証する。
