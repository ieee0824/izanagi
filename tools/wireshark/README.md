# Wireshark Lua Dissector for Izanagi Protocol

izanagi の host-agent 間プロトコルを Wireshark で解析するための Lua dissector です。

## ワイヤーフォーマット

### 通常モード

```
+--------+----------+------------------+
| type   | length   | body             |
| (u8)   | (u32 LE) | (bincode bytes)  |
+--------+----------+------------------+
```

### HMAC 認証モード

```
+--------+----------+------------------+----------+--------+
| type   | length   | body             | sequence | hmac   |
| (u8)   | (u32 LE) | (bincode bytes)  | (u64 LE) | (32B)  |
+--------+----------+------------------+----------+--------+
```

### メッセージタイプ

| 値 | 名前 | 方向 | 説明 |
|----|------|------|------|
| 0 | Start | host -> agent | トレース開始 |
| 1 | Stop | host -> agent | トレース停止 |
| 2 | Event | agent -> host | syscall イベント |
| 3 | Ready | agent -> host | エージェント準備完了 |
| 4 | Error | 双方向 | エラー通知 |
| 5 | Hello | 双方向 | 認証ネゴシエーション |
| 6 | Exec | host -> agent | コマンド実行依頼 |
| 7 | ExecResult | agent -> host | コマンド実行結果 |
| 8 | Shell | host -> agent | 対話シェル起動 |
| 9 | ShellData | 双方向 | シェルデータ |
| 10 | ShellClose | agent -> host | シェル終了 |
| 11 | ShellResize | host -> agent | ターミナルリサイズ |

## インストール

### 方法 1: Wireshark の個人プラグインディレクトリにコピー

```bash
# macOS
cp tools/wireshark/izanagi.lua ~/.local/lib/wireshark/plugins/

# Linux
cp tools/wireshark/izanagi.lua ~/.local/lib/wireshark/plugins/

# Windows
copy tools\wireshark\izanagi.lua %APPDATA%\Wireshark\plugins\
```

プラグインディレクトリが存在しない場合は作成してください:

```bash
mkdir -p ~/.local/lib/wireshark/plugins
```

> **Tip:** Wireshark のプラグインディレクトリは Help > About Wireshark > Folders で確認できます。

### 方法 2: Wireshark 起動時に直接指定

```bash
wireshark -X lua_script:tools/wireshark/izanagi.lua
```

### 方法 3: tshark で使用

```bash
tshark -X lua_script:tools/wireshark/izanagi.lua -r capture.pcap
```

## 設定

### HMAC モード

HMAC 認証付きフレームを解析する場合は、Wireshark の Preferences で HMAC モードを有効にしてください:

1. Edit > Preferences > Protocols > Izanagi
2. "HMAC mode" にチェックを入れる

### カスタムポート

デフォルトでは TCP ポート 9001 で自動認識します。別のポートを使用している場合は、
Wireshark の "Decode As..." 機能で対象ポートに Izanagi プロトコルを割り当ててください。

## 表示フィルター

```
# Izanagi プロトコルのみ表示
izanagi

# 特定のメッセージタイプのみ表示
izanagi.type == 2      # Event メッセージのみ
izanagi.type == 4      # Error メッセージのみ

# ボディサイズでフィルタ
izanagi.length > 100
```

## 制限事項

- body の bincode デシリアライズは行いません（ヘッダー情報とバイト列の表示のみ）
- HMAC の検証は行いません（表示のみ）
