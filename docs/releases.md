# バイナリリリース

`.github/workflows/release.yml` は macOS / Linux の ARM64・x86_64 用バイナリを
ネイティブビルドします。Linux 本体は `landlock,ebpf`、guest agent は `ebpf` を
有効にします。DNS・HTTP プロキシは本体と同じ `bin/` に配置します。
Linux アーカイブには guest agent と eBPF オブジェクトも同梱します。

## 公開手順

1. 本体・agent・プロキシの `Cargo.toml` のバージョンを揃え、対応する lockfile を更新します。
2. PR の CI・CodeQL・secret scan を確認して main にマージします。
3. `workflow_dispatch` を実行すると、公開せずにビルド・CLI の smoke test・パッケージ化を確認できます。
4. 本体のバージョンに一致するタグ（例: `v0.1.0`）を push します。
5. 全 target のビルドとチェックサム検証が成功すると、アーカイブと `SHA256SUMS` を付けた GitHub Release が自動公開されます。

```bash
# バージョン更新と workflow を含むコミットを main に反映した後
git tag v0.1.0
git push origin v0.1.0
```

`v0.1.0-rc.1` のようなハイフン付きバージョンは、自動でプレリリースとして公開します。
その場合も各 `Cargo.toml` のバージョンを `0.1.0-rc.1` に揃えてください。

タグと本体のバージョンが一致しない場合は停止します。既存リリースの資産を自動上書きしません。
公開後に再実行する場合は、既存リリースを確認してください。通常は新しいバージョンタグで公開します。
`workflow_dispatch` はタグを選択した場合もビルド確認のみで、公開しません。
ビルド job の権限は読み取りのみで、Release 作成 job だけに `contents: write` を付与します。

## 配布物と制約

- macOS: 本体・両プロキシを ad-hoc 署名します。Developer ID 署名・公証には未対応です。
- Linux: Ubuntu 24.04 の glibc にリンクします。古い glibc / musl 環境には対応しません。
- eBPF: 独立した Linux job で little-endian BPF オブジェクトをビルドし、両 CPU の配布物に同梱します。
- VM / コンテナイメージは配布しません。guest agent の CPU と guest の CPU を合わせてください。
- CLI smoke test はサンドボックスの実行確認ではありません。Linux の Landlock / eBPF の検証は Linux CI と実機で行います。
- eBPF crate は既存 CI と同じく lockfile 未管理です。他のバイナリは `--locked` でビルドします。

## ローカルのパッケージ化

対応 target に対して release ビルドを済ませた後、CI と同じスクリプトを使えます。

```bash
TARGET=aarch64-apple-darwin
cargo build --locked --release --bin izanagi --target "$TARGET"
for component in izanagi-dns-proxy izanagi-http-capture; do
  cargo build --locked --release --manifest-path "$component/Cargo.toml" --target "$TARGET"
done
# macOS: 配布前に各バイナリを codesign --sign - --force で署名
python3 tools/package-release.py --version 0.1.0 --target "$TARGET"
```

Linux では本体に `--features landlock,ebpf` を追加し、agent も `--features ebpf` で
ビルドしてください。パッケージ化には `--ebpf-object /path/to/izanagi-ebpf` が必要です。
出力先は `dist/` です。必須ファイルが欠けている場合、パッケージ化は停止します。
アーカイブには全バイナリの実行権限と、アーカイブ単位の SHA-256 ファイルを付けます。
