#!/bin/sh
# izanagi-agent をフォアグラウンドで直接実行する (#159)
# tini が PID 1 としてシグナルを転送し、孤児プロセスを回収する。

# ホストから渡された環境変数はそのまま izanagi-agent に継承される。
#
# 【セキュリティ注意】
# 環境変数はコンテナ内の /proc/1/environ から読み取り可能なため、
# シークレットの受け渡しには IZANAGI_SECRET_FILE（ファイルマウント）を
# 強く推奨する。IZANAGI_SHARED_SECRET は開発・テスト用途に限定すること。

exec /usr/local/bin/izanagi-agent
