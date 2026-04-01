# ダイジェストで固定してサプライチェーン攻撃を防止 (#157)
# 更新手順: docker pull alpine:3.23 && docker inspect --format='{{index .RepoDigests 0}}' alpine:3.23
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

# 基本パッケージ (SSH は不要 — agent 通信は TCP 9001 で行う)
# OpenRC / init は不要 — izanagi-agent をフォアグラウンドで直接実行 (#159)
# Node.js/npm はデモ用 (npm install の監視)
RUN echo "https://dl-cdn.alpinelinux.org/alpine/v$(cut -d. -f1-2 /etc/alpine-release)/community" >> /etc/apk/repositories \
    && apk add --no-cache bash nodejs npm curl

# 非特権ユーザーを作成（コマンド実行はこのユーザーで行う）
RUN adduser -D -h /home/izanagi -s /bin/sh izanagi

# ワークスペースディレクトリを作成（izanagi ユーザー所有）
RUN mkdir -p /workspace && chown izanagi:izanagi /workspace

# izanagi-agent をコピー（root で実行 — eBPF に必要）
COPY izanagi-agent /usr/local/bin/izanagi-agent
RUN chmod +x /usr/local/bin/izanagi-agent

# エントリポイント: izanagi-agent をフォアグラウンドで直接実行
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9001

ENTRYPOINT ["/entrypoint.sh"]
