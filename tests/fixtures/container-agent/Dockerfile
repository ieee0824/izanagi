# Disposable security fixture; no host project or credentials are shared.
FROM debian:trixie-slim
RUN useradd -m izanagi && mkdir -p /workspace /project && chown izanagi:izanagi /workspace /project
COPY izanagi-agent /usr/local/bin/izanagi-agent
RUN chmod 0755 /usr/local/bin/izanagi-agent
ENTRYPOINT ["/usr/local/bin/izanagi-agent"]
