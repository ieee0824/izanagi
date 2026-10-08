# Izanagi Makefile
#
# ターゲット一覧: make help

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- 変数 ---
AGENT_TARGET_MUSL := aarch64-unknown-linux-musl
AGENT_TARGET_GNU  := aarch64-unknown-linux-gnu
AGENT_TARGET := $(AGENT_TARGET_MUSL)
AGENT_BINARY := izanagi-agent/target/$(AGENT_TARGET)/release/izanagi-agent
AGENT_BINARY_GNU := izanagi-agent/target/$(AGENT_TARGET_GNU)/release/izanagi-agent
EBPF_BINARY := izanagi-ebpf/target/bpfel-unknown-none/release/izanagi-ebpf
HTTP_BINARY_GNU := izanagi-http-capture/target/$(AGENT_TARGET_GNU)/release/izanagi-http-capture
# Keep LLVM bitcode compatible with the macOS LLVM 22 BPF linker.
EBPF_TOOLCHAIN ?= nightly-2026-02-12
IMAGE_NAME := izanagi-vm
IMAGE_DIR := image
PACKER_DIR := packer
INSTALL_DIR := $(HOME)/.izanagi/bin
QEMU_IMAGE_DIR := $(HOME)/.izanagi/images
HOST_FEATURES :=
ifeq ($(shell uname -s),Linux)
HOST_FEATURES := --features landlock,ebpf
endif

# --- ビルド ---

.PHONY: build
build: ## ホスト側バイナリをビルド
	cargo build --release $(HOST_FEATURES)

.PHONY: build-agent
build-agent: ## agent を Linux musl クロスビルド (cargo-zigbuild 必要)
	cd izanagi-agent && cargo zigbuild --target $(AGENT_TARGET) --release --features ebpf

.PHONY: build-agent-gnu
build-agent-gnu: ## agent を Linux glibc クロスビルド (cargo-zigbuild 必要)
	cd izanagi-agent && cargo zigbuild --target $(AGENT_TARGET_GNU) --release --features ebpf

.PHONY: build-http-gnu
build-http-gnu: ## guest HTTP sidecar を Linux glibc クロスビルド
	cd izanagi-http-capture && cargo zigbuild --target $(AGENT_TARGET_GNU) --release --locked

.PHONY: build-ebpf
build-ebpf: ## eBPF プログラムをビルド (nightly + bpf-linker + LLVM 必要)
	cd izanagi-ebpf && DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/opt/llvm/lib \
		cargo +$(EBPF_TOOLCHAIN) build --target bpfel-unknown-none --release -Z build-std=core

.PHONY: build-all
build-all: build build-agent build-ebpf build-http-gnu ## ホスト + agent + eBPF + HTTP sidecar を全ビルド

# --- インストール ---

.PHONY: install
install: build ## ホスト側バイナリを ~/.izanagi/bin にインストール
	mkdir -p $(INSTALL_DIR)
	cp target/release/izanagi $(INSTALL_DIR)/izanagi
	chmod +x $(INSTALL_DIR)/izanagi
	codesign --sign - --force $(INSTALL_DIR)/izanagi
	@echo "Installed: $(INSTALL_DIR)/izanagi"
	@echo "PATH に $(INSTALL_DIR) を追加してください:"
	@echo '  export PATH="$$HOME/.izanagi/bin:$$PATH"'

.PHONY: uninstall
uninstall: ## インストールしたバイナリを削除
	rm -f $(INSTALL_DIR)/izanagi
	@echo "Removed: $(INSTALL_DIR)/izanagi"

# --- コンテナイメージ ---

.PHONY: image
image: build-agent-gnu ## コンテナイメージをビルド (Debian, agent glibc クロスビルド含む)
	cp $(AGENT_BINARY_GNU) $(IMAGE_DIR)/izanagi-agent
	chmod +x $(IMAGE_DIR)/izanagi-agent
	$(RUNTIME) build -f $(IMAGE_DIR)/Dockerfile.debian -t $(IMAGE_NAME) $(IMAGE_DIR)
	rm -f $(IMAGE_DIR)/izanagi-agent
	@echo "Done! Image: $(IMAGE_NAME)"

.PHONY: image-quick
image-quick: ## コンテナイメージをビルド (Debian, 既存 agent バイナリを使用)
	@test -f $(AGENT_BINARY_GNU) || (echo "Error: $(AGENT_BINARY_GNU) not found. Run 'make build-agent-gnu' first." && exit 1)
	cp $(AGENT_BINARY_GNU) $(IMAGE_DIR)/izanagi-agent
	chmod +x $(IMAGE_DIR)/izanagi-agent
	$(RUNTIME) build -f $(IMAGE_DIR)/Dockerfile.debian -t $(IMAGE_NAME) $(IMAGE_DIR)
	rm -f $(IMAGE_DIR)/izanagi-agent
	@echo "Done! Image: $(IMAGE_NAME)"

.PHONY: image-alpine
image-alpine: build-agent ## Alpine コンテナイメージをビルド (agent musl クロスビルド含む)
	cp $(AGENT_BINARY) $(IMAGE_DIR)/izanagi-agent
	chmod +x $(IMAGE_DIR)/izanagi-agent
	$(RUNTIME) build -t $(IMAGE_NAME)-alpine $(IMAGE_DIR)
	rm -f $(IMAGE_DIR)/izanagi-agent
	@echo "Done! Image: $(IMAGE_NAME)-alpine"

.PHONY: image-alpine-quick
image-alpine-quick: ## Alpine コンテナイメージをビルド (既存 agent バイナリを使用)
	@test -f $(AGENT_BINARY) || (echo "Error: $(AGENT_BINARY) not found. Run 'make build-agent' first." && exit 1)
	cp $(AGENT_BINARY) $(IMAGE_DIR)/izanagi-agent
	chmod +x $(IMAGE_DIR)/izanagi-agent
	$(RUNTIME) build -t $(IMAGE_NAME)-alpine $(IMAGE_DIR)
	rm -f $(IMAGE_DIR)/izanagi-agent
	@echo "Done! Image: $(IMAGE_NAME)-alpine"

# --- QEMU イメージ ---

.PHONY: qemu-image
qemu-image: build-agent-gnu build-ebpf build-http-gnu ## QEMU qcow2 イメージをビルド (Debian, agent + eBPF + HTTP sidecar)
	cd $(PACKER_DIR) && packer init debian.pkr.hcl
	rm -rf $(PACKER_DIR)/output-debian
	cd $(PACKER_DIR) && PACKER_LOG=1 PACKER_LOG_PATH=packer.log packer build \
		-var "agent_binary=../$(AGENT_BINARY_GNU)" \
		-var "ebpf_binary=../$(EBPF_BINARY)" \
		-var "http_binary=../$(HTTP_BINARY_GNU)" \
		debian.pkr.hcl
	mkdir -p $(QEMU_IMAGE_DIR)
	cp $(PACKER_DIR)/output-debian/debian-aarch64.qcow2 $(QEMU_IMAGE_DIR)/
	@echo "Done! QEMU image: $(QEMU_IMAGE_DIR)/debian-aarch64.qcow2"

.PHONY: qemu-image-quick
qemu-image-quick: ## QEMU qcow2 イメージをビルド (Debian, 既存 agent + eBPF + HTTP sidecar)
	@test -f $(AGENT_BINARY_GNU) || (echo "Error: $(AGENT_BINARY_GNU) not found. Run 'make build-agent-gnu' first." && exit 1)
	@test -f $(EBPF_BINARY) || (echo "Error: $(EBPF_BINARY) not found. Run 'make build-ebpf' first." && exit 1)
	@test -f $(HTTP_BINARY_GNU) || (echo "Error: $(HTTP_BINARY_GNU) not found. Run 'make build-http-gnu' first." && exit 1)
	cd $(PACKER_DIR) && packer init debian.pkr.hcl
	rm -rf $(PACKER_DIR)/output-debian
	cd $(PACKER_DIR) && PACKER_LOG=1 PACKER_LOG_PATH=packer.log packer build \
		-var "agent_binary=../$(AGENT_BINARY_GNU)" \
		-var "ebpf_binary=../$(EBPF_BINARY)" \
		-var "http_binary=../$(HTTP_BINARY_GNU)" \
		debian.pkr.hcl
	mkdir -p $(QEMU_IMAGE_DIR)
	cp $(PACKER_DIR)/output-debian/debian-aarch64.qcow2 $(QEMU_IMAGE_DIR)/
	@echo "Done! QEMU image: $(QEMU_IMAGE_DIR)/debian-aarch64.qcow2"

.PHONY: qemu-image-alpine
qemu-image-alpine: build-agent ## Alpine QEMU qcow2 イメージをビルド (Packer + agent クロスビルド)
	cd $(PACKER_DIR) && packer init alpine.pkr.hcl
	rm -rf $(PACKER_DIR)/output
	cd $(PACKER_DIR) && packer build -var "agent_binary=../$(AGENT_BINARY)" alpine.pkr.hcl
	mkdir -p $(QEMU_IMAGE_DIR)
	cp $(PACKER_DIR)/output/alpine-aarch64.qcow2 $(QEMU_IMAGE_DIR)/
	@echo "Done! QEMU image: $(QEMU_IMAGE_DIR)/alpine-aarch64.qcow2"

.PHONY: qemu-image-alpine-quick
qemu-image-alpine-quick: ## Alpine QEMU qcow2 イメージをビルド (既存 agent バイナリを使用)
	@test -f $(AGENT_BINARY) || (echo "Error: $(AGENT_BINARY) not found. Run 'make build-agent' first." && exit 1)
	cd $(PACKER_DIR) && packer init alpine.pkr.hcl
	rm -rf $(PACKER_DIR)/output
	cd $(PACKER_DIR) && packer build -var "agent_binary=../$(AGENT_BINARY)" alpine.pkr.hcl
	mkdir -p $(QEMU_IMAGE_DIR)
	cp $(PACKER_DIR)/output/alpine-aarch64.qcow2 $(QEMU_IMAGE_DIR)/
	@echo "Done! QEMU image: $(QEMU_IMAGE_DIR)/alpine-aarch64.qcow2"

# --- テスト ---

.PHONY: test
test: ## テスト実行
	cargo test $(HOST_FEATURES)

.PHONY: test-all
test-all: test test-agent ## 全クレートのテスト実行

.PHONY: test-agent
test-agent: ## agent のテスト実行
	cd izanagi-agent && cargo test

.PHONY: lint
lint: ## clippy + fmt チェック
	cargo clippy $(HOST_FEATURES) -- -D warnings
	cargo fmt -- --check

# --- コンテナ起動 ---

.PHONY: run-container
run-container: ## コンテナを起動 (テスト用、認証なし)
	$(RUNTIME) run --rm -it -p 9001:9001 \
		-e IZANAGI_ALLOW_NO_TOKEN=1 \
		-e IZANAGI_ALLOW_ALL_COMMANDS=1 \
		$(IMAGE_NAME)

.PHONY: run-container-bg
run-container-bg: ## コンテナをバックグラウンド起動
	$(RUNTIME) run --rm -d --name izanagi-sandbox -p 9001:9001 \
		-e IZANAGI_ALLOW_NO_TOKEN=1 \
		-e IZANAGI_ALLOW_ALL_COMMANDS=1 \
		$(IMAGE_NAME)
	@echo "Started. Stop with: make stop-container"

.PHONY: stop-container
stop-container: ## コンテナを停止
	$(RUNTIME) stop izanagi-sandbox 2>/dev/null || true

# --- クリーンアップ ---

.PHONY: clean
clean: ## ビルド成果物を削除
	cargo clean
	rm -f $(IMAGE_DIR)/izanagi-agent

# --- ユーティリティ ---

.PHONY: audit
audit: ## 依存クレートの脆弱性チェック (cargo-audit 必要)
	cargo audit

# コンテナランタイムの自動検出
RUNTIME := $(shell command -v container 2>/dev/null || command -v docker 2>/dev/null || echo "echo 'Error: container or docker not found' && exit 1")

.PHONY: help
help: ## このヘルプを表示
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
