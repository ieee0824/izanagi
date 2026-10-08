/// QEMU fw_cfg からセッショントークンを読み取る。
///
/// Linux ゲストでは `/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.token/raw` に
/// QEMU の `-fw_cfg` オプションで渡された値が配置される。
/// ファイルが存在しない場合（非 QEMU 環境）は `None` を返す。
pub(crate) fn read_fw_cfg_token() -> Option<String> {
    let path = "/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.token/raw";
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(_) => None,
    }
}

/// QEMU fw_cfg から HMAC シークレットを読み取る (#161)。
///
/// Linux ゲストでは `/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.secret/raw` に
/// QEMU の `-fw_cfg` オプションで渡された値が配置される。
/// ファイルが存在しない場合（非 QEMU 環境）は `None` を返す。
/// fw_cfg から読み取れた場合、環境変数 `IZANAGI_SHARED_SECRET` より優先する。
pub(crate) fn read_fw_cfg_secret() -> Option<Vec<u8>> {
    let path = "/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.secret/raw";
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                None
            } else {
                eprintln!("loaded HMAC secret from fw_cfg");
                Some(trimmed.as_bytes().to_vec())
            }
        }
        Err(_) => None,
    }
}

/// 起動時に環境変数設定のサマリをログ出力する。
pub(crate) fn log_env_summary() {
    let allowed_cmds = std::env::var("IZANAGI_ALLOWED_COMMANDS").unwrap_or_default();
    let allow_all = std::env::var("IZANAGI_ALLOW_ALL_COMMANDS").unwrap_or_default();
    let allow_no_token = std::env::var("IZANAGI_ALLOW_NO_TOKEN").unwrap_or_default();

    eprintln!("--- agent config summary ---");
    if !allowed_cmds.is_empty() {
        eprintln!("  IZANAGI_ALLOWED_COMMANDS = {}", allowed_cmds);
    } else if allow_all == "1" {
        eprintln!("  IZANAGI_ALLOW_ALL_COMMANDS = 1 (all commands permitted)");
    } else {
        eprintln!("  command allowlist: not configured (fail-closed)");
    }
    if allow_no_token == "1" {
        eprintln!("  IZANAGI_ALLOW_NO_TOKEN = 1 (token auth disabled)");
    }
    // 矛盾チェック: allowlist が設定済みなのに ALLOW_ALL_COMMANDS=1
    if !allowed_cmds.is_empty() && allow_all == "1" {
        eprintln!(
            "  WARNING: IZANAGI_ALLOWED_COMMANDS and IZANAGI_ALLOW_ALL_COMMANDS=1 are both set. The allowlist takes precedence; ALLOW_ALL will be ignored."
        );
    }
    eprintln!("---");
}
