//! CLI / agent に共通のコマンド出力制限。

/// 保持する出力サイズの上限 (512 KiB から余裕分を引いた値)。
///
/// stdout と stderr を両方とも上限まで切り詰めても、`ExecResult` が
/// フレームの本体の上限 (1 MiB) に収まるよう、切り詰めの印と
/// エンコードの分の余裕を差し引いている。
pub const MAX_OUTPUT_SIZE: usize = 512 * 1024 - 64;

/// 上限を超えた出力を切り詰め、切り詰めたことを末尾に示す。
pub fn truncate_output(mut data: Vec<u8>) -> Vec<u8> {
    if data.len() > MAX_OUTPUT_SIZE {
        data.truncate(MAX_OUTPUT_SIZE);
        data.extend_from_slice(b"\n[truncated]");
    }
    data
}
