use izanagi::mcp::{JsonRpcResponse, ToolCallParams, ToolCallResult};
use izanagi::session;
use serde_json::Value;

use super::exec_capture::{ExecOutput, exec_on_session_capture};

/// sandbox_status ツールの実装。
///
/// セッション情報を読み込み、プロセスが生存しているか確認して結果を返す。
pub(super) fn handle_sandbox_status(id: Value) -> JsonRpcResponse {
    let izanagi_dir = super::izanagi_dir();
    handle_sandbox_status_with_dir(id, &izanagi_dir)
}

/// sandbox_status の内部実装。テストから izanagi_dir を差し替えるために分離。
pub(super) fn handle_sandbox_status_with_dir(
    id: Value,
    izanagi_dir: &std::path::Path,
) -> JsonRpcResponse {
    let status = match session::load_session(izanagi_dir) {
        Ok(Some(s)) if session::is_session_alive(&s) => {
            let backend = match &s.backend {
                session::SessionBackend::AppleContainer { .. } => "apple-container",
                session::SessionBackend::Qemu { .. } => "qemu",
            };
            serde_json::json!({
                "running": true,
                "backend": backend,
                "pid": s.pid,
            })
        }
        _ => {
            serde_json::json!({ "running": false })
        }
    };

    let result = ToolCallResult::text(status.to_string());
    let value = serde_json::to_value(result).expect("ToolCallResult のシリアライズは常に成功する");
    JsonRpcResponse::success(id, value)
}

// ---------------------------------------------------------------------------
// sandbox_exec / sandbox_shell ハンドラ
// ---------------------------------------------------------------------------

/// arguments から command (string) と args (array of string) を取り出す。
///
/// arguments が非オブジェクトの場合や command が空の場合はエラーを返す。
fn extract_exec_args(params: &ToolCallParams) -> Result<(String, Vec<String>), String> {
    let args_obj = match &params.arguments {
        Some(Value::Object(obj)) => obj,
        Some(_) => return Err("arguments must be an object".to_string()),
        None => return Err("missing required argument: command".to_string()),
    };

    let command = match args_obj.get("command") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::String(_)) => return Err("command must not be empty".to_string()),
        Some(_) => return Err("command must be a string".to_string()),
        None => return Err("missing required argument: command".to_string()),
    };

    let args = match args_obj.get("args") {
        Some(Value::Array(arr)) => {
            let mut v = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::String(s) => v.push(s.clone()),
                    _ => return Err("args items must be strings".to_string()),
                }
            }
            v
        }
        Some(Value::Null) | None => vec![],
        Some(_) => return Err("args must be an array of strings".to_string()),
    };

    Ok((command, args))
}

/// sandbox_exec ツールの実装。
pub(super) async fn handle_sandbox_exec(id: Value, params: &ToolCallParams) -> JsonRpcResponse {
    let izanagi_dir = super::izanagi_dir();
    handle_sandbox_exec_with_dir(id, params, &izanagi_dir).await
}

/// sandbox_exec の内部実装。テストから izanagi_dir を差し替えるために分離。
pub(super) async fn handle_sandbox_exec_with_dir(
    id: Value,
    params: &ToolCallParams,
    izanagi_dir: &std::path::Path,
) -> JsonRpcResponse {
    let (command, args) = match extract_exec_args(params) {
        Ok(v) => v,
        Err(e) => {
            let result = ToolCallResult::error(e);
            return tool_response(id, result);
        }
    };

    // セッション検証
    let sess = match session::load_session(izanagi_dir) {
        Ok(Some(s)) if session::is_session_alive(&s) => s,
        Ok(_) => {
            let result = ToolCallResult::error("sandbox is not running");
            return tool_response(id, result);
        }
        Err(e) => {
            let result = ToolCallResult::error(format!("failed to load session: {e}"));
            return tool_response(id, result);
        }
    };

    // コマンド列を構築
    let mut cmd = vec![command];
    cmd.extend(args);

    match exec_on_session_capture(&sess, &cmd).await {
        Ok(output) => {
            let text = format_exec_output(&output);
            let result = if output.exit_code == 0 {
                ToolCallResult::text(text)
            } else {
                ToolCallResult::error(text)
            };
            tool_response(id, result)
        }
        Err(e) => {
            let result = ToolCallResult::error(format!("exec failed: {e}"));
            tool_response(id, result)
        }
    }
}

/// sandbox_shell ツールの実装。command を /bin/sh -c で実行する。
pub(super) async fn handle_sandbox_shell(id: Value, params: &ToolCallParams) -> JsonRpcResponse {
    let izanagi_dir = super::izanagi_dir();
    handle_sandbox_shell_with_dir(id, params, &izanagi_dir).await
}

/// sandbox_shell の内部実装。テストから izanagi_dir を差し替えるために分離。
pub(super) async fn handle_sandbox_shell_with_dir(
    id: Value,
    params: &ToolCallParams,
    izanagi_dir: &std::path::Path,
) -> JsonRpcResponse {
    // sandbox_shell は command のみ取得 (args は無視)
    let args_obj = match &params.arguments {
        Some(Value::Object(obj)) => obj,
        Some(_) => {
            let result = ToolCallResult::error("arguments must be an object");
            return tool_response(id, result);
        }
        None => {
            let result = ToolCallResult::error("missing required argument: command");
            return tool_response(id, result);
        }
    };

    let command = match args_obj.get("command") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::String(_)) => {
            let result = ToolCallResult::error("command must not be empty");
            return tool_response(id, result);
        }
        Some(_) => {
            let result = ToolCallResult::error("command must be a string");
            return tool_response(id, result);
        }
        None => {
            let result = ToolCallResult::error("missing required argument: command");
            return tool_response(id, result);
        }
    };

    // /bin/sh -c <command> として sandbox_exec に委譲
    let shell_params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(serde_json::json!({
            "command": "/bin/sh",
            "args": ["-c", command]
        })),
    };

    handle_sandbox_exec_with_dir(id, &shell_params, izanagi_dir).await
}

fn tool_response(id: Value, result: ToolCallResult) -> JsonRpcResponse {
    let value = serde_json::to_value(result).expect("ToolCallResult のシリアライズは常に成功する");
    JsonRpcResponse::success(id, value)
}

/// フォーマットされた実行結果テキストを返す。
fn format_exec_output(output: &ExecOutput) -> String {
    let mut text = String::new();
    if !output.stdout.is_empty() {
        text.push_str(&output.stdout);
    }
    if !output.stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str("[stderr]\n");
        text.push_str(&output.stderr);
    }
    if text.is_empty() {
        text.push_str(&format!("(exit code: {})", output.exit_code));
    } else if output.exit_code != 0 {
        text.push_str(&format!("\n(exit code: {})", output.exit_code));
    }
    text
}
