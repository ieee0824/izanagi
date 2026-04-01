//! MCP Server メインループ (stdio transport)。
//!
//! stdin から JSON-RPC 2.0 メッセージを行単位で読み、stdout に応答を返す。
//! ログ出力は全て stderr に行い、stdout は MCP プロトコル専用とする。

mod exec_capture;
#[cfg(test)]
mod tests;
mod tools;

// サブモジュールから super::super:: を避けるための re-export
use super::{build_sandbox_env, izanagi_dir};

use izanagi::mcp::{
    self, INVALID_PARAMS, INVALID_REQUEST, InitializeResult, JSONRPC_VERSION, JsonRpcRequest,
    JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR, ServerCapabilities, ServerInfo, ToolCallParams,
    ToolsCapability, ToolsListResult,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

/// 1 行の最大バイト数 (4 MiB)。これを超える行は拒否する。
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// MCP Server として起動し、stdin/stdout で JSON-RPC メッセージを処理する。
///
/// config は不要。設定ファイルがない環境でも起動可能。
pub async fn cmd_mcp() -> anyhow::Result<u8> {
    let stdin = tokio::io::stdin();
    let mut stdout = BufWriter::new(tokio::io::stdout());
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    eprintln!("izanagi MCP server started (stdio transport)");

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // EOF — クライアントが切断
            eprintln!("izanagi MCP server: stdin closed, shutting down");
            break;
        }

        // 行サイズ制限: DoS 防止
        if line.len() > MAX_LINE_BYTES {
            let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Message too large");
            let mut json = serde_json::to_vec(&resp)?;
            json.push(b'\n');
            stdout.write_all(&json).await?;
            stdout.flush().await?;
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(response) = handle_message(trimmed).await {
            let mut json = serde_json::to_vec(&response)?;
            json.push(b'\n');
            stdout.write_all(&json).await?;
            stdout.flush().await?;
        }
    }

    Ok(0)
}

/// 1 行の JSON-RPC メッセージを処理し、レスポンスを返す。
/// notification の場合は `None` を返す。
async fn handle_message(input: &str) -> Option<JsonRpcResponse> {
    // 2段階パース: JSON 構文エラー → PARSE_ERROR、スキーマ不一致 → INVALID_REQUEST
    let raw: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => {
            return Some(JsonRpcResponse::error(
                Value::Null,
                PARSE_ERROR,
                "Parse error",
            ));
        }
    };
    let request: JsonRpcRequest = match serde_json::from_value(raw.clone()) {
        Ok(req) => req,
        Err(e) => {
            // id が取得できればレスポンスに含める
            let id = raw.get("id").cloned().unwrap_or(Value::Null);
            return Some(JsonRpcResponse::error(
                id,
                INVALID_REQUEST,
                format!("Invalid Request: {e}"),
            ));
        }
    };

    // notification: id が None の場合はレスポンス不要
    let Some(id) = request.id else {
        return None;
    };

    // JSON-RPC 2.0 バージョン検証
    if request.jsonrpc != JSONRPC_VERSION {
        return Some(JsonRpcResponse::error(
            id,
            INVALID_REQUEST,
            "Invalid JSON-RPC version (expected \"2.0\")",
        ));
    }

    match request.method.as_str() {
        "initialize" => {
            let result = InitializeResult {
                protocol_version: "2024-11-05".to_string(),
                capabilities: ServerCapabilities {
                    tools: Some(ToolsCapability {}),
                },
                server_info: ServerInfo {
                    name: "izanagi".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
            };
            let value = serde_json::to_value(result)
                .expect("InitializeResult のシリアライズは常に成功する");
            Some(JsonRpcResponse::success(id, value))
        }
        "tools/list" => {
            let result = ToolsListResult {
                tools: mcp::tool_definitions(),
            };
            let value =
                serde_json::to_value(result).expect("ToolsListResult のシリアライズは常に成功する");
            Some(JsonRpcResponse::success(id, value))
        }
        "tools/call" => {
            let params: ToolCallParams = match request.params {
                Some(v) => match serde_json::from_value(v) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(JsonRpcResponse::error(
                            id,
                            INVALID_PARAMS,
                            format!("Invalid params: {e}"),
                        ));
                    }
                },
                None => {
                    return Some(JsonRpcResponse::error(id, INVALID_PARAMS, "Missing params"));
                }
            };
            Some(dispatch_tool_call(id, &params).await)
        }
        _ => Some(JsonRpcResponse::error(
            id,
            METHOD_NOT_FOUND,
            format!("Method not found: {}", request.method),
        )),
    }
}

/// ツール名に応じてディスパッチする。
async fn dispatch_tool_call(id: Value, params: &ToolCallParams) -> JsonRpcResponse {
    match params.name.as_str() {
        "sandbox_status" => tools::handle_sandbox_status(id),
        "sandbox_exec" => tools::handle_sandbox_exec(id, params).await,
        "sandbox_shell" => tools::handle_sandbox_shell(id, params).await,
        _ => JsonRpcResponse::error(id, INVALID_PARAMS, format!("Unknown tool: {}", params.name)),
    }
}
