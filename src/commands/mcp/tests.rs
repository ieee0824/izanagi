use super::tools::{
    handle_sandbox_exec_with_dir, handle_sandbox_shell_with_dir, handle_sandbox_status_with_dir,
};
use super::*;
use serde_json::json;

#[tokio::test]
async fn initialize_returns_capabilities() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0.1.0" }
        }
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert!(result["capabilities"]["tools"].is_object());
    assert_eq!(result["serverInfo"]["name"], "izanagi");
}

#[tokio::test]
async fn tools_list_returns_tools() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let result = resp.get_result().expect("should be a success response");

    let tools = result["tools"].as_array().expect("tools should be array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"sandbox_status"));
    assert!(names.contains(&"sandbox_exec"));
    assert!(names.contains(&"sandbox_shell"));
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "unknown/method"
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, METHOD_NOT_FOUND);
    assert!(err.message.contains("Method not found"));
}

#[tokio::test]
async fn notification_returns_none() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))
    .unwrap();

    let resp = handle_message(&input).await;
    assert!(resp.is_none(), "notification should not produce a response");
}

#[tokio::test]
async fn parse_error_returns_error() {
    let resp = handle_message("this is not json")
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, PARSE_ERROR);
}

#[tokio::test]
async fn sandbox_status_no_session_returns_not_running() {
    let tmp = make_unique_tmp_dir();

    let id = json!(4);
    let resp = handle_sandbox_status_with_dir(id, &tmp);
    let result = resp.get_result().expect("should be a success response");

    let content_text = result["content"][0]["text"].as_str().unwrap();
    let status: serde_json::Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(status["running"], json!(false));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn unknown_tool_returns_error() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool"
        }
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, INVALID_PARAMS);
    assert!(err.message.contains("Unknown tool"));
}

#[tokio::test]
async fn tools_call_missing_params_returns_error() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call"
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, INVALID_PARAMS);
}

#[tokio::test]
async fn invalid_jsonrpc_version_returns_error() {
    let input = serde_json::to_string(&json!({
        "jsonrpc": "1.0",
        "id": 5,
        "method": "initialize"
    }))
    .unwrap();

    let resp = handle_message(&input)
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, INVALID_REQUEST);
    assert!(err.message.contains("2.0"));
}

#[tokio::test]
async fn invalid_request_schema_returns_invalid_request() {
    // method フィールドがない JSON → INVALID_REQUEST (PARSE_ERROR ではない)
    let input = r#"{"jsonrpc": "2.0", "id": 6}"#;
    let resp = handle_message(input)
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, INVALID_REQUEST);
    assert!(err.message.contains("Invalid Request"));
}

#[tokio::test]
async fn invalid_json_syntax_returns_parse_error() {
    // JSON 構文エラー → PARSE_ERROR
    let resp = handle_message("{invalid json")
        .await
        .expect("should return a response");
    let err = resp.get_error().expect("should be an error response");

    assert_eq!(err.code, PARSE_ERROR);
}

// ----- sandbox_exec テスト -----

#[tokio::test]
async fn sandbox_exec_no_session_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(json!({"command": "ls"})),
    };
    let resp = handle_sandbox_exec_with_dir(json!(10), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not running"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn sandbox_exec_missing_command_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(json!({})),
    };
    let resp = handle_sandbox_exec_with_dir(json!(11), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("command"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn sandbox_exec_empty_command_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(json!({"command": ""})),
    };
    let resp = handle_sandbox_exec_with_dir(json!(12), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("empty"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

// ----- sandbox_shell テスト -----

#[tokio::test]
async fn sandbox_shell_no_session_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_shell".to_string(),
        arguments: Some(json!({"command": "echo hello"})),
    };
    let resp = handle_sandbox_shell_with_dir(json!(20), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not running"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn sandbox_shell_missing_command_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_shell".to_string(),
        arguments: Some(json!({})),
    };
    let resp = handle_sandbox_shell_with_dir(json!(21), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("command"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn sandbox_shell_empty_command_returns_error() {
    let tmp = make_unique_tmp_dir();

    let params = ToolCallParams {
        name: "sandbox_shell".to_string(),
        arguments: Some(json!({"command": ""})),
    };
    let resp = handle_sandbox_shell_with_dir(json!(22), &params, &tmp).await;
    let result = resp.get_result().expect("should be a success response");

    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("empty"), "text: {text}");

    let _ = std::fs::remove_dir_all(&tmp);
}

// =====================================================================
// 結合テスト (E2E: 複数メッセージの連続処理)
// =====================================================================

/// initialize → notifications/initialized → tools/list → tools/call の完全フロー。
/// 各レスポンスの id が正しくエコーバックされることを検証する。
#[tokio::test]
async fn integration_full_flow_initialize_to_tools_call() {
    let tmp = make_unique_tmp_dir();

    // Step 1: initialize (id=100)
    let init_msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "integration-test", "version": "1.0.0" }
        }
    }))
    .unwrap();
    let resp = handle_message(&init_msg)
        .await
        .expect("initialize should return response");
    assert_eq!(resp.id, json!(100), "id should be echoed back");
    let result = resp.get_result().expect("initialize should succeed");
    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert!(
        result["capabilities"]["tools"].is_object(),
        "should advertise tools capability"
    );
    assert_eq!(result["serverInfo"]["name"], "izanagi");

    // Step 2: notifications/initialized (no id → no response)
    let notif_msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))
    .unwrap();
    let resp = handle_message(&notif_msg).await;
    assert!(resp.is_none(), "notification should not produce a response");

    // Step 3: tools/list (id=101)
    let list_msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/list"
    }))
    .unwrap();
    let resp = handle_message(&list_msg)
        .await
        .expect("tools/list should return response");
    assert_eq!(resp.id, json!(101), "id should be echoed back");
    let result = resp.get_result().expect("tools/list should succeed");
    let tools = result["tools"].as_array().expect("tools should be array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"sandbox_status"));
    assert!(names.contains(&"sandbox_exec"));
    assert!(names.contains(&"sandbox_shell"));

    // Step 4: tools/call sandbox_status (id=102, セッション未存在)
    // sandbox_status は izanagi_dir() を使うので、直接 with_dir を呼ぶ
    let resp = handle_sandbox_status_with_dir(json!(102), &tmp);
    assert_eq!(resp.id, json!(102), "id should be echoed back");
    let result = resp.get_result().expect("sandbox_status should succeed");
    let content_text = result["content"][0]["text"].as_str().unwrap();
    let status: Value = serde_json::from_str(content_text).unwrap();
    assert_eq!(status["running"], json!(false));

    let _ = std::fs::remove_dir_all(&tmp);
}

/// sandbox_status (セッション未存在) → running: false を返す。
#[tokio::test]
async fn integration_sandbox_status_no_session() {
    let tmp = make_unique_tmp_dir();
    let resp = handle_sandbox_status_with_dir(json!(200), &tmp);
    assert_eq!(resp.id, json!(200));
    let result = resp.get_result().expect("should succeed");
    let text = result["content"][0]["text"].as_str().unwrap();
    let status: Value = serde_json::from_str(text).unwrap();
    assert_eq!(status["running"], json!(false));
    let _ = std::fs::remove_dir_all(&tmp);
}

/// sandbox_exec (セッション未存在) → isError: true を返す。
#[tokio::test]
async fn integration_sandbox_exec_no_session() {
    let tmp = make_unique_tmp_dir();
    let params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(json!({"command": "ls"})),
    };
    let resp = handle_sandbox_exec_with_dir(json!(201), &params, &tmp).await;
    assert_eq!(resp.id, json!(201));
    let result = resp.get_result().expect("should succeed at protocol level");
    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not running"), "text: {text}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// sandbox_shell (セッション未存在) → isError: true を返す。
#[tokio::test]
async fn integration_sandbox_shell_no_session() {
    let tmp = make_unique_tmp_dir();
    let params = ToolCallParams {
        name: "sandbox_shell".to_string(),
        arguments: Some(json!({"command": "echo hello"})),
    };
    let resp = handle_sandbox_shell_with_dir(json!(202), &params, &tmp).await;
    assert_eq!(resp.id, json!(202));
    let result = resp.get_result().expect("should succeed at protocol level");
    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not running"), "text: {text}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// 未知のツール名 → INVALID_PARAMS エラー。
#[tokio::test]
async fn integration_unknown_tool_name() {
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 203,
        "method": "tools/call",
        "params": { "name": "totally_unknown_tool" }
    }))
    .unwrap();
    let resp = handle_message(&msg).await.expect("should return response");
    assert_eq!(resp.id, json!(203));
    let err = resp.get_error().expect("should be error");
    assert_eq!(err.code, INVALID_PARAMS);
    assert!(err.message.contains("Unknown tool"));
}

/// パラメータ不正 (command が空文字列) → isError: true。
#[tokio::test]
async fn integration_empty_command_returns_error() {
    let tmp = make_unique_tmp_dir();
    let params = ToolCallParams {
        name: "sandbox_exec".to_string(),
        arguments: Some(json!({"command": ""})),
    };
    let resp = handle_sandbox_exec_with_dir(json!(204), &params, &tmp).await;
    assert_eq!(resp.id, json!(204));
    let result = resp.get_result().expect("should succeed at protocol level");
    assert_eq!(result["isError"], json!(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("empty"), "text: {text}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// 不正 JSON → PARSE_ERROR (-32700)。
#[tokio::test]
async fn integration_invalid_json_parse_error() {
    let resp = handle_message("{{not valid json}}")
        .await
        .expect("should return response");
    let err = resp.get_error().expect("should be error");
    assert_eq!(err.code, PARSE_ERROR);
    assert_eq!(resp.id, json!(null), "id should be null for parse errors");
}

/// notification (initialized) はレスポンスを返さない。
#[tokio::test]
async fn integration_notification_no_response() {
    // id なしの notification は応答しない
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))
    .unwrap();
    assert!(handle_message(&msg).await.is_none());

    // 別の notification method でも同様
    let msg2 = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress"
    }))
    .unwrap();
    assert!(handle_message(&msg2).await.is_none());
}

/// jsonrpc バージョン不正 → INVALID_REQUEST (-32600)。
#[tokio::test]
async fn integration_invalid_jsonrpc_version() {
    let msg = serde_json::to_string(&json!({
        "jsonrpc": "1.0",
        "id": 300,
        "method": "initialize"
    }))
    .unwrap();
    let resp = handle_message(&msg).await.expect("should return response");
    assert_eq!(resp.id, json!(300));
    let err = resp.get_error().expect("should be error");
    assert_eq!(err.code, INVALID_REQUEST);
    assert!(err.message.contains("2.0"));
}

/// method フィールド欠落 → INVALID_REQUEST (-32600)。
#[tokio::test]
async fn integration_missing_method_field() {
    let msg = r#"{"jsonrpc": "2.0", "id": 301}"#;
    let resp = handle_message(msg).await.expect("should return response");
    assert_eq!(resp.id, json!(301));
    let err = resp.get_error().expect("should be error");
    assert_eq!(err.code, INVALID_REQUEST);
    assert!(err.message.contains("Invalid Request"));
}

/// 複数メッセージの連続処理で id が混同されないことを検証する。
#[tokio::test]
async fn integration_id_echo_across_multiple_messages() {
    // 異なる id を持つ複数のメッセージを連続送信
    let ids_and_methods = vec![
        (json!("string-id-1"), "initialize"),
        (json!(42), "tools/list"),
        (json!("string-id-2"), "tools/list"),
        (json!(999), "initialize"),
    ];

    for (id, method) in &ids_and_methods {
        let msg = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": if *method == "initialize" {
                Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1.0.0" }
                }))
            } else {
                None
            }
        }))
        .unwrap();
        let resp = handle_message(&msg).await.expect("should return response");
        assert_eq!(
            resp.id, *id,
            "id mismatch for method={method}, expected={id}, got={}",
            resp.id
        );
    }
}

// ----- ヘルパー -----

/// テスト用のユニークな一時ディレクトリを作成する。
fn make_unique_tmp_dir() -> std::path::PathBuf {
    let unique = format!(
        "izanagi_mcp_test_{}_{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tmp = std::env::temp_dir().join(unique);
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    tmp
}
