//! MCP (Model Context Protocol) JSON-RPC 2.0 type definitions and tool schemas.
//!
//! MCP is a JSON-RPC 2.0 based protocol that communicates over stdin/stdout.
//! The typical flow is: initialize -> initialized -> tools/list -> tools/call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 base types
// ---------------------------------------------------------------------------

/// JSON-RPC 2.0 request object.
///
/// `id` が `None` の場合は notification（レスポンス不要）として扱う。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response object.
///
/// `result` と `error` は排他的（一方のみ設定可能）。
/// 不正な組み合わせを防ぐため、フィールドは private で `success()` / `error()` で生成する。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 constants
// ---------------------------------------------------------------------------

pub const JSONRPC_VERSION: &str = "2.0";

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

// ---------------------------------------------------------------------------
// MCP specific types — initialize
// ---------------------------------------------------------------------------

/// Parameters for the `initialize` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

/// Client capabilities (currently empty; reserved for future extensions).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ClientCapabilities {}

/// Information about the MCP client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Result of the `initialize` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// Server capabilities advertised during initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

/// Indicates that the server supports tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ToolsCapability {}

/// Information about the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// MCP specific types — tools
// ---------------------------------------------------------------------------

/// Result of the `tools/list` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
}

/// A single tool definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Parameters for the `tools/call` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

/// Result of the `tools/call` request.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallResult {
    pub content: Vec<Content>,
    /// `true` の場合、ツール実行がエラーで終了したことを示す。
    #[serde(
        rename = "isError",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_error: bool,
}

impl ToolCallResult {
    /// テキストコンテンツを持つ成功レスポンスを生成する。
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content {
                type_: "text".to_string(),
                text: text.into(),
            }],
            is_error: false,
        }
    }

    /// テキストコンテンツを持つエラーレスポンスを生成する。
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content {
                type_: "text".to_string(),
                text: text.into(),
            }],
            is_error: true,
        }
    }
}

/// A single content block returned by a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Content {
    #[serde(rename = "type")]
    pub type_: String,
    pub text: String,
}

// ---------------------------------------------------------------------------
// Tool schema definitions
// ---------------------------------------------------------------------------

/// Returns the list of tools provided by this MCP server.
pub fn tool_definitions() -> Vec<Tool> {
    vec![
        sandbox_status_tool(),
        sandbox_exec_tool(),
        sandbox_shell_tool(),
    ]
}

fn sandbox_status_tool() -> Tool {
    Tool {
        name: "sandbox_status".to_string(),
        description: "Returns the current sandbox status.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false
        }),
    }
}

fn sandbox_exec_tool() -> Tool {
    Tool {
        name: "sandbox_exec".to_string(),
        description: "Executes a command inside the sandbox and returns its output.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to execute."
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Arguments to pass to the command."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        }),
    }
}

fn sandbox_shell_tool() -> Tool {
    Tool {
        name: "sandbox_shell".to_string(),
        description:
            "Executes a shell command inside the sandbox via /bin/sh -c and returns its output."
                .to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        }),
    }
}

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

impl JsonRpcResponse {
    /// Returns the result value, if this is a success response.
    pub fn get_result(&self) -> Option<&Value> {
        self.result.as_ref()
    }

    /// Returns the error, if this is an error response.
    pub fn get_error(&self) -> Option<&JsonRpcError> {
        self.error.as_ref()
    }

    /// Create a successful response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_jsonrpc_request() {
        let req = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: Some(json!({"protocolVersion": "2024-11-05"})),
        };
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn notification_omits_id() {
        let notif = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };
        let serialized = serde_json::to_string(&notif).unwrap();
        let value: Value = serde_json::from_str(&serialized).unwrap();
        assert!(value.get("id").is_none());
    }

    #[test]
    fn roundtrip_jsonrpc_response_success() {
        let resp = JsonRpcResponse::success(json!(1), json!({"status": "ok"}));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn roundtrip_jsonrpc_response_error() {
        let resp = JsonRpcResponse::error(json!(2), METHOD_NOT_FOUND, "Method not found");
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(resp, deserialized);
        assert_eq!(resp.get_error().unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn roundtrip_initialize_params() {
        let params = InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ClientCapabilities {},
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
        };
        let serialized = serde_json::to_string(&params).unwrap();
        let deserialized: InitializeParams = serde_json::from_str(&serialized).unwrap();
        assert_eq!(params, deserialized);

        // Verify camelCase field names
        let value: Value = serde_json::from_str(&serialized).unwrap();
        assert!(value.get("protocolVersion").is_some());
        assert!(value.get("clientInfo").is_some());
    }

    #[test]
    fn roundtrip_initialize_result() {
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
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: InitializeResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn roundtrip_tools_list_result() {
        let result = ToolsListResult {
            tools: tool_definitions(),
        };
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ToolsListResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
        assert_eq!(deserialized.tools.len(), 3);
    }

    #[test]
    fn roundtrip_tool_call_params() {
        let params = ToolCallParams {
            name: "sandbox_exec".to_string(),
            arguments: Some(json!({"command": "ls", "args": ["-la"]})),
        };
        let serialized = serde_json::to_string(&params).unwrap();
        let deserialized: ToolCallParams = serde_json::from_str(&serialized).unwrap();
        assert_eq!(params, deserialized);
    }

    #[test]
    fn roundtrip_tool_call_result() {
        let result = ToolCallResult {
            content: vec![Content {
                type_: "text".to_string(),
                text: "sandbox is running".to_string(),
            }],
            is_error: false,
        };
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ToolCallResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);

        // Verify "type" field name (not "type_")
        let value: Value = serde_json::from_str(&serialized).unwrap();
        let content = value["content"][0].as_object().unwrap();
        assert!(content.contains_key("type"));
        assert!(!content.contains_key("type_"));
    }

    #[test]
    fn tool_definitions_schema_validation() {
        let tools = tool_definitions();

        let status_tool = tools.iter().find(|t| t.name == "sandbox_status").unwrap();
        assert_eq!(status_tool.input_schema["type"].as_str().unwrap(), "object");
        let required = status_tool.input_schema["required"].as_array().unwrap();
        assert!(required.is_empty());

        let exec_tool = tools.iter().find(|t| t.name == "sandbox_exec").unwrap();
        let props = exec_tool.input_schema["properties"].as_object().unwrap();
        assert!(props.contains_key("command"));
        assert!(props.contains_key("args"));
        let required = exec_tool.input_schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn response_omits_none_fields() {
        let resp = JsonRpcResponse::success(json!(1), json!("ok"));
        let serialized = serde_json::to_string(&resp).unwrap();
        let value: Value = serde_json::from_str(&serialized).unwrap();
        // error field should be omitted
        assert!(value.get("error").is_none());
    }
}
