use super::*;
use serial_test::serial;

#[test]
fn parse_readme_example() {
    let toml_str = r#"
[sandbox]
backend = "qemu"
tracer = "auto"

[sandbox.qemu]
cpus = 2
memory = "4G"
image = "default"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file", "network", "process"]

[detect]
suspicious_paths = [
"/etc/passwd",
"/etc/shadow",
"~/.ssh/*",
"~/.aws/*",
"~/.gnupg/*",
"~/.config/gh/*",
]
allowed_hosts = [
"registry.npmjs.org",
"github.com",
]
"#;
    let config = Config::from_toml(toml_str).expect("failed to parse");
    assert_eq!(config.sandbox.backend, SandboxBackend::Qemu);
    assert_eq!(config.sandbox.tracer, TracerBackend::Auto);

    let qemu = config.sandbox.qemu.expect("qemu section missing");
    assert_eq!(qemu.cpus, 2);
    assert_eq!(qemu.memory, "4G");
    assert_eq!(qemu.image, "default");

    assert_eq!(config.share.paths, vec!["."]);
    assert_eq!(config.share.mount_point, "/workspace");

    assert_eq!(
        config.monitor.syscalls,
        vec![
            SyscallCategory::File,
            SyscallCategory::Network,
            SyscallCategory::Process
        ]
    );

    assert_eq!(config.detect.suspicious_paths.len(), 6);
    assert_eq!(
        config.detect.allowed_hosts,
        vec!["registry.npmjs.org", "github.com"]
    );
}

#[test]
fn default_config_is_valid() {
    let config = Config::default();
    config.validate().expect("default config should be valid");
    assert_eq!(config.sandbox.backend, SandboxBackend::Native);
    assert_eq!(config.sandbox.tracer, TracerBackend::Auto);
    assert!(config.sandbox.qemu.is_none());
    assert_eq!(config.share.paths, vec!["."]);
    assert_eq!(config.share.mount_point, "/workspace");
    assert_eq!(
        config.monitor.syscalls,
        vec![
            SyscallCategory::File,
            SyscallCategory::Network,
            SyscallCategory::Process
        ]
    );
}

#[test]
fn validate_invalid_backend() {
    let toml_str = r#"
[sandbox]
backend = "docker"
tracer = "auto"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file"]

[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let err = Config::from_toml(toml_str).unwrap_err();
    assert!(err.to_string().contains("backend"));
}

#[test]
fn validate_invalid_tracer() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "strace"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file"]

[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let err = Config::from_toml(toml_str).unwrap_err();
    assert!(err.to_string().contains("tracer"));
}

#[test]
fn validate_qemu_without_section() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.qemu = None;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("[sandbox.qemu]"));
}

#[test]
fn validate_qemu_with_section() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.qemu = Some(QemuSection::default());
    config
        .validate()
        .expect("qemu with section should be valid");
}

#[test]
fn validate_invalid_syscall_category() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "auto"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file", "memory"]

[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let err = Config::from_toml(toml_str).unwrap_err();
    assert!(err.to_string().contains("memory") || err.to_string().contains("unknown variant"));
}

#[test]
fn validate_env_syscall_category() {
    let mut config = Config::default();
    config.monitor.syscalls = vec![SyscallCategory::Env];
    config.validate().expect("env category should be valid");
}

#[test]
fn load_nonexistent_returns_default() {
    let config = Config::load(Path::new("/tmp/izanagi_nonexistent_test.toml"))
        .expect("should return default");
    assert_eq!(config.sandbox.backend, SandboxBackend::Native);
}

#[test]
fn validate_share_root_path_rejected() {
    let mut config = Config::default();
    config.share.paths = vec!["/".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("ルートパス"));
}

#[test]
#[serial(env)]
fn validate_share_sensitive_path_rejected() {
    let mut config = Config::default();
    config.share.paths = vec!["~/.ssh".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("機密パス"));
}

#[test]
#[serial(env)]
fn validate_share_sensitive_subpath_rejected() {
    let mut config = Config::default();
    config.share.paths = vec!["~/.aws/credentials".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("機密パス"));
}

// --- プラットフォームバリデーションのテスト ---

#[test]
fn validate_native_unsupported_platform() {
    let config = Config::default();
    let err = config.validate_for_platform(false, false).unwrap_err();
    assert!(err.to_string().contains("native"));
}

#[test]
fn validate_ebpf_on_macos() {
    let mut config = Config::default();
    config.sandbox.tracer = TracerBackend::Ebpf;
    let err = config.validate_for_platform(false, true).unwrap_err();
    assert!(err.to_string().contains("ebpf"));
}

#[test]
fn validate_dtrace_on_linux() {
    let mut config = Config::default();
    config.sandbox.tracer = TracerBackend::Dtrace;
    let err = config.validate_for_platform(true, false).unwrap_err();
    assert!(err.to_string().contains("dtrace"));
}

#[test]
fn validate_ebpf_on_linux_ok() {
    let mut config = Config::default();
    config.sandbox.tracer = TracerBackend::Ebpf;
    config
        .validate_for_platform(true, false)
        .expect("ebpf on linux should be valid");
}

#[test]
fn validate_dtrace_on_macos_ok() {
    let mut config = Config::default();
    config.sandbox.tracer = TracerBackend::Dtrace;
    config
        .validate_for_platform(false, true)
        .expect("dtrace on macos should be valid");
}

// --- 変換テスト ---

#[test]
fn to_sandbox_config_qemu() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.qemu = Some(QemuSection {
        cpus: 4,
        memory: "8G".to_string(),
        image: "ubuntu".to_string(),
        restrict_network: true,
    });
    config.share.paths = vec!["/home/user/project".to_string()];
    config.share.mount_point = "/mnt".to_string();

    let sc = config.to_sandbox_config().expect("should succeed");
    match sc {
        crate::sandbox::SandboxConfig::Qemu {
            cpus,
            memory_mb,
            image,
            share,
            ..
        } => {
            assert_eq!(cpus, 4);
            assert_eq!(memory_mb, 8192);
            assert_eq!(image, "ubuntu");
            assert_eq!(share.host_paths, vec![PathBuf::from("/home/user/project")]);
            assert_eq!(share.mount_point, PathBuf::from("/mnt"));
        }
        _ => panic!("expected Qemu variant"),
    }
}

#[test]
fn to_sandbox_config_native() {
    let config = Config::default();
    let sc = config.to_sandbox_config().expect("should succeed");
    // native バックエンドは OS に応じて Landlock か AppleContainer
    if cfg!(target_os = "linux") {
        assert!(matches!(sc, crate::sandbox::SandboxConfig::Landlock { .. }));
    } else {
        assert!(matches!(
            sc,
            crate::sandbox::SandboxConfig::AppleContainer { .. }
        ));
    }
}

#[test]
fn to_sandbox_config_native_linux() {
    let config = Config::default();
    let sc = config
        .to_sandbox_config_for_platform(true)
        .expect("should succeed");
    assert!(matches!(sc, crate::sandbox::SandboxConfig::Landlock { .. }));
}

#[test]
fn to_sandbox_config_native_macos() {
    let config = Config::default();
    let sc = config
        .to_sandbox_config_for_platform(false)
        .expect("should succeed");
    assert!(matches!(
        sc,
        crate::sandbox::SandboxConfig::AppleContainer { .. }
    ));
}

#[test]
fn to_trace_filter_default() {
    let config = Config::default();
    let filter = config.to_trace_filter();
    assert_eq!(filter.categories.len(), 3);
    assert!(
        filter
            .categories
            .contains(&crate::event::SyscallCategory::File)
    );
    assert!(
        filter
            .categories
            .contains(&crate::event::SyscallCategory::Network)
    );
    assert!(
        filter
            .categories
            .contains(&crate::event::SyscallCategory::Process)
    );
    assert!(filter.pids.is_none());
}

#[test]
fn to_trace_filter_with_env() {
    let mut config = Config::default();
    config.monitor.syscalls = vec![SyscallCategory::Env];
    let filter = config.to_trace_filter();
    assert_eq!(filter.categories.len(), 1);
    assert!(filter.categories.contains(&SyscallCategory::Env));
}

#[test]
fn to_rules_returns_rules_from_config() {
    let config = Config::default();
    let rules = config.to_rules();
    // デフォルト設定では suspicious_paths が設定されているため、少なくとも
    // SuspiciousPathRule + NetworkAllowlistRule + UnexpectedExecRule + EnvAccessRule + ProcessBaselineRule = 5つ以上
    assert!(rules.len() >= 5);
    let names: Vec<&str> = rules.iter().map(|r| r.name()).collect();
    assert!(names.contains(&"suspicious-path"));
    assert!(names.contains(&"network-allowlist"));
    assert!(names.contains(&"unexpected-exec"));
    assert!(names.contains(&"env-access"));
    assert!(names.contains(&"process-baseline"));
}

#[test]
fn to_rules_with_allowed_hosts() {
    let mut config = Config::default();
    config.detect.allowed_hosts = vec!["93.184.216.34".to_string()];
    let rules = config.to_rules();
    let names: Vec<&str> = rules.iter().map(|r| r.name()).collect();
    assert!(names.contains(&"network-allowlist"));
}

#[test]
fn to_rules_with_warnings_when_no_user_rules() {
    let mut config = Config::default();
    config.detect.suspicious_paths.clear();
    config.detect.allowed_hosts.clear();
    // UnexpectedExecRule と EnvAccessRule は常に有効だが、ユーザ設定由来のルールがないので警告が出る
    let (rules, warnings) = config.to_rules_with_warnings();
    assert!(!rules.is_empty());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("ユーザ設定由来"));
}

#[test]
fn validate_share_parent_dir_traversal_rejected() {
    let mut config = Config::default();
    config.share.paths = vec!["../.ssh".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains(".."));
}

#[test]
fn validate_share_nonexistent_path_returns_warning() {
    let mut config = Config::default();
    config.share.paths = vec!["/tmp/izanagi_nonexistent_test_path_xyz".to_string()];
    let warnings = config.validate().expect("should be valid");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("存在しません"));
}

#[test]
fn parse_memory_mb_variants() {
    assert_eq!(super::parse_memory_mb("4G").unwrap(), 4096);
    assert_eq!(super::parse_memory_mb("512M").unwrap(), 512);
    assert_eq!(super::parse_memory_mb("1g").unwrap(), 1024);
    assert_eq!(super::parse_memory_mb("256m").unwrap(), 256);
    assert_eq!(super::parse_memory_mb("1024").unwrap(), 1024);
    assert!(super::parse_memory_mb("").is_err());
    assert!(super::parse_memory_mb("abc").is_err());
}

// --- known_processes パーステスト (#173) ---

#[test]
fn parse_known_processes_none_when_omitted() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "auto"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file"]

[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let config = Config::from_toml(toml_str).unwrap();
    assert!(config.detect.known_processes.is_none());
}

#[test]
fn parse_known_processes_some_when_specified() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "auto"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file"]

[detect]
suspicious_paths = []
allowed_hosts = []
known_processes = ["node", "npm", "custom-tool"]
"#;
    let config = Config::from_toml(toml_str).unwrap();
    assert_eq!(
        config.detect.known_processes,
        Some(vec![
            "node".to_string(),
            "npm".to_string(),
            "custom-tool".to_string(),
        ])
    );
}

#[test]
fn parse_known_processes_empty_array() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "auto"

[share]
paths = ["."]
mount_point = "/workspace"

[monitor]
syscalls = ["file"]

[detect]
suspicious_paths = []
allowed_hosts = []
known_processes = []
"#;
    let config = Config::from_toml(toml_str).unwrap();
    // 空配列は Some(vec![]) であり None とは異なる
    assert_eq!(config.detect.known_processes, Some(vec![]));
}

#[test]
fn known_processes_none_uses_default_baseline() {
    let mut config = Config::default();
    config.detect.known_processes = None;
    let rules = config.to_rules();
    let baseline = rules
        .iter()
        .find(|r| r.name() == "process-baseline")
        .unwrap();
    // デフォルトベースラインには git が含まれる
    let event = crate::event::SyscallEvent {
        timestamp: std::time::SystemTime::now(),
        pid: 1,
        tgid: 0,
        process_name: "git".into(),
        syscall: crate::event::Syscall::Execve,
        args: smallvec::smallvec![crate::event::SyscallArg::Path(std::path::PathBuf::from(
            "git"
        ))],
        result: crate::event::SyscallResult::Ok(0),
    };
    assert!(
        baseline.check(&event).is_none(),
        "git はデフォルトベースラインで許可されるべき"
    );
}

#[test]
fn known_processes_some_uses_custom_baseline() {
    let mut config = Config::default();
    config.detect.known_processes = Some(vec!["custom-tool".to_string()]);
    let rules = config.to_rules();
    let baseline = rules
        .iter()
        .find(|r| r.name() == "process-baseline")
        .unwrap();
    // カスタムベースラインには git は含まれない
    let event = crate::event::SyscallEvent {
        timestamp: std::time::SystemTime::now(),
        pid: 1,
        tgid: 0,
        process_name: "git".into(),
        syscall: crate::event::Syscall::Execve,
        args: smallvec::smallvec![crate::event::SyscallArg::Path(std::path::PathBuf::from(
            "git"
        ))],
        result: crate::event::SyscallResult::Ok(0),
    };
    assert!(
        baseline.check(&event).is_some(),
        "git はカスタムベースラインで未知プロセスとして検知されるべき"
    );
}

// --- #209/#210: DNS プロキシ設定テスト ---

#[test]
fn parse_dns_proxy_section() {
    let toml = r#"
[sandbox]
backend = "native"
tracer = "none"
[share]
paths = ["."]
mount_point = "/workspace"
[monitor]
syscalls = ["file"]
[detect]
suspicious_paths = []
allowed_hosts = []
[dns_proxy]
enabled = true
listen = "127.0.0.1:15353"
"#;
    let config = Config::from_toml(toml).unwrap();
    let dns = config.dns_proxy.unwrap();
    assert!(dns.enabled);
    assert_eq!(dns.listen, "127.0.0.1:15353");
}

#[test]
fn dns_proxy_endpoint_extraction() {
    let mut config = Config::default();
    // dns_proxy が None → None
    assert_eq!(config.dns_proxy_endpoint(), None);

    // enabled = false → None
    config.dns_proxy = Some(DnsProxySection {
        enabled: false,
        listen: "127.0.0.1:53".to_string(),
    });
    assert_eq!(config.dns_proxy_endpoint(), None);

    // enabled = true, IPv4:port → ポートを保持
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: "127.0.0.1:15353".to_string(),
    });
    assert_eq!(
        config.dns_proxy_endpoint(),
        Some("127.0.0.1:15353".to_string())
    );

    // IPv6:port → エンドポイントを保持
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: "[::1]:53".to_string(),
    });
    assert_eq!(config.dns_proxy_endpoint(), Some("[::1]:53".to_string()));

    // IP アドレス単体（ポートなし）→ 拒否
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: "10.0.2.2".to_string(),
    });
    assert_eq!(config.dns_proxy_endpoint(), None);

    // 不正な値 → None
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: "not-an-address".to_string(),
    });
    assert_eq!(config.dns_proxy_endpoint(), None);
}

#[test]
fn dns_proxy_absent_means_disabled() {
    let toml = r#"
[sandbox]
backend = "native"
tracer = "none"
[share]
paths = ["."]
mount_point = "/workspace"
[monitor]
syscalls = ["file"]
[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let config = Config::from_toml(toml).unwrap();
    assert!(config.dns_proxy.is_none());
    assert_eq!(config.dns_proxy_endpoint(), None);
}

// --- #206: Apple Container ネットワーク制限テスト ---

/// テスト TOML のボイラープレートを生成するヘルパー。
/// `extra_sections` に追加セクション（[sandbox.apple_container] や [dns_proxy] 等）を渡す。
fn apple_container_toml(extra_sections: &str) -> String {
    format!(
        r#"
[sandbox]
backend = "apple-container"
tracer = "none"
{extra_sections}
[share]
paths = ["."]
mount_point = "/workspace"
[monitor]
syscalls = ["file"]
[detect]
suspicious_paths = []
allowed_hosts = []
"#
    )
}

#[test]
fn parse_apple_container_network() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\nnetwork = \"none\"",
    );
    let config = Config::from_toml(&toml).unwrap();
    let ac = config.sandbox.apple_container.unwrap();
    assert_eq!(ac.network, Some(ContainerNetworkMode::None));
}

#[test]
fn parse_apple_container_network_invalid() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\nnetwork = \"host\"",
    );
    assert!(Config::from_toml(&toml).is_err());
}

#[test]
fn validate_network_none_rejects() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\nnetwork = \"none\"",
    );
    let config = Config::from_toml(&toml).unwrap();
    // macOS 環境をシミュレート (is_linux=false, is_macos=true)
    // validate() を直呼びすると Linux CI で「macOS でのみ利用可能」エラーが先に発生する
    let result = config.validate_for_platform(false, true);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("サポートされていません")
    );
}

#[test]
fn validate_native_network_none_rejects() {
    let toml = r#"
[sandbox]
backend = "native"
tracer = "none"
[sandbox.apple_container]
image = "izanagi-vm"
network = "none"
[share]
paths = ["."]
mount_point = "/workspace"
[monitor]
syscalls = ["file"]
[detect]
suspicious_paths = []
allowed_hosts = []
"#;
    let config = Config::from_toml(toml).unwrap();
    // validate() で Native + network=none が拒否されること
    let result = config.validate_for_platform(false, true);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("サポートされていません")
    );
    // to_sandbox_config でも拒否されること
    let config2 = Config::from_toml(toml).unwrap();
    let result2 = config2.to_sandbox_config_for_platform(false);
    assert!(result2.is_err());
}

#[test]
fn validate_network_none_with_dns_proxy_rejects() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\nnetwork = \"none\"\n\
         [dns_proxy]\nenabled = true\nlisten = \"127.0.0.1:15353\"",
    );
    let config = Config::from_toml(&toml).unwrap();
    // macOS 環境をシミュレート
    let result = config.validate_for_platform(false, true);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("サポートされていません")
    );
}

#[test]
fn parse_apple_container_network_absent() {
    let toml = apple_container_toml("[sandbox.apple_container]\nimage = \"izanagi-vm\"");
    let config = Config::from_toml(&toml).unwrap();
    let ac = config.sandbox.apple_container.unwrap();
    assert!(ac.network.is_none());
}

// --- #166: AppleContainer to_sandbox_config テスト ---

/// SandboxConfig から AppleContainer のフィールドを取り出すヘルパー。
fn unwrap_apple_container(
    sc: SandboxConfig,
) -> (
    String,
    crate::sandbox::ShareConfig,
    Option<String>,
    Option<ContainerNetworkMode>,
) {
    match sc {
        SandboxConfig::AppleContainer {
            image,
            share,
            dns_proxy,
            network,
        } => (image, share, dns_proxy, network),
        other => panic!("expected AppleContainer, got {:?}", other),
    }
}

#[test]
fn to_sandbox_config_apple_container_default() {
    let toml = apple_container_toml("");
    let config = Config::from_toml(&toml).unwrap();
    let (image, share, dns_proxy, network) =
        unwrap_apple_container(config.to_sandbox_config_for_platform(false).unwrap());
    assert_eq!(image, "izanagi-vm");
    assert_eq!(share.mount_point, PathBuf::from("/workspace"));
    assert!(dns_proxy.is_none());
    assert!(network.is_none());
}

#[test]
fn to_sandbox_config_apple_container_custom_image() {
    let toml = apple_container_toml("[sandbox.apple_container]\nimage = \"custom-image\"");
    let config = Config::from_toml(&toml).unwrap();
    let (image, ..) = unwrap_apple_container(config.to_sandbox_config_for_platform(false).unwrap());
    assert_eq!(image, "custom-image");
}

#[test]
fn to_sandbox_config_apple_container_network_none_rejects() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\nnetwork = \"none\"",
    );
    let config = Config::from_toml(&toml).unwrap();
    let result = config.to_sandbox_config_for_platform(false);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("サポートされていません")
    );
}

#[test]
fn to_sandbox_config_apple_container_with_dns_proxy() {
    let toml = apple_container_toml(
        "[sandbox.apple_container]\nimage = \"izanagi-vm\"\n[dns_proxy]\nenabled = true\nlisten = \"192.168.1.2:15353\"",
    );
    let config = Config::from_toml(&toml).unwrap();
    let (_, _, dns_proxy, _) =
        unwrap_apple_container(config.to_sandbox_config_for_platform(false).unwrap());
    assert_eq!(dns_proxy, Some("192.168.1.2:15353".to_string()));
}

#[test]
fn to_sandbox_config_apple_container_share_paths() {
    let toml = apple_container_toml("[sandbox.apple_container]\nimage = \"izanagi-vm\"");
    let config = Config::from_toml(&toml).unwrap();
    let (_, share, ..) =
        unwrap_apple_container(config.to_sandbox_config_for_platform(false).unwrap());
    assert_eq!(share.host_paths, vec![PathBuf::from(".")]);
    assert_eq!(share.mount_point, PathBuf::from("/workspace"));
}

#[test]
fn settings_path_for_dir_is_deterministic() {
    let dir = Path::new("/Users/test/project");
    let p1 = settings_path_for_dir(dir).unwrap();
    let p2 = settings_path_for_dir(dir).unwrap();
    assert_eq!(p1, p2);
    assert!(p1.to_string_lossy().contains(".izanagi/settings/"));
    assert!(p1.to_string_lossy().ends_with("/izanagi.toml"));
}

#[test]
fn settings_path_differs_by_dir() {
    let p1 = settings_path_for_dir(Path::new("/a")).unwrap();
    let p2 = settings_path_for_dir(Path::new("/b")).unwrap();
    assert_ne!(p1, p2);
}

#[test]
fn validation_preserves_backend_then_platform_then_share_error_priority() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.tracer = TracerBackend::Ebpf;
    config.share.paths = vec!["/".into()];
    let error = config.validate_for_platform(false, true).unwrap_err();
    assert!(error.to_string().contains("[sandbox.qemu]"));
    config.sandbox.backend = SandboxBackend::Native;
    let error = config.validate_for_platform(false, true).unwrap_err();
    assert!(error.to_string().contains("ebpf"));
    config.sandbox.tracer = TracerBackend::Auto;
    let error = config.validate_for_platform(false, true).unwrap_err();
    assert!(error.to_string().contains("ルートパス"));
}

#[test]
fn old_configs_default_to_read_only_and_mode_reaches_each_backend() {
    let mut value: toml::Value =
        toml::from_str(&toml::to_string(&Config::default()).unwrap()).unwrap();
    value["share"].as_table_mut().unwrap().remove("read_only");
    assert!(
        Config::from_toml(&toml::to_string(&value).unwrap())
            .unwrap()
            .share
            .read_only
    );
    for backend in [
        SandboxBackend::Native,
        SandboxBackend::Qemu,
        SandboxBackend::AppleContainer,
    ] {
        for read_only in [true, false] {
            let mut config = Config::default();
            config.sandbox.backend = backend;
            config.sandbox.qemu = Some(QemuSection::default());
            config.share.read_only = read_only;
            for linux in [true, false] {
                let share = match config.to_sandbox_config_for_platform(linux).unwrap() {
                    crate::sandbox::SandboxConfig::Landlock { share }
                    | crate::sandbox::SandboxConfig::Qemu { share, .. }
                    | crate::sandbox::SandboxConfig::AppleContainer { share, .. } => share,
                };
                assert_eq!(share.read_only, read_only);
            }
        }
    }
}

#[tokio::test]
async fn workspace_write_rule_is_enabled_in_sync_and_async_configuration() {
    let config = Config::default();
    assert!(
        config
            .to_rules()
            .iter()
            .any(|r| r.name() == "workspace-write")
    );
    let (rules, _) = config
        .to_rules_with_warnings_async(std::time::Duration::from_secs(1))
        .await;
    assert!(rules.iter().any(|r| r.name() == "workspace-write"));
}

#[test]
fn writable_share_emits_host_execution_warning() {
    let mut config = Config::default();
    config.share.read_only = false;
    assert!(
        config
            .validate()
            .unwrap()
            .iter()
            .any(|w| w.contains("Writable shares"))
    );
}

#[test]
fn qemu_network_restriction_defaults_and_explicit_opt_out_reach_backend() {
    for (setting, expected) in [("", true), ("restrict_network = false", false)] {
        let mut config = Config::default();
        config.sandbox.backend = SandboxBackend::Qemu;
        config.sandbox.qemu = Some(
            toml::from_str(&format!(
                "cpus = 2\nmemory = \"4G\"\nimage = \"default\"\n{setting}"
            ))
            .unwrap(),
        );
        match config.to_sandbox_config().unwrap() {
            crate::sandbox::SandboxConfig::Qemu {
                restrict_network, ..
            } => {
                assert_eq!(restrict_network, expected);
            }
            _ => panic!("expected QEMU"),
        }
    }
}

#[test]
fn restricted_qemu_rejects_network_proxies_until_explicit_opt_out() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.qemu = Some(QemuSection::default());
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: default_dns_proxy_listen(),
    });
    assert!(
        config
            .validate_for_platform(false, true)
            .unwrap_err()
            .to_string()
            .contains("restrict_network")
    );
    config.sandbox.qemu.as_mut().unwrap().restrict_network = false;
    assert!(
        config
            .validate_for_platform(false, true)
            .unwrap()
            .iter()
            .any(|w| w.contains("loopback"))
    );
}

#[test]
fn dns_proxy_rejects_unreachable_or_ambiguous_endpoints() {
    let mut config = Config::default();
    config.sandbox.backend = SandboxBackend::Qemu;
    config.sandbox.qemu = Some(QemuSection {
        restrict_network: false,
        ..Default::default()
    });
    for listen in [
        "0.0.0.0:15353",
        "[::]:53",
        "127.0.0.1:0",
        "127.0.0.1",
        "[::1]:15353",
        "127.0.0.2:15353",
        "224.0.0.1:53",
    ] {
        config.dns_proxy = Some(DnsProxySection {
            enabled: true,
            listen: listen.into(),
        });
        assert!(
            config.validate_for_platform(false, true).is_err(),
            "{listen}"
        );
    }
    config.dns_proxy = Some(DnsProxySection {
        enabled: true,
        listen: "127.0.0.1:15353".into(),
    });
    assert!(config.validate_for_platform(false, true).is_ok());
    config.sandbox.backend = SandboxBackend::AppleContainer;
    assert!(config.validate_for_platform(false, true).is_err());
    config.dns_proxy.as_mut().unwrap().listen = "192.168.1.2:15353".into();
    assert!(config.validate_for_platform(false, true).is_ok());
    config.sandbox.backend = SandboxBackend::Native;
    assert!(config.validate_for_platform(true, false).is_err());
}

#[test]
fn sensitive_directory_alias_protects_its_target_and_missing_descendants() {
    let directory = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let target = external.path().join("keys");
    std::fs::create_dir(&target).unwrap();
    let sensitive = directory.path().join(".ssh");
    std::os::unix::fs::symlink(&target, &sensitive).unwrap();
    for share in [
        external.path().to_owned(),
        target.clone(),
        target.join("missing-key"),
    ] {
        let resolved = resolve_existing_prefix(&share).unwrap();
        assert!(validate_sensitive_share("fixture", &[&share, &resolved], &sensitive).is_err());
    }
    let sibling = external.path().join("keys-backup");
    let resolved = resolve_existing_prefix(&sibling).unwrap();
    assert!(validate_sensitive_share("fixture", &[&sibling, &resolved], &sensitive).is_ok());
}

#[test]
fn dangling_share_alias_and_missing_children_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let alias = directory.path().join("dangling");
    std::os::unix::fs::symlink(directory.path().join("missing-target"), &alias).unwrap();
    for share in [alias.clone(), alias.join("missing-child")] {
        assert!(resolve_existing_prefix(&share).is_err());
    }
}
