use std::sync::Arc;

use crate::event::SyscallEvent;

/// アラートの深刻度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    /// 通常のアクセス記録。
    Info,
    /// 不審だが許容される可能性があるアクセス。
    Warn,
    /// 明確に悪意ある、または危険なアクセス。
    Critical,
}

/// ルールがマッチした結果。深刻度とメッセージを一体で返す。
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub level: AlertLevel,
    pub message: String,
}

/// 検知されたアラート。
#[derive(Debug, Clone)]
pub struct Alert {
    pub level: AlertLevel,
    pub event: Arc<SyscallEvent>,
    pub rule_name: String,
    pub message: String,
}

/// 個々の検知ルール。
///
/// trait にすることで、パターンマッチ・レート制限・機械学習ベースなど
/// 異なるアプローチのルールを統一的に扱える。
pub trait Rule: Send + Sync {
    /// ルールの識別名。ログやアラートに表示される。
    fn name(&self) -> &str;

    /// イベントを検査し、不審であれば `Some(RuleMatch)` を返す。
    /// 問題なければ `None`。
    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch>;
}

/// ルールの集合を管理し、イベントを検査する。
pub struct Detector {
    rules: Vec<Box<dyn Rule>>,
}

impl Detector {
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    /// イベントを全ルールで検査し、最も深刻なアラートを返す。
    /// どのルールにも該当しなければ `None`。
    ///
    /// 2パス方式:
    /// - 1パス目: 全ルールの `check()` を呼び、マッチした (index, RuleMatch) を収集
    /// - 2パス目: 最も深刻な RuleMatch に対してのみ Alert を構築
    pub fn analyze(&self, event: &Arc<SyscallEvent>) -> Option<Alert> {
        // 1パス目: check() のみ実行し、マッチ結果を収集
        let matches: Vec<(usize, RuleMatch)> = self
            .rules
            .iter()
            .enumerate()
            .filter_map(|(i, rule)| rule.check(event).map(|m| (i, m)))
            .collect();

        // 2パス目: 最も深刻なマッチに対してのみ Alert を構築
        matches
            .into_iter()
            .max_by_key(|(_, m)| m.level)
            .map(|(i, m)| Alert {
                level: m.level,
                event: Arc::clone(event),
                rule_name: self.rules[i].name().to_string(),
                message: m.message,
            })
    }

    /// イベントを全ルールで検査し、マッチした全てのアラートを返す。
    /// フォレンジック・監査用途で、最も深刻なものだけでなく全マッチを確認したい場合に使う。
    pub fn analyze_all(&self, event: &Arc<SyscallEvent>) -> Vec<Alert> {
        self.rules
            .iter()
            .filter_map(|rule| {
                rule.check(event).map(|m| Alert {
                    level: m.level,
                    event: Arc::clone(event),
                    rule_name: rule.name().to_string(),
                    message: m.message,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Syscall, SyscallResult};
    use std::time::SystemTime;

    /// テスト用のダミーイベントを生成する。
    fn dummy_event() -> Arc<SyscallEvent> {
        Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 1234,
            tgid: 0,
            process_name: "test".into(),
            syscall: Syscall::Open,
            args: smallvec::smallvec![],
            result: SyscallResult::Ok(0),
        })
    }

    /// 常にマッチする MockRule。
    struct MockRule {
        rule_name: String,
        level: AlertLevel,
        msg: String,
    }

    impl MockRule {
        fn new(name: &str, level: AlertLevel, msg: &str) -> Self {
            Self {
                rule_name: name.to_string(),
                level,
                msg: msg.to_string(),
            }
        }
    }

    impl Rule for MockRule {
        fn name(&self) -> &str {
            &self.rule_name
        }

        fn check(&self, _event: &SyscallEvent) -> Option<RuleMatch> {
            Some(RuleMatch {
                level: self.level,
                message: self.msg.clone(),
            })
        }
    }

    /// 常にマッチしない MockRule。
    struct NeverMatchRule;

    impl Rule for NeverMatchRule {
        fn name(&self) -> &str {
            "never-match"
        }

        fn check(&self, _event: &SyscallEvent) -> Option<RuleMatch> {
            None
        }
    }

    #[test]
    fn analyze_no_rules_returns_none() {
        let detector = Detector::new(vec![]);
        let event = dummy_event();
        assert!(detector.analyze(&event).is_none());
    }

    #[test]
    fn analyze_single_rule_match() {
        let detector = Detector::new(vec![Box::new(MockRule::new(
            "test-rule",
            AlertLevel::Warn,
            "suspicious",
        ))]);
        let event = dummy_event();
        let alert = detector.analyze(&event).expect("should match");
        assert_eq!(alert.level, AlertLevel::Warn);
        assert_eq!(alert.rule_name, "test-rule");
        assert_eq!(alert.message, "suspicious");
    }

    #[test]
    fn analyze_multiple_rules_returns_most_severe() {
        let detector = Detector::new(vec![
            Box::new(MockRule::new("info-rule", AlertLevel::Info, "info msg")),
            Box::new(MockRule::new(
                "critical-rule",
                AlertLevel::Critical,
                "critical msg",
            )),
            Box::new(MockRule::new("warn-rule", AlertLevel::Warn, "warn msg")),
        ]);
        let event = dummy_event();
        let alert = detector.analyze(&event).expect("should match");
        assert_eq!(alert.level, AlertLevel::Critical);
        assert_eq!(alert.rule_name, "critical-rule");
    }

    #[test]
    fn analyze_all_returns_all_matches() {
        let detector = Detector::new(vec![
            Box::new(MockRule::new("info-rule", AlertLevel::Info, "info msg")),
            Box::new(NeverMatchRule),
            Box::new(MockRule::new(
                "critical-rule",
                AlertLevel::Critical,
                "critical msg",
            )),
            Box::new(MockRule::new("warn-rule", AlertLevel::Warn, "warn msg")),
        ]);
        let event = dummy_event();
        let alerts = detector.analyze_all(&event);
        assert_eq!(alerts.len(), 3);
        let names: Vec<&str> = alerts.iter().map(|a| a.rule_name.as_str()).collect();
        assert!(names.contains(&"info-rule"));
        assert!(names.contains(&"critical-rule"));
        assert!(names.contains(&"warn-rule"));
    }

    #[test]
    fn analyze_all_no_rules_returns_empty() {
        let detector = Detector::new(vec![]);
        let event = dummy_event();
        assert!(detector.analyze_all(&event).is_empty());
    }

    #[test]
    fn analyze_rules_no_match_returns_none() {
        let detector = Detector::new(vec![Box::new(NeverMatchRule), Box::new(NeverMatchRule)]);
        let event = dummy_event();
        assert!(detector.analyze(&event).is_none());
    }
}
