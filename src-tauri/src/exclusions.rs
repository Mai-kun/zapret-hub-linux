//! Named exclusion groups kept in `data/exclusions.toml`. A group's `apps` are matched against
//! running processes and their open local ports go into the nftables bypass sets, so the
//! sockets of the excluded programs never reach nfqws2 — never the processes themselves into a
//! cgroup: a cgroup mark passes to every child the excluded process ever starts. The enabled
//! groups' domains, IPs, apps and ports are also derived into the flat exclude lists of zapret2
//! and the settings' ports, so zapret2 and the nftables queue see the same exclusions.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use specta::Type;

/// `data/exclusions.toml` next to the exe: portable, like everything else (spec 4.3).
pub const FILE_NAME: &str = "exclusions.toml";

/// The groups created when there are no exclusions yet.
pub const DEFAULT_NAME_APPS: &str = "🛡️ Программы без zapret";

pub const DEFAULT_NAME_RU: &str = "🇷🇺 Российские сайты и сервисы";
pub const DEFAULT_DOMAINS_RU: &[&str] = &[
    "gosuslugi.ru", "sberbank.ru", "tbank.ru", "tinkoff.ru", "vtb.ru",
    "alfabank.ru", "avito.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru",
    "yandex.ru", "ya.ru", "vk.com", "mail.ru", "rutube.ru"
];

pub const DEFAULT_NAME_LOCAL: &str = "🏠 Локальные и приватные сети";
pub const DEFAULT_IPS_LOCAL: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"];

pub const DEFAULT_NAME_P2P: &str = "⚡ Торренты и P2P-порты";
pub const DEFAULT_PORTS_P2P: &[&str] = &["51413", "6881-6889"];

/// Flat exclude lists of zapret2, derived from the enabled groups.
pub const LIST_DOMAINS: &str = "list-exclude-user.txt";
pub const LIST_IPS: &str = "ipset-exclude-user.txt";
pub const LIST_APPS: &str = "list-apps-user.txt";

/// One named group of exclusions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ExclusionRule {
    pub name: String,
    pub enabled: bool,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub ports: Vec<String>,
    #[serde(default)]
    pub apps: Vec<String>,
}

/// All groups, loaded from or saved to {FILE_NAME}.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionRules {
    pub path: PathBuf,
    pub rules: Vec<ExclusionRule>,
}

impl ExclusionRules {
    /// Reads {FILE_NAME}; a missing or empty file becomes the single default group, so an app
    /// without any exclusions still bypasses `opencode` and `opencode-cli`. A toml written by an
    /// older version (no `apps` key) reads fine thanks to `#[serde(default)]`.
    pub fn load(paths: &crate::state::Paths) -> anyhow::Result<Self> {
        let path = paths.data().join(FILE_NAME);
        let rules = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let rules: Vec<ExclusionRule> = if text.trim().is_empty() {
                    Vec::new()
                } else {
                    let value: toml::Value = toml::from_str(&text)
                        .with_context(|| format!("{} is damaged", path.display()))?;
                    let array = value
                        .as_table()
                        .and_then(|table| table.get("rules"))
                        .and_then(|rules| rules.as_array())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "{} is damaged: expected a top-level `[[rules]]` array of tables",
                                path.display()
                            )
                        })?;
                    array
                        .iter()
                        .map(|entry| {
                            let text = toml::to_string(entry)
                                .map_err(|err| anyhow::anyhow!("{err}"))?;
                            toml::from_str(&text).map_err(|err| anyhow::anyhow!("{err}"))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?
                };
                if rules.is_empty() {
                    default_rules()
                } else {
                    rules
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => default_rules(),
            Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
        };
        Ok(Self { path, rules })
    }

    /// Atomic save: a crash mid-write leaves the old file, not half of the new.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        #[derive(serde::Serialize)]
        struct RulesFile<'a> {
            rules: &'a Vec<ExclusionRule>,
        }
        let text = toml::to_string_pretty(&RulesFile { rules: &self.rules })
            .with_context(|| "cannot serialize exclusions")?;
        let temp = self.path.with_extension("toml.tmp");
        std::fs::write(&temp, &text)
            .with_context(|| format!("cannot write {}", temp.display()))?;
        std::fs::rename(&temp, &self.path)
            .with_context(|| format!("cannot replace {}", self.path.display()))?;
        Ok(())
    }

    /// The apps of the enabled groups, de-duplicated, in the rules' order.
    pub fn enabled_apps(&self) -> Vec<String> {
        self.enabled_entries(|rule| &rule.apps)
    }

    /// The ports of the enabled groups, de-duplicated, in the rules' order.
    pub fn enabled_ports(&self) -> Vec<String> {
        self.enabled_entries(|rule| &rule.ports)
    }

    /// The domains of the enabled groups, de-duplicated.
    pub fn enabled_domains(&self) -> Vec<String> {
        self.enabled_entries(|rule| &rule.domains)
    }

    /// The IPs of the enabled groups, de-duplicated.
    pub fn enabled_ips(&self) -> Vec<String> {
        self.enabled_entries(|rule| &rule.ips)
    }

    fn enabled_entries(&self, pick: fn(&ExclusionRule) -> &Vec<String>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            for entry in pick(rule) {
                if !out.iter().any(|had| had.eq_ignore_ascii_case(entry)) {
                    out.push(entry.clone());
                }
            }
        }
        out
    }

    /// The group named {DEFAULT_NAME_APPS}, creating it at the end when missing.
    #[allow(dead_code)] // the CLI talks to it through JSON; the app edits rules wholesale
    pub fn default_group(&mut self) -> &mut ExclusionRule {
        if let Some(position) = self
            .rules
            .iter()
            .position(|rule| rule.name == DEFAULT_NAME_APPS)
        {
            return &mut self.rules[position];
        }
        self.rules.push(default_rule_apps());
        self.rules.last_mut().unwrap()
    }
}

pub(crate) fn default_rules() -> Vec<ExclusionRule> {
    vec![
        ExclusionRule {
            name: DEFAULT_NAME_RU.to_owned(),
            enabled: true,
            domains: DEFAULT_DOMAINS_RU.iter().map(|d| d.to_string()).collect(),
            ips: Vec::new(),
            ports: Vec::new(),
            apps: Vec::new(),
        },
        ExclusionRule {
            name: DEFAULT_NAME_LOCAL.to_owned(),
            enabled: true,
            domains: Vec::new(),
            ips: DEFAULT_IPS_LOCAL.iter().map(|i| i.to_string()).collect(),
            ports: Vec::new(),
            apps: Vec::new(),
        },
        ExclusionRule {
            name: DEFAULT_NAME_P2P.to_owned(),
            enabled: false,
            domains: Vec::new(),
            ips: Vec::new(),
            ports: DEFAULT_PORTS_P2P.iter().map(|p| p.to_string()).collect(),
            apps: Vec::new(),
        },
        default_rule_apps(),
    ]
}

fn default_rule_apps() -> ExclusionRule {
    ExclusionRule {
        name: DEFAULT_NAME_APPS.to_owned(),
        // Off with no apps: the user adds what they really need to bypass. An app excluded by
        // default (the agent `opencode` once shipped here) carries the exclusion onto everything
        // it starts — the app itself and its test checks included.
        enabled: false,
        domains: Vec::new(),
        ips: Vec::new(),
        ports: Vec::new(),
        apps: Vec::new(),
    }
}

/// Every line non-blank and not a comment: what one exclude list file holds.
fn list_lines(entries: &[String]) -> String {
    let mut text = String::new();
    for entry in entries {
        let trimmed = entry.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            text.push_str(trimmed);
            text.push('\n');
        }
    }
    text
}

/// Derives the flat zapret2 lists from the enabled groups and writes them into `lists_dir`.
pub fn write_derived_lists(lists_dir: &Path, rules: &ExclusionRules) -> anyhow::Result<()> {
    std::fs::create_dir_all(lists_dir).with_context(|| {
        format!(
            "cannot create the lists folder {}",
            lists_dir.display()
        )
    })?;
    for (name, entries) in [
        (LIST_DOMAINS, rules.enabled_domains()),
        (LIST_IPS, rules.enabled_ips()),
        (LIST_APPS, rules.enabled_apps()),
    ] {
        std::fs::write(lists_dir.join(name), list_lines(&entries))
            .with_context(|| format!("cannot write {}", lists_dir.join(name).display()))?;
    }
    Ok(())
}

/// Matches one process name against one exclusion app, case-insensitive: `opencode` matches
/// `opencode`, `opencode-cli` and `/usr/bin/opencode`.
pub fn app_matches(name: &str, app: &str) -> bool {
    let name = name.to_lowercase();
    let app = app.to_lowercase();
    !name.is_empty() && !app.is_empty() && (name.contains(&app) || app.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn missing_file_gives_all_default_groups() {
        let dir = tmp_dir();
        let paths = crate::state::Paths {
            exe_dir: dir.path().to_path_buf(),
        };
        let rules = ExclusionRules::load(&paths).unwrap();
        assert_eq!(rules.rules.len(), 4);
        assert!(rules.rules.iter().any(|r| r.name == DEFAULT_NAME_RU));
        assert!(rules.rules.iter().any(|r| r.name == DEFAULT_NAME_APPS));
    }

    #[test]
    fn empty_file_gives_all_default_groups_too() {
        let dir = tmp_dir();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, "").unwrap();
        let paths = crate::state::Paths {
            exe_dir: dir.path().to_path_buf(),
        };
        let rules = ExclusionRules::load(&paths).unwrap();
        assert_eq!(rules.rules.len(), 4);
    }

    #[test]
    fn old_toml_without_apps_reads_with_empty_apps() {
        let dir = tmp_dir();
        let paths = crate::state::Paths {
            exe_dir: dir.path().to_path_buf(),
        };
        std::fs::create_dir_all(paths.data()).unwrap();
        std::fs::write(paths.data().join(FILE_NAME), r#"[[rules]]
name = "mine"
enabled = true
domains = ["example.com"]
ips = []
ports = ["443"]
"#)
        .unwrap();
        let rules = ExclusionRules::load(&paths).unwrap();
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].apps, Vec::<String>::new());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tmp_dir();
        let paths = crate::state::Paths {
            exe_dir: dir.path().to_path_buf(),
        };
        let mut rules = ExclusionRules::load(&paths).unwrap();
        rules.rules.push(ExclusionRule {
            name: "mine".into(),
            enabled: false,
            domains: vec!["discord.com".into()],
            ips: Vec::new(),
            ports: vec!["51413".into()],
            apps: vec!["qbittorrent".into()],
        });
        rules.save().unwrap();
        let loaded = ExclusionRules::load(&paths).unwrap();
        assert_eq!(loaded.rules, rules.rules);
        assert!(loaded.path.exists());
        let text = std::fs::read_to_string(&loaded.path).unwrap();
        assert!(text.contains("\"qbittorrent\""));
        assert!(text.contains("name = \"mine\""));
    }

    #[test]
    fn enabled_lists_skip_disabled_rules_and_deduplicate() {
        let rules = ExclusionRules {
            path: PathBuf::new(),
            rules: vec![
                ExclusionRule { name: "a".into(), enabled: true, domains: vec!["d.com".into()], ips: vec![], ports: vec![], apps: vec!["opencode".into()] },
                ExclusionRule { name: "b".into(), enabled: false, domains: vec!["d.com".into()], ips: vec!["10.0.0.1".into()], ports: vec![], apps: vec!["opencode".into()] },
                ExclusionRule {
                    name: "c".into(),
                    enabled: true,
                    domains: vec!["D.COM".into()],
                    ips: vec![],
                    ports: vec!["443".to_string()],
                    apps: vec!["Opencode".into()],
                },
            ],
        };
        assert_eq!(rules.enabled_domains(), vec!["d.com".to_owned()]);
        assert_eq!(rules.enabled_ips(), Vec::<String>::new());
        assert_eq!(rules.enabled_ports(), vec!["443".to_owned()]);
        assert_eq!(rules.enabled_apps(), vec!["opencode".to_owned()]);
    }

    #[test]
    fn app_matching_is_case_insensitive_and_matches_paths() {
        assert!(app_matches("opencode", "opencode"));
        assert!(app_matches("opencode-cli", "opencode"));
        assert!(app_matches("/usr/bin/opencode", "opencode"));
        assert!(app_matches("OPENCODE-CLI", "opencode"));
        assert!(!app_matches("firefox", "opencode"));
        assert!(!app_matches("", "opencode"));
        assert!(!app_matches("opencode", ""));
    }

    #[test]
    fn default_group_is_created_when_missing() {
        let mut rules = ExclusionRules {
            path: PathBuf::new(),
            rules: vec![ExclusionRule { name: "other".into(), enabled: true, domains: Vec::new(), ips: Vec::new(), ports: Vec::new(), apps: Vec::new() }],
        };
        let group = rules.default_group();
        assert_eq!(group.name, DEFAULT_NAME_APPS);
        // Off and empty by default: the user adds the apps they really need to bypass.
        assert!(!group.enabled);
        assert_eq!(group.apps, Vec::<String>::new());
        assert!(rules.rules.iter().any(|rule| rule.name == DEFAULT_NAME_APPS));
    }
}

