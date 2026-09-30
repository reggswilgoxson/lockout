//! `lockout.toml`. Every key is optional.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lockout_ai_core::guard::OnError;
use lockout_ai_core::{Action, Allow, Audience, Category, Rules, SegmentConfig};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub audience: Option<Audience>,
    /// Audience table file. Default: `audience.toml` next to this config, if it exists.
    pub audience_table: Option<PathBuf>,
    pub jev: JevConfig,
    /// Your identifier formats, e.g. `employee_id = 'E\d{6}'`. Matches are `employee_ref`.
    pub identifiers: BTreeMap<String, String>,
    pub allow: AllowConfig,
    #[serde(rename = "override")]
    pub overrides: BTreeMap<Category, Action>,
    pub segment: SegmentOverride,
    /// Directory relative paths are resolved against (the config file's).
    #[serde(skip)]
    pub dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JevConfig {
    /// Environment variable holding the API key.
    pub api_key_env: String,
    /// Environment variable holding the endpoint URL (used when `url` is unset).
    pub url_env: String,
    /// Full endpoint URL. There is deliberately no built-in default: see crates/lockout/src/jev/API.md.
    pub url: Option<String>,
    pub model: String,
    /// Header carrying the key. `Authorization` sends `Bearer <key>`; any other header sends the bare key.
    pub api_key_header: String,
    pub timeout_ms: u64,
    pub max_inflight: usize,
    /// Stop reading input while this many bytes wait for verdicts.
    pub max_buffer: usize,
    pub on_error: OnError,
}

impl Default for JevConfig {
    fn default() -> Self {
        JevConfig {
            api_key_env: "JEV_API_KEY".into(),
            url_env: "JEV_URL".into(),
            url: None,
            model: "jev".into(),
            api_key_header: "Authorization".into(),
            timeout_ms: 1200,
            max_inflight: 4,
            max_buffer: 16 * 1024,
            on_error: OnError::Block,
        }
    }
}

/// Where Jev is and how to reach it, once the key and URL are known.
#[derive(Clone, Debug)]
pub struct JevSettings {
    pub url: String,
    pub api_key: String,
    pub model: String,
    pub api_key_header: String,
    pub timeout_ms: u64,
}

impl JevConfig {
    /// `Ok(None)` when no key is set (local mode). An error when a key is set
    /// but no endpoint is, so data is never sent to a guessed host.
    pub fn settings(&self) -> Result<Option<JevSettings>, String> {
        let key = std::env::var(&self.api_key_env).ok().filter(|k| !k.trim().is_empty());
        let Some(api_key) = key else { return Ok(None) };
        let url = self
            .url
            .clone()
            .or_else(|| std::env::var(&self.url_env).ok())
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "{} is set but no Jev endpoint is: set {} or [jev] url in lockout.toml",
                    self.api_key_env, self.url_env
                )
            })?;
        if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost"))
        {
            return Err(format!("Jev endpoint must use https: {url}"));
        }
        Ok(Some(JevSettings {
            url,
            api_key,
            model: self.model.clone(),
            api_key_header: self.api_key_header.clone(),
            timeout_ms: self.timeout_ms,
        }))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowConfig {
    pub emails: Vec<String>,
    pub domains: Vec<String>,
    pub phones: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SegmentOverride {
    pub first_min: Option<usize>,
    pub min: Option<usize>,
    pub max: Option<usize>,
    pub overlap: Option<usize>,
}

impl Config {
    /// Loads `path`, or `./lockout.toml` if it exists, or the defaults.
    pub fn load(path: Option<&Path>) -> Result<Config, String> {
        let default = Path::new("lockout.toml");
        let path = match path {
            Some(p) => p,
            None if default.exists() => default,
            None => return Ok(Config::default()),
        };
        let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut config: Config = toml::from_str(&src).map_err(|e| format!("{}: {e}", path.display()))?;
        config.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(config)
    }

    /// The built-in rules with the audience table applied, if there is one.
    pub fn rules(&self) -> Result<Rules, String> {
        let mut rules = Rules::builtin();
        let path = match &self.audience_table {
            Some(p) => Some(self.dir.join(p)),
            None => Some(self.dir.join("audience.toml")).filter(|p| p.exists()),
        };
        if let Some(path) = path {
            let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            rules.apply_table_source(&src).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(rules)
    }

    pub fn allow(&self) -> Allow {
        Allow {
            emails: self.allow.emails.clone(),
            domains: self.allow.domains.clone(),
            phones: self.allow.phones.clone(),
        }
    }

    pub fn identifiers(&self) -> Result<Vec<(String, Regex)>, String> {
        self.identifiers
            .iter()
            .map(|(name, pattern)| {
                Regex::new(pattern).map(|re| (name.clone(), re)).map_err(|e| format!("identifiers.{name}: {e}"))
            })
            .collect()
    }

    pub fn segment(&self) -> SegmentConfig {
        let d = SegmentConfig::default();
        let s = &self.segment;
        SegmentConfig {
            first_min: s.first_min.unwrap_or(d.first_min),
            min: s.min.unwrap_or(d.min),
            max: s.max.unwrap_or(d.max),
            overlap: s.overlap.unwrap_or(d.overlap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_example() {
        let c: Config = toml::from_str(
            r#"
            audience = "site"
            [jev]
            api_key_env = "JEV_API_KEY"
            on_error = "block"
            [identifiers]
            employee_id = 'E\d{6}'
            claim_number = 'WC-\d{4}-\d{5}'
            [allow]
            emails = ["safety@yourco.com"]
            phones = ["+1 800 555 0100"]
            [override]
            fault_or_discipline = "block"
            "#,
        )
        .unwrap();
        assert_eq!(c.audience, Some(Audience::Site));
        assert_eq!(c.identifiers().unwrap().len(), 2);
        assert_eq!(c.overrides[&Category::FaultOrDiscipline], Action::Block);
    }

    #[test]
    fn the_shipped_audience_table_is_valid() {
        let mut rules = Rules::builtin();
        rules.apply_table_source(include_str!("../../../audience.toml")).unwrap();
    }

    #[test]
    fn rejects_typos() {
        assert!(toml::from_str::<Config>("audiance = \"site\"").is_err());
        assert!(toml::from_str::<Config>("[override]\ncontacts = \"off\"").is_err());
    }
}
