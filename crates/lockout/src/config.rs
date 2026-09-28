//! `lockout.toml`. Every key is optional.

use std::collections::BTreeMap;
use std::path::Path;

use lockout_ai_core::{Action, Allow, Audience, Category, SegmentConfig};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub audience: Option<Audience>,
    pub jev: JevConfig,
    /// Your identifier formats, e.g. `employee_id = 'E\d{6}'`. Matches are `employee_ref`.
    pub identifiers: BTreeMap<String, String>,
    pub allow: AllowConfig,
    #[serde(rename = "override")]
    pub overrides: BTreeMap<Category, Action>,
    pub segment: SegmentOverride,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JevConfig {
    pub api_key_env: String,
    pub on_error: OnError,
}

impl Default for JevConfig {
    fn default() -> Self {
        JevConfig { api_key_env: "JEV_API_KEY".into(), on_error: OnError::Block }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnError {
    Block,
    LocalOnly,
    Warn,
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
        toml::from_str(&src).map_err(|e| format!("{}: {e}", path.display()))
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
    fn rejects_typos() {
        assert!(toml::from_str::<Config>("audiance = \"site\"").is_err());
        assert!(toml::from_str::<Config>("[override]\ncontacts = \"off\"").is_err());
    }
}
