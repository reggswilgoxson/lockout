//! Categories, audiences and the rules that map one to the other.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What a finding is about. The names match `rules/ehs.toml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PrivacyCase,
    WorkerHealth,
    SubstanceTest,
    FaultOrDiscipline,
    OtherSpecial,
    PersonIdentity,
    EmployeeRef,
    Contact,
    GovernmentId,
    Financial,
}

impl Category {
    pub const ALL: [Category; 10] = [
        Category::PrivacyCase,
        Category::WorkerHealth,
        Category::SubstanceTest,
        Category::FaultOrDiscipline,
        Category::OtherSpecial,
        Category::PersonIdentity,
        Category::EmployeeRef,
        Category::Contact,
        Category::GovernmentId,
        Category::Financial,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::PrivacyCase => "privacy_case",
            Category::WorkerHealth => "worker_health",
            Category::SubstanceTest => "substance_test",
            Category::FaultOrDiscipline => "fault_or_discipline",
            Category::OtherSpecial => "other_special",
            Category::PersonIdentity => "person_identity",
            Category::EmployeeRef => "employee_ref",
            Category::Contact => "contact",
            Category::GovernmentId => "government_id",
            Category::Financial => "financial",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Category {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Category::ALL.into_iter().find(|c| c.as_str() == s).ok_or_else(|| format!("unknown category `{s}`"))
    }
}

/// Who will read the output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// The incident team, who may see names.
    Investigation,
    /// Workforce-wide bulletins and chatbots.
    #[default]
    Site,
    /// External reports, vendors, public copies.
    Public,
}

impl Audience {
    pub fn as_str(self) -> &'static str {
        match self {
            Audience::Investigation => "investigation",
            Audience::Site => "site",
            Audience::Public => "public",
        }
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Audience {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "investigation" => Ok(Audience::Investigation),
            "site" => Ok(Audience::Site),
            "public" => Ok(Audience::Public),
            _ => Err(format!("unknown audience `{s}` (expected investigation, site or public)")),
        }
    }
}

/// What happens to a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Off,
    Warn,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Off => "off",
            Action::Warn => "warn",
            Action::Block => "block",
        }
    }
}

impl FromStr for Action {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(Action::Off),
            "warn" => Ok(Action::Warn),
            "block" => Ok(Action::Block),
            _ => Err(format!("unknown action `{s}` (expected block, warn or off)")),
        }
    }
}

/// One category's entry in `rules/ehs.toml`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryRule {
    /// The question Jev is asked. `None` for local-only categories.
    pub question: Option<String>,
    pub citations: Vec<String>,
    pub investigation: Action,
    pub site: Action,
    pub public: Action,
    /// Jev probability at or above which a `block` category blocks.
    #[serde(default)]
    pub block_threshold: Option<f32>,
    /// Jev probability at or above which a finding is reported as a warning.
    #[serde(default)]
    pub warn_threshold: Option<f32>,
}

impl CategoryRule {
    pub fn action(&self, audience: Audience) -> Action {
        match audience {
            Audience::Investigation => self.investigation,
            Audience::Site => self.site,
            Audience::Public => self.public,
        }
    }
}

/// The parsed rules file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub version: u32,
    pub thresholds: Thresholds,
    pub categories: BTreeMap<Category, CategoryRule>,
}

/// Default Jev probability thresholds.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub block: f32,
    pub warn: f32,
}

/// One category's row in an audience table file. Every key is optional.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableRow {
    pub investigation: Option<Action>,
    pub site: Option<Action>,
    pub public: Option<Action>,
    pub block_threshold: Option<f32>,
    pub warn_threshold: Option<f32>,
}

/// An audience table: per category, what each audience gets, and optional
/// thresholds. Overrides the built-in rules; see `audience.toml`.
pub type AudienceTable = BTreeMap<Category, TableRow>;

fn check_thresholds(what: &str, block: f32, warn: f32) -> Result<(), String> {
    if !(0.0..=1.0).contains(&block) || !(0.0..=1.0).contains(&warn) {
        return Err(format!("{what}: thresholds must be between 0 and 1"));
    }
    if warn > block {
        return Err(format!("{what}: warn_threshold must not be above block_threshold"));
    }
    Ok(())
}

const BUILTIN_RULES: &str = include_str!("../rules/ehs.toml");

impl Rules {
    /// The rules shipped with lockout.
    pub fn builtin() -> Rules {
        Rules::parse(BUILTIN_RULES).expect("built-in rules/ehs.toml is valid")
    }

    pub fn parse(src: &str) -> Result<Rules, String> {
        let rules: Rules = toml::from_str(src).map_err(|e| e.to_string())?;
        if rules.version != 1 {
            return Err(format!("unsupported rules version {}", rules.version));
        }
        if let Some(missing) = Category::ALL.iter().find(|c| !rules.categories.contains_key(c)) {
            return Err(format!("rules are missing category `{missing}`"));
        }
        rules.validate()?;
        Ok(rules)
    }

    /// Parses an audience table file and applies it on top of these rules.
    pub fn apply_table_source(&mut self, src: &str) -> Result<(), String> {
        let table: AudienceTable = toml::from_str(src).map_err(|e| e.to_string())?;
        self.apply_table(&table)
    }

    pub fn apply_table(&mut self, table: &AudienceTable) -> Result<(), String> {
        for (category, row) in table {
            let rule = self.categories.get_mut(category).expect("every category has a rule");
            rule.investigation = row.investigation.unwrap_or(rule.investigation);
            rule.site = row.site.unwrap_or(rule.site);
            rule.public = row.public.unwrap_or(rule.public);
            rule.block_threshold = row.block_threshold.or(rule.block_threshold);
            rule.warn_threshold = row.warn_threshold.or(rule.warn_threshold);
        }
        self.validate()
    }

    fn validate(&self) -> Result<(), String> {
        check_thresholds("thresholds", self.thresholds.block, self.thresholds.warn)?;
        for c in Category::ALL {
            let (block, warn) = self.thresholds(c);
            check_thresholds(c.as_str(), block, warn)?;
        }
        Ok(())
    }

    /// (block, warn) thresholds for a category.
    pub fn thresholds(&self, category: Category) -> (f32, f32) {
        let rule = self.get(category);
        (rule.block_threshold.unwrap_or(self.thresholds.block), rule.warn_threshold.unwrap_or(self.thresholds.warn))
    }

    pub fn get(&self, category: Category) -> &CategoryRule {
        &self.categories[&category]
    }
}

/// Rules resolved for one audience, with any per-category overrides applied.
#[derive(Clone, Debug)]
pub struct Policy {
    rules: Rules,
    audience: Audience,
    overrides: BTreeMap<Category, Action>,
}

impl Policy {
    pub fn new(rules: Rules, audience: Audience, overrides: BTreeMap<Category, Action>) -> Policy {
        Policy { rules, audience, overrides }
    }

    pub fn audience(&self) -> Audience {
        self.audience
    }

    pub fn action(&self, category: Category) -> Action {
        self.overrides.get(&category).copied().unwrap_or_else(|| self.rules.get(category).action(self.audience))
    }

    pub fn citations(&self, category: Category) -> &[String] {
        &self.rules.get(category).citations
    }

    /// (block, warn) Jev probability thresholds for a category.
    pub fn thresholds(&self, category: Category) -> (f32, f32) {
        self.rules.thresholds(category)
    }

    /// The questions to ask Jev: every category that has one and is not `off`.
    pub fn questions(&self) -> Vec<(Category, String)> {
        Category::ALL
            .into_iter()
            .filter(|c| self.action(*c) != Action::Off)
            .filter_map(|c| self.rules.get(c).question.clone().map(|q| (c, q)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse_and_cover_every_category() {
        let rules = Rules::builtin();
        for c in Category::ALL {
            assert!(!rules.get(c).citations.is_empty(), "{c} has no citations");
        }
    }

    #[test]
    fn stricter_audiences_never_relax_a_category() {
        let rules = Rules::builtin();
        for c in Category::ALL {
            let r = rules.get(c);
            assert!(r.investigation <= r.site && r.site <= r.public, "{c} gets looser with a wider audience");
        }
    }

    #[test]
    fn audience_table_overrides_actions_and_thresholds() {
        let mut rules = Rules::builtin();
        rules
            .apply_table_source(
                "[worker_health]\ninvestigation = \"off\"\nblock_threshold = 0.9\n\n[contact]\nsite = \"warn\"\n",
            )
            .unwrap();
        assert_eq!(rules.get(Category::WorkerHealth).investigation, Action::Off);
        assert_eq!(rules.get(Category::WorkerHealth).site, Action::Block);
        assert_eq!(rules.thresholds(Category::WorkerHealth), (0.9, 0.5));
        assert_eq!(rules.get(Category::Contact).site, Action::Warn);
    }

    #[test]
    fn audience_table_rejects_mistakes() {
        for bad in [
            "[workers_health]\nsite = \"block\"",
            "[contact]\nsite = \"blocked\"",
            "[contact]\nsight = \"block\"",
            "[contact]\nwarn_threshold = 0.9\nblock_threshold = 0.5",
            "[contact]\nblock_threshold = 80",
        ] {
            assert!(Rules::builtin().apply_table_source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn questions_skip_off_and_local_only_categories() {
        let p = Policy::new(Rules::builtin(), Audience::Investigation, Default::default());
        let asked: Vec<Category> = p.questions().into_iter().map(|(c, _)| c).collect();
        assert!(asked.contains(&Category::WorkerHealth));
        assert!(!asked.contains(&Category::PersonIdentity)); // off for investigation
        assert!(!asked.contains(&Category::GovernmentId)); // local rules only
    }

    #[test]
    fn overrides_win() {
        let mut o = BTreeMap::new();
        o.insert(Category::FaultOrDiscipline, Action::Block);
        let p = Policy::new(Rules::builtin(), Audience::Site, o);
        assert_eq!(p.action(Category::FaultOrDiscipline), Action::Block);
        assert_eq!(p.action(Category::PersonIdentity), Action::Warn);
    }
}
