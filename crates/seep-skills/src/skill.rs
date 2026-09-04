//! Skills: runbooks the agent can consult.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The `skill.toml` manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    /// One line, loaded into every prompt. This is what the agent matches on, so
    /// it should say when to use the skill, not just what it is.
    pub description: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub author: String,
    /// Phrases that should surface this skill. Matching is substring-based on
    /// purpose: an operator typing "web tier is slow" should reach a skill whose
    /// keyword is "web tier" without anyone configuring a regex.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Tools this skill expects to exist. A skill that needs `kubectl` on a host
    /// without it is hidden rather than offered and then failed.
    #[serde(default)]
    pub requires_tools: Vec<String>,
    /// Host features this skill needs, e.g. `docker`, `systemd`.
    #[serde(default)]
    pub requires_features: Vec<String>,
    /// Environments this skill applies to. Empty means all.
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_version() -> String {
    "1.0.0".into()
}
fn default_true() -> bool {
    true
}

/// A loaded skill.
#[derive(Debug, Clone)]
pub struct Skill {
    pub manifest: SkillManifest,
    pub dir: PathBuf,
    /// The `SKILL.md` body, loaded lazily.
    body: Option<String>,
}

impl Skill {
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// The single line included in every prompt.
    pub fn summary(&self) -> String {
        format!("{} — {}", self.manifest.name, self.manifest.description)
    }

    /// The full body, read from disk on first use.
    pub fn body(&mut self) -> &str {
        if self.body.is_none() {
            let path = self.dir.join("SKILL.md");
            self.body = Some(std::fs::read_to_string(&path).unwrap_or_else(|_| {
                format!(
                    "(no SKILL.md found for '{}'; only its description is available)",
                    self.manifest.name
                )
            }));
        }
        self.body.as_deref().unwrap_or_default()
    }

    /// How well this skill matches a query, in `[0, 1]`. Zero means no match.
    pub fn relevance(&self, query: &str) -> f32 {
        let query = query.to_lowercase();
        let mut best = 0.0f32;

        for keyword in &self.manifest.keywords {
            let keyword = keyword.to_lowercase();
            if query.contains(&keyword) {
                // A longer matched phrase is a stronger signal than a single word.
                let strength = (keyword.split_whitespace().count() as f32 / 3.0).min(1.0);
                best = best.max(0.6 + strength * 0.4);
            }
        }

        // The name itself is a keyword, with hyphens treated as spaces so
        // "restart-web-tier" is reachable by typing "restart web tier".
        let spelled = self.manifest.name.replace(['-', '_'], " ").to_lowercase();
        if query.contains(&spelled) {
            best = best.max(0.95);
        }

        if best == 0.0 {
            // Fall back to term overlap with the description.
            let terms: Vec<&str> = query
                .split_whitespace()
                .filter(|t| t.len() > 3)
                .collect();
            if !terms.is_empty() {
                let description = self.manifest.description.to_lowercase();
                let hits = terms.iter().filter(|t| description.contains(**t)).count();
                if hits > 0 {
                    best = (hits as f32 / terms.len() as f32) * 0.5;
                }
            }
        }
        best
    }

    /// Whether this host can actually run the skill.
    pub fn is_usable(&self, available_tools: &[String], features: &[String], env: Option<&str>) -> bool {
        if !self.manifest.enabled {
            return false;
        }
        for tool in &self.manifest.requires_tools {
            if !available_tools.iter().any(|t| t == tool) {
                return false;
            }
        }
        for feature in &self.manifest.requires_features {
            if !features.iter().any(|f| f == feature) {
                return false;
            }
        }
        if !self.manifest.environments.is_empty() {
            match env {
                Some(env) => {
                    if !self.manifest.environments.iter().any(|e| e.eq_ignore_ascii_case(env)) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// All installed skills.
#[derive(Debug, Clone, Default)]
pub struct SkillLibrary {
    skills: BTreeMap<String, Skill>,
    /// Directories that failed to load, reported rather than silently ignored.
    problems: Vec<String>,
}

impl SkillLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every skill under a directory.
    pub fn load(dir: &Path) -> Self {
        let mut library = Self::new();
        if !dir.exists() {
            return library;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                library.problems.push(format!("could not read {}: {}", dir.display(), e));
                return library;
            }
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("skill.toml");
            if !manifest_path.exists() {
                continue;
            }
            match std::fs::read_to_string(&manifest_path) {
                Ok(text) => match toml::from_str::<SkillManifest>(text.trim_start_matches('\u{feff}')) {
                    Ok(manifest) => {
                        library
                            .skills
                            .insert(manifest.name.clone(), Skill { manifest, dir: path, body: None });
                    }
                    Err(e) => library
                        .problems
                        .push(format!("{}: {}", manifest_path.display(), e)),
                },
                Err(e) => library
                    .problems
                    .push(format!("{}: {}", manifest_path.display(), e)),
            }
        }
        library
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Skill> {
        self.skills.get_mut(name)
    }

    pub fn all(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values()
    }

    pub fn insert(&mut self, skill: Skill) {
        self.skills.insert(skill.manifest.name.clone(), skill);
    }

    /// Skills this host can use, as one-line summaries for the prompt.
    pub fn summaries(&self, available_tools: &[String], features: &[String], env: Option<&str>) -> Vec<String> {
        self.skills
            .values()
            .filter(|s| s.is_usable(available_tools, features, env))
            .map(|s| s.summary())
            .collect()
    }

    /// The most relevant usable skills for a query, best first.
    ///
    /// Returns at most `limit` and only those above a floor, because pulling in
    /// a marginally-related runbook costs context and misleads the agent.
    pub fn match_query(
        &self,
        query: &str,
        available_tools: &[String],
        features: &[String],
        env: Option<&str>,
        limit: usize,
    ) -> Vec<&Skill> {
        let mut scored: Vec<(f32, &Skill)> = self
            .skills
            .values()
            .filter(|s| s.is_usable(available_tools, features, env))
            .map(|s| (s.relevance(query), s))
            .filter(|(score, _)| *score >= 0.3)
            .collect();

        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Stable tie-break so the same query always yields the same set.
                .then_with(|| a.1.manifest.name.cmp(&b.1.manifest.name))
        });
        scored.into_iter().take(limit).map(|(_, s)| s).collect()
    }

    /// The starter skill written at `seep init`, as an example to copy.
    pub fn example_manifest() -> String {
        r#"# A SeeP skill: operational knowledge the agent can consult.
#
# Only `description` is loaded into every prompt. The body in SKILL.md is read
# on demand when this skill matches what is being asked — so keep the
# description precise about *when* to use this, and put the detail in the body.

name        = "restart-web-tier"
description = "Safely cycle the web tier one node at a time, draining each from the load balancer first."
version     = "1.0.0"

# Phrases that should surface this skill.
keywords = ["restart web", "cycle web tier", "web tier", "rolling restart"]

# The skill is hidden on hosts that cannot run it, rather than offered and failed.
requires_tools    = ["svc_restart", "http_health"]
requires_features = ["svc"]

# Restrict to specific environments. Omit for all.
# environments = ["prod"]
"#
        .to_string()
    }

    pub fn example_body() -> String {
        r#"# Restarting the web tier

## When to use this

The web tier needs cycling — after a config change, a memory leak, or a deploy
that did not take effect. Do **not** use this to fix an unknown problem; find out
what is wrong first.

## Before you start

Check that more than one node is healthy. Restarting the last healthy node is an
outage, not a remediation.

## Procedure

1. List the web nodes and confirm at least two are `online`.
2. For each node, one at a time:
   a. Drain it from the load balancer and wait for connections to fall to zero.
   b. `svc_reload nginx` first — if the change was configuration, a reload is
      enough and costs nothing.
   c. Only if a reload is insufficient, `svc_restart nginx`.
   d. Check `http_health` against the node directly before returning it to the pool.
   e. Return it to the load balancer and wait for it to pass health checks.
3. Do not proceed to the next node until the previous one is serving traffic.

## If something goes wrong

Stop. A half-cycled tier still serves traffic; a fully cycled broken one does not.
Report which node failed and what it said, and leave the remaining nodes alone.
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn manifest(name: &str, keywords: &[&str]) -> SkillManifest {
        SkillManifest {
            name: name.into(),
            description: format!("does {} things", name),
            version: "1.0.0".into(),
            author: String::new(),
            keywords: keywords.iter().map(|k| k.to_string()).collect(),
            requires_tools: vec![],
            requires_features: vec![],
            environments: vec![],
            enabled: true,
        }
    }

    fn skill(name: &str, keywords: &[&str]) -> Skill {
        Skill { manifest: manifest(name, keywords), dir: PathBuf::from("."), body: None }
    }

    fn library(skills: Vec<Skill>) -> SkillLibrary {
        let mut library = SkillLibrary::new();
        for skill in skills {
            library.insert(skill);
        }
        library
    }

    #[test]
    fn a_keyword_match_surfaces_the_skill() {
        let library = library(vec![skill("restart-web-tier", &["cycle web tier"])]);
        let matched = library.match_query("please cycle web tier now", &[], &[], None, 5);
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn a_hyphenated_name_is_reachable_by_typing_it_with_spaces() {
        let library = library(vec![skill("restart-web-tier", &[])]);
        let matched = library.match_query("can you restart web tier", &[], &[], None, 5);
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn an_unrelated_query_matches_nothing() {
        // A marginally-related runbook costs context and misleads the agent.
        let library = library(vec![skill("restart-web-tier", &["cycle web tier"])]);
        assert!(library
            .match_query("what is the weather", &[], &[], None, 5)
            .is_empty());
    }

    #[test]
    fn longer_keyword_phrases_score_higher() {
        let generic = skill("generic", &["web"]);
        let specific = skill("specific", &["restart the web tier"]);
        let query = "restart the web tier please";
        assert!(specific.relevance(query) > generic.relevance(query));
    }

    #[test]
    fn skills_requiring_absent_tools_are_hidden() {
        // Offering a skill that cannot run wastes a turn discovering that.
        let mut skill = skill("k8s-rollback", &["rollback"]);
        skill.manifest.requires_tools = vec!["k8s_rollback".into()];

        assert!(!skill.is_usable(&[], &[], None));
        assert!(skill.is_usable(&["k8s_rollback".to_string()], &[], None));
    }

    #[test]
    fn skills_requiring_absent_features_are_hidden() {
        let mut skill = skill("compose-restart", &["compose"]);
        skill.manifest.requires_features = vec!["docker".into()];
        assert!(!skill.is_usable(&[], &[], None));
        assert!(skill.is_usable(&[], &["docker".to_string()], None));
    }

    #[test]
    fn environment_restrictions_are_enforced() {
        let mut skill = skill("prod-only", &["prod thing"]);
        skill.manifest.environments = vec!["prod".into()];
        assert!(skill.is_usable(&[], &[], Some("prod")));
        assert!(!skill.is_usable(&[], &[], Some("dev")));
        assert!(!skill.is_usable(&[], &[], None), "unknown environment is not prod");
    }

    #[test]
    fn a_disabled_skill_is_never_offered() {
        let mut skill = skill("off", &["off"]);
        skill.manifest.enabled = false;
        assert!(!skill.is_usable(&[], &[], None));
    }

    #[test]
    fn matching_is_limited_and_deterministic() {
        let skills: Vec<Skill> = (0..10)
            .map(|i| skill(&format!("skill-{}", i), &["restart"]))
            .collect();
        let library = library(skills);
        let first = library.match_query("restart", &[], &[], None, 3);
        let second = library.match_query("restart", &[], &[], None, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(
            first.iter().map(|s| s.name()).collect::<Vec<_>>(),
            second.iter().map(|s| s.name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn only_descriptions_are_loaded_for_the_prompt() {
        // The body must stay off the prompt until the skill is actually relevant.
        let library = library(vec![skill("a", &["x"]), skill("b", &["y"])]);
        let summaries = library.summaries(&[], &[], None);
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|s| s.len() < 200));
    }

    #[test]
    fn loading_reads_manifests_from_disk() {
        let dir = tempdir().unwrap();
        let skill_dir = dir.path().join("restart-web-tier");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("skill.toml"), SkillLibrary::example_manifest()).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), SkillLibrary::example_body()).unwrap();

        let mut library = SkillLibrary::load(dir.path());
        assert_eq!(library.len(), 1);
        assert!(library.problems().is_empty());

        let skill = library.get_mut("restart-web-tier").unwrap();
        assert!(skill.body().contains("one at a time"));
    }

    #[test]
    fn a_malformed_manifest_is_reported_rather_than_silently_skipped() {
        let dir = tempdir().unwrap();
        let skill_dir = dir.path().join("broken");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("skill.toml"), "this is not = valid toml [[[").unwrap();

        let library = SkillLibrary::load(dir.path());
        assert_eq!(library.len(), 0);
        assert_eq!(library.problems().len(), 1);
        assert!(library.problems()[0].contains("broken"));
    }

    #[test]
    fn directories_without_a_manifest_are_ignored_quietly() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("not-a-skill")).unwrap();
        let library = SkillLibrary::load(dir.path());
        assert_eq!(library.len(), 0);
        assert!(library.problems().is_empty());
    }

    #[test]
    fn a_missing_skills_directory_is_not_an_error() {
        let library = SkillLibrary::load(Path::new("/definitely/not/here"));
        assert!(library.is_empty());
        assert!(library.problems().is_empty());
    }

    #[test]
    fn a_missing_body_degrades_to_a_readable_note() {
        let dir = tempdir().unwrap();
        let mut skill = skill("no-body", &[]);
        skill.dir = dir.path().to_path_buf();
        assert!(skill.body().contains("no SKILL.md"));
    }

    #[test]
    fn the_shipped_example_manifest_parses() {
        let manifest: SkillManifest =
            toml::from_str(&SkillLibrary::example_manifest()).unwrap();
        assert_eq!(manifest.name, "restart-web-tier");
        assert!(!manifest.keywords.is_empty());
    }
}
