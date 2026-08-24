//! Home Assistant add-on options.
//!
//! The Supervisor writes the operator's choices to `/data/options.json` before
//! start, taking the keys from the `schema` in `addon/config.yaml`. Outside the
//! add-on the file is absent and every field falls back to the value the command
//! line already implies, so one code path serves both installations.

use std::path::{Path, PathBuf};

/// Where the Supervisor writes the options.
pub const OPTIONS_PATH: &str = "/data/options.json";

/// Where the config lives when nothing says otherwise.
pub const DEFAULT_CONFIG: &str = "/config/guestpass.yaml";

/// The add-on's options. Every field carries a default, so a missing key is a
/// value rather than an error.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct Options {
    /// The guestpass YAML file to load.
    pub policy_file: PathBuf,
    /// Verbosity, in the Supervisor's vocabulary. [`Options::directive`] maps it
    /// to `tracing`'s.
    pub log_level: Box<str>,
    /// Print the LaTeX pass document to the log at startup. An add-on install
    /// has no shell, so the log is where a document can be collected from.
    pub emit_tex: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy_file: PathBuf::from(DEFAULT_CONFIG),
            log_level: "info".into(),
            emit_tex: false,
        }
    }
}

impl Options {
    /// Read the Supervisor's options.
    #[must_use]
    pub fn read() -> Self {
        Self::read_from(Path::new(OPTIONS_PATH))
    }

    /// Absence and malformation both yield the defaults. Refusing to start would
    /// leave the operator without the log that names the problem, and the file
    /// is written by the Supervisor rather than by hand.
    fn read_from(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_else(|e| {
            eprintln!("{}: {e}; continuing with defaults", path.display());
            Self::default()
        })
    }

    /// `log_level` in `tracing`'s spelling. Total: the schema constrains the
    /// input, and anything outside it reads as the default rather than as a
    /// filter that silently drops every event.
    #[must_use]
    pub fn directive(&self) -> &'static str {
        match self.log_level.as_ref() {
            "trace" => "trace",
            "debug" => "debug",
            "warning" | "warn" => "warn",
            "error" => "error",
            _ => "info",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn an_absent_options_file_is_the_default() {
        assert_eq!(
            Options::read_from(Path::new("/nonexistent/options.json")),
            Options::default()
        );
    }

    #[test]
    fn a_malformed_options_file_is_the_default() {
        let path = std::env::temp_dir().join(format!("gp-opt-{}.json", std::process::id()));
        std::fs::write(&path, "{not json").expect("write");
        assert_eq!(Options::read_from(&path), Options::default());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_supervisor_shape_parses() {
        let json = r#"{"policy_file":"/config/other.yaml","log_level":"warning","emit_tex":true}"#;
        let opts: Options = serde_json::from_str(json).expect("parses");
        assert_eq!(opts.policy_file, PathBuf::from("/config/other.yaml"));
        assert_eq!(opts.directive(), "warn");
        assert!(opts.emit_tex);
    }

    #[test]
    fn every_supervisor_level_maps_to_a_tracing_directive() {
        for level in ["trace", "debug", "info", "warning", "error"] {
            let opts = Options {
                log_level: level.into(),
                ..Options::default()
            };
            assert!(
                tracing_subscriber::EnvFilter::try_new(opts.directive()).is_ok(),
                "{level} produced an unusable filter"
            );
        }
    }

    /// Gate G7: the shipped add-on manifest and this struct describe the same
    /// options. A key added to one and not the other is a setting the operator
    /// can choose and the program ignores.
    #[test]
    fn the_shipped_addon_manifest_matches_this_struct() {
        #[derive(serde::Deserialize)]
        struct Manifest {
            options: Options,
            schema: BTreeMap<String, serde_yaml_ng::Value>,
        }

        let text = std::fs::read_to_string("addon/config.yaml").expect("addon/config.yaml");
        let manifest: Manifest = serde_yaml_ng::from_str(&text).expect("manifest parses");

        assert_eq!(
            manifest.options,
            Options::default(),
            "the manifest's defaults and this struct's defaults have diverged"
        );

        let declared: BTreeSet<&str> = manifest.schema.keys().map(String::as_str).collect();
        let known: BTreeSet<&str> = ["policy_file", "log_level", "emit_tex"].into();
        assert_eq!(
            declared, known,
            "the manifest schema and this struct differ"
        );
    }
}
