//! The mechanical gates over the source text (AGENTS.md G5, G6, G9, G11).
//!
//! Each gate is a pure function from a tree to findings, and findings
//! accumulate: one report names everything wrong, not the first thing. The
//! YAML gates parse into typed structs instead of grepping shapes out of text.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// One violated invariant, carrying where and what.
#[derive(Debug)]
pub struct Finding {
    pub gate: &'static str,
    pub place: String,
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.gate, self.place, self.detail)
    }
}

/// Every gate, accumulated. O(total bytes under `src/`) plus two YAML parses.
pub fn check_all(root: &Path) -> std::io::Result<Vec<Finding>> {
    let mut findings = banned_identifiers(&root.join("src"))?;
    findings.extend(pure_core(root)?);
    findings.extend(network_listener(&root.join("src"))?);
    findings.extend(publish_parity(
        &root.join("addon/config.yaml"),
        &root.join(".github/workflows/deploy.yaml"),
    ));
    Ok(findings)
}

/// G5. Each name marks a design guestpass does not have. An inline
/// `// ALLOW-BANNED: <reason>` suppresses one line; writing the reason is the
/// point of the escape hatch.
pub fn banned_identifiers(src: &Path) -> std::io::Result<Vec<Finding>> {
    const BANNED: [&str; 8] = [
        "cookie",
        "session",
        "jwt",
        "sqlite",
        "redirect",
        "nonce",
        "expires_in",
        "refresh_token",
    ];
    scan(src, "G5", &|line| {
        if line.contains("ALLOW-BANNED:") {
            return None;
        }
        let lower = line.to_ascii_lowercase();
        BANNED.iter().find(|p| lower.contains(**p)).copied()
    })
}

/// G6. `src/policy/` and `src/gate/` take time as an argument and perform no
/// I/O, so their behaviour is reproducible from their inputs alone.
pub fn pure_core(root: &Path) -> std::io::Result<Vec<Finding>> {
    const IMPURE: [&str; 6] = [
        "Instant::now",
        "SystemTime::now",
        "OffsetDateTime::now",
        "std::fs",
        "tokio",
        "reqwest",
    ];
    let mut findings = Vec::new();
    for dir in ["src/policy", "src/gate"] {
        findings.extend(scan(&root.join(dir), "G6", &|line| {
            IMPURE.iter().find(|p| line.contains(**p)).copied()
        })?);
    }
    Ok(findings)
}

/// G9. A program that cannot name a TCP listener cannot be configured into
/// opening one; proving the absence is stronger than checking a bind address.
pub fn network_listener(src: &Path) -> std::io::Result<Vec<Finding>> {
    const LISTENER: [&str; 3] = ["TcpListener", "SocketAddr", "0.0.0.0"];
    scan(src, "G9", &|line| {
        LISTENER.iter().find(|p| line.contains(**p)).copied()
    })
}

/// The `addon/config.yaml` fields the parity gate reads. Extra keys pass by.
#[derive(serde::Deserialize)]
struct Addon {
    image: String,
    arch: BTreeSet<String>,
}

/// The `deploy.yaml` spine down to the build matrix, typed. A rename of any
/// key on this path fails the parse loudly instead of matching nothing.
#[derive(serde::Deserialize)]
struct Deploy {
    jobs: DeployJobs,
}
#[derive(serde::Deserialize)]
struct DeployJobs {
    build: BuildJob,
}
#[derive(serde::Deserialize)]
struct BuildJob {
    strategy: Strategy,
}
#[derive(serde::Deserialize)]
struct Strategy {
    matrix: Matrix,
}
#[derive(serde::Deserialize)]
struct Matrix {
    include: Vec<Cell>,
}
#[derive(serde::Deserialize)]
struct Cell {
    arch: String,
}

/// G11. The Supervisor installs `<image>:<version>` for the machine it runs
/// on, so an architecture the manifest offers and the matrix never builds is
/// an install that fails at pull time, on a machine the maintainer does not
/// own.
pub fn publish_parity(addon: &Path, deploy: &Path) -> Vec<Finding> {
    let fail = |detail: String| {
        vec![Finding {
            gate: "G11",
            place: format!("{} / {}", addon.display(), deploy.display()),
            detail,
        }]
    };

    let manifest: Addon = match std::fs::read_to_string(addon)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_yaml_ng::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(m) => m,
        Err(e) => return fail(format!("addon manifest unreadable: {e}")),
    };
    let workflow: Deploy = match std::fs::read_to_string(deploy)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_yaml_ng::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(d) => d,
        Err(e) => return fail(format!("deploy workflow unreadable: {e}")),
    };

    let built: BTreeSet<String> = workflow
        .jobs
        .build
        .strategy
        .matrix
        .include
        .into_iter()
        .map(|c| c.arch)
        .collect();

    let mut findings = Vec::new();
    if manifest.arch != built {
        findings.extend(fail(format!(
            "manifest offers {:?}; the matrix builds {:?}",
            manifest.arch, built
        )));
    }
    // A {arch} placeholder names one image per architecture; this repository
    // publishes a single manifest list, so the placeholder would name nothing.
    if manifest.image.contains("{arch}") {
        findings.push(Finding {
            gate: "G11",
            place: addon.display().to_string(),
            detail: format!("image `{}` carries an {{arch}} placeholder", manifest.image),
        });
    }
    findings
}

/// Scan every `.rs` line under `dir` with a pure line judgement. Missing
/// directories scan as empty: a gate over nothing has nothing to find.
fn scan(
    dir: &Path,
    gate: &'static str,
    judge: &dyn Fn(&str) -> Option<&'static str>,
) -> std::io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for path in rust_sources(dir)? {
        let text = std::fs::read_to_string(&path)?;
        for (ix, line) in text.lines().enumerate() {
            if let Some(pattern) = judge(line) {
                findings.push(Finding {
                    gate,
                    place: format!("{}:{}", path.display(), ix + 1),
                    detail: format!("`{pattern}` in `{}`", line.trim()),
                });
            }
        }
    }
    Ok(findings)
}

/// Depth-first, sorted at each level for deterministic reports.
fn rust_sources(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            out.extend(rust_sources(&path)?);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gates run against the repository they live in: the shipped tree is
    /// clean. This is the gate step itself, in test form.
    #[test]
    fn the_shipped_tree_is_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("root");
        let findings = check_all(root).expect("readable tree");
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// A gate that cannot fail is decoration, so each is shown firing.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("gp-xtask-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            Self(dir)
        }
        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
            std::fs::write(&path, text).expect("write");
            path
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn banned_identifiers_fire_and_the_escape_hatch_holds() {
        let tree = Scratch::new("g5");
        tree.write("src/a.rs", "fn session_cookie() {}\n");
        tree.write(
            "src/b.rs",
            "let s = \"Session\"; // ALLOW-BANNED: exercising the escape\n",
        );
        let findings = banned_identifiers(&tree.0.join("src")).expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].place.ends_with("a.rs:1"));
    }

    #[test]
    fn the_pure_core_rejects_clocks_and_io() {
        let tree = Scratch::new("g6");
        tree.write("src/policy/mod.rs", "let t = OffsetDateTime::now_utc();\n");
        tree.write("src/gate/mod.rs", "fn admit(now: OffsetDateTime) {}\n");
        let findings = pure_core(&tree.0).expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].gate, "G6");
    }

    #[test]
    fn a_named_tcp_listener_fires() {
        let tree = Scratch::new("g9");
        tree.write("src/net.rs", "use std::net::TcpListener;\n");
        let findings = network_listener(&tree.0.join("src")).expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn publish_parity_fires_on_an_unbuildable_architecture() {
        let tree = Scratch::new("g11");
        let addon = tree.write(
            "addon/config.yaml",
            "image: ghcr.io/x/y\narch:\n  - aarch64\n  - amd64\n  - armv7\n",
        );
        let deploy = tree.write(
            "deploy.yaml",
            "jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - arch: amd64\n          - arch: aarch64\n",
        );
        let findings = publish_parity(&addon, &deploy);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("armv7"), "{findings:?}");
    }

    #[test]
    fn publish_parity_fires_on_an_arch_placeholder() {
        let tree = Scratch::new("g11b");
        let addon = tree.write(
            "addon/config.yaml",
            "image: ghcr.io/x/y/{arch}\narch: [amd64, aarch64]\n",
        );
        let deploy = tree.write(
            "deploy.yaml",
            "jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - arch: amd64\n          - arch: aarch64\n",
        );
        let findings = publish_parity(&addon, &deploy);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("placeholder"));
    }
}
