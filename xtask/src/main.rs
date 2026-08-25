//! CI logic for guestpass, typed. The pure decisions live in `release` and
//! `gates`; this file is the shell that gathers environment, runs processes,
//! and renders outputs.

#![deny(unsafe_code)]

mod gates;
mod release;

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use release::{Event, Sha7, Stamp, Version};

#[derive(Parser)]
#[command(name = "xtask", about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run gates G5, G6, G9, and G11 over the repository.
    Gates,
    /// Resolve the publish identity: version, tags, created (D-13, G13).
    ///
    /// Reads EVENT, RELEASE_TAG, GITHUB_SHA, GITHUB_REPOSITORY from the
    /// environment and the release tags from git; writes key=value lines to
    /// GITHUB_OUTPUT, or stdout when unset.
    Resolve,
    /// Join per-architecture digests into one tagged manifest list.
    ///
    /// Reads IMAGE and TAGS from the environment; digests are the file names
    /// under --digests, as pushed by the build matrix.
    Manifest {
        #[arg(long)]
        digests: PathBuf,
    },
    /// Everything CI runs, in CI's order, as one command.
    Verify,
}

fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Cmd::Gates => run_gates(),
        Cmd::Resolve => resolve(),
        Cmd::Manifest { digests } => manifest(&digests),
        Cmd::Verify => verify(),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level under the root")
        .to_owned()
}

fn run_gates() -> Result<(), String> {
    let findings = gates::check_all(&repo_root()).map_err(|e| e.to_string())?;
    if findings.is_empty() {
        println!("gates G5, G6, G9, G11: clean");
        Ok(())
    } else {
        for f in &findings {
            eprintln!("{f}");
        }
        Err(format!("{} gate finding(s)", findings.len()))
    }
}

/// The manifest fields `resolve` reconciles against.
#[derive(serde::Deserialize)]
struct Addon {
    version: String,
    image: String,
}

fn env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn resolve() -> Result<(), String> {
    let root = repo_root();
    let manifest: Addon = serde_yaml_ng::from_str(
        &std::fs::read_to_string(root.join("addon/config.yaml")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    // The image this workflow publishes and the image the manifest names must
    // be the same string, or the Supervisor pulls something never pushed.
    let image = format!("ghcr.io/{}", env_var("GITHUB_REPOSITORY")?.to_lowercase());
    if manifest.image != image {
        return Err(format!(
            "::error ::addon/config.yaml names {}; this workflow publishes {image}",
            manifest.image
        ));
    }
    let declared = Version::parse_triple(&manifest.version)
        .ok_or_else(|| format!("manifest version `{}` is not a triple", manifest.version))?;

    let event = match env_var("EVENT")?.as_str() {
        "release" => Event::Release {
            tag: env_var("RELEASE_TAG")?,
        },
        // workflow_dispatch is a push by another finger.
        _ => Event::Push,
    };
    let sha = env_var("GITHUB_SHA")
        .and_then(|s| Sha7::parse(&s).ok_or_else(|| format!("GITHUB_SHA `{s}` is not a commit")))?;
    let now = Stamp::from_unix(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
            .try_into()
            .expect("fits i64"),
    )
    .expect("the present formats");

    // The tag list, from the one place it exists.
    let out = Command::new("git")
        .args(["tag", "--list", "v*"])
        .current_dir(&root)
        .output()
        .map_err(|e| format!("git tag: {e}"))?;
    if !out.status.success() {
        return Err(format!("git tag: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let released = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(Version::parse_release_tag)
        .collect::<Vec<_>>();

    let publish = release::resolve(&event, declared, released, now, sha)
        .map_err(|e| format!("::error ::{e}"))?;

    emit(&[
        ("version", publish.version_tag()),
        ("tags", publish.tags().join(" ")),
        ("created", now.created()),
        ("image", image),
    ])
}

/// key=value lines to GITHUB_OUTPUT, or stdout outside Actions.
fn emit(pairs: &[(&str, String)]) -> Result<(), String> {
    let render = |w: &mut dyn std::io::Write| -> std::io::Result<()> {
        for (k, v) in pairs {
            writeln!(w, "{k}={v}")?;
        }
        Ok(())
    };
    match std::env::var_os("GITHUB_OUTPUT") {
        Some(path) => {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            render(&mut f).map_err(|e| e.to_string())
        }
        None => render(&mut std::io::stdout()).map_err(|e| e.to_string()),
    }
}

/// A digest file name as the build matrix leaves it: 64 hex characters.
fn digest_name(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{}: not a digest name", path.display()))?;
    if name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(name.to_owned())
    } else {
        Err(format!("{name}: not a sha256 digest"))
    }
}

fn manifest(digests: &Path) -> Result<(), String> {
    let image = env_var("IMAGE")?;
    let tags: Vec<String> = env_var("TAGS")?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if tags.is_empty() {
        return Err("TAGS is empty".to_owned());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(digests)
        .map_err(|e| format!("{}: {e}", digests.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort();
    if entries.is_empty() {
        return Err(format!("{}: no digests", digests.display()));
    }

    // The argument vector is assembled typed and passed as arguments, never
    // through a shell.
    let mut args: Vec<String> = vec!["buildx".into(), "imagetools".into(), "create".into()];
    for tag in &tags {
        args.push("--tag".into());
        args.push(format!("{image}:{tag}"));
    }
    for entry in &entries {
        args.push(format!("{image}@sha256:{}", digest_name(entry)?));
    }
    run(
        "docker",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
    )?;
    run(
        "docker",
        &[
            "buildx",
            "imagetools",
            "inspect",
            &format!("{image}:{}", tags[0]),
        ],
        &[],
    )
}

fn run(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .current_dir(repo_root())
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} failed", args.join(" ")))
    }
}

/// Everything CI runs, in CI's order. Running a subset locally and reporting
/// it as the whole set is the failure this command removes; `upstream-ci.yaml`
/// calls the same steps.
fn verify() -> Result<(), String> {
    const SKIP: (&str, &str) = ("GUESTPASS_SKIP_FRONTEND_BUILD", "1");
    let step = |name: &str| println!("\n=== {name} ===");

    step("cargo fmt");
    run("cargo", &["fmt", "--all", "--check"], &[])?;

    step("cargo clippy");
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &[SKIP],
    )?;

    step("cargo test");
    run("cargo", &["test", "--workspace", "--locked"], &[SKIP])?;

    step("gates G5, G6, G9, G11");
    run_gates()?;

    step("cargo-deny (G1)");
    if Command::new("cargo")
        .args(["deny", "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        run(
            "cargo",
            &["deny", "check", "advisories", "bans", "licenses", "sources"],
            &[],
        )?;
    } else {
        println!("  cargo-deny absent; CI runs it via the pinned action");
    }

    step("frontend");
    if Command::new("npm")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let front = repo_root().join("frontend");
        for args in [["ci", "--silent"].as_slice(), ["run", "build"].as_slice()] {
            let status = Command::new("npm")
                .args(args)
                .current_dir(&front)
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("npm {} failed", args.join(" ")));
            }
        }
    } else {
        println!("  npm absent; CI runs the frontend job");
    }

    println!("\nall checks passed");
    Ok(())
}
