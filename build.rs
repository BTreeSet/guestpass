//! Build the frontend before `rust-embed` bakes `frontend/dist/` into the binary.
//!
//! `GUESTPASS_SKIP_FRONTEND_BUILD=1` skips the npm build and uses whatever is
//! already in `frontend/dist/`, for CI and Docker stages that build it in a
//! dedicated step and for machines without Node. When the build is skipped or
//! npm is unavailable and `dist` is missing, a placeholder is written so the
//! crate still compiles, with a warning so the omission is visible.

use std::path::Path;
use std::process::Command;

fn main() {
    let frontend = Path::new("frontend");
    let dist = frontend.join("dist");

    for path in [
        "frontend/src",
        "frontend/index.html",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/vite.config.ts",
        "frontend/tsconfig.app.json",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=GUESTPASS_SKIP_FRONTEND_BUILD");

    if std::env::var_os("GUESTPASS_SKIP_FRONTEND_BUILD").is_some() {
        ensure_dist(&dist);
        return;
    }
    if !frontend.join("package.json").exists() {
        warn("frontend/package.json not found; skipping frontend build");
        ensure_dist(&dist);
        return;
    }
    if let Err(message) = build(frontend) {
        warn(&format!("frontend build skipped: {message}"));
        ensure_dist(&dist);
    }
}

fn build(frontend: &Path) -> Result<(), String> {
    let npm = std::env::var("NPM").unwrap_or_else(|_| {
        if cfg!(windows) {
            "npm.cmd".to_owned()
        } else {
            "npm".to_owned()
        }
    });
    if !frontend.join("node_modules").exists() {
        run(&npm, &["ci"], frontend)?;
    }
    run(&npm, &["run", "build"], frontend)
}

fn run(program: &str, args: &[&str], dir: &Path) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|e| format!("could not launch `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{program} {}` exited with {status}",
            args.join(" ")
        ))
    }
}

fn ensure_dist(dist: &Path) {
    if dist.join("index.html").exists() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(dist) {
        warn(&format!("could not create {}: {e}", dist.display()));
        return;
    }
    let placeholder = "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
<title>guestpass</title></head><body><p>Frontend not built. Run \
<code>npm run build</code> in <code>frontend/</code>.</p></body></html>\n";
    if let Err(e) = std::fs::write(dist.join("index.html"), placeholder) {
        warn(&format!("could not write placeholder index.html: {e}"));
    }
}

fn warn(message: &str) {
    println!("cargo:warning={message}");
}
