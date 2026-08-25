//! The Actions pipeline as typed values (AGENTS.md G14, docs/decisions.md D-14).
//!
//! The committed YAML is a compiled artifact of the definitions below, emitted
//! by `cargo xtask workflows` and held in place by a drift test. The states
//! that must never occur are unrepresentable in the source language:
//!
//! * A trigger is a closed enum with no `workflow_run` or `pull_request_target`
//!   variant, so an elevated-token trigger cannot be written.
//! * Workflow-level permissions are not a field: the emitter always writes
//!   `permissions: {}`, so an ambient grant cannot be written.
//! * Every job carries `Permissions` and `timeout_minutes` as required fields,
//!   so an unbounded or undeclared job does not compile.
//! * An action reference is either a GitHub- or Docker-owned slug pinned to a
//!   major tag, or a third-party slug pinned to a 40-hex commit; both proofs
//!   run in const evaluation, so a mispinned action does not compile.
//! * The architecture matrix is one constant, shared by the CI and deploy
//!   matrices; gate G11 reconciles the add-on manifest against its emission.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// The pin algebra.

/// Namespaces whose actions ride their owner's trust: pin to a major tag and
/// pick up security and performance fixes without a hash bump.
const TRUSTED_NAMESPACES: [&str; 2] = ["actions/", "docker/"];

const fn has_prefix(s: &str, prefix: &str) -> bool {
    let (s, p) = (s.as_bytes(), prefix.as_bytes());
    if s.len() < p.len() {
        return false;
    }
    let mut i = 0;
    while i < p.len() {
        if s[i] != p[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn in_trusted_namespace(slug: &str) -> bool {
    has_prefix(slug, TRUSTED_NAMESPACES[0]) || has_prefix(slug, TRUSTED_NAMESPACES[1])
}

const fn is_full_sha(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 40 {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_hexdigit() {
            return false;
        }
        i += 1;
    }
    true
}

/// One action reference. The constructors are the pin policy; every reference
/// below is a `const`, so a violation fails compilation, not review.
pub struct Action {
    slug: &'static str,
    pin: Pin,
}

enum Pin {
    Major(u8),
    Sha {
        sha: &'static str,
        version: &'static str,
    },
}

impl Action {
    /// A first-party action: `actions/` or `docker/` only.
    const fn trusted(slug: &'static str, major: u8) -> Self {
        assert!(
            in_trusted_namespace(slug),
            "major-tag pins are for the actions/ and docker/ namespaces"
        );
        Self {
            slug,
            pin: Pin::Major(major),
        }
    }

    /// A third-party action: full commit SHA, version recorded alongside.
    const fn pinned(slug: &'static str, sha: &'static str, version: &'static str) -> Self {
        assert!(
            !in_trusted_namespace(slug),
            "first-party actions pin to a major tag"
        );
        assert!(is_full_sha(sha), "a third-party pin is a 40-hex commit");
        Self {
            slug,
            pin: Pin::Sha { sha, version },
        }
    }

    fn render(&self) -> String {
        match self.pin {
            Pin::Major(n) => format!("{}@v{n}", self.slug),
            Pin::Sha { sha, version } => format!("{}@{sha}  # {version}", self.slug),
        }
    }
}

const CHECKOUT: Action = Action::trusted("actions/checkout", 7);
const SETUP_NODE: Action = Action::trusted("actions/setup-node", 7);
const UPLOAD_ARTIFACT: Action = Action::trusted("actions/upload-artifact", 7);
const DOWNLOAD_ARTIFACT: Action = Action::trusted("actions/download-artifact", 8);
const SETUP_BUILDX: Action = Action::trusted("docker/setup-buildx-action", 4);
const LOGIN: Action = Action::trusted("docker/login-action", 4);
const BUILD_PUSH: Action = Action::trusted("docker/build-push-action", 7);
const RUST_CACHE: Action = Action::pinned(
    "Swatinem/rust-cache",
    "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "v2.9.2",
);
const CARGO_DENY: Action = Action::pinned(
    "EmbarkStudios/cargo-deny-action",
    "3c6349835b2b7b196a839186cb8b78e02f7b5f25",
    "v2.1.1",
);
const SETUP_UV: Action = Action::pinned(
    "astral-sh/setup-uv",
    "20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
    "v10.0.1",
);

// ---------------------------------------------------------------------------
// The architecture set: one constant, three consumers (deploy matrix, CI
// matrix, and gate G11's reconciliation with the add-on manifest).

pub struct Arch {
    pub name: &'static str,
    pub platform: &'static str,
    pub runner: &'static str,
}

pub const ARCHITECTURES: [Arch; 2] = [
    Arch {
        name: "amd64",
        platform: "linux/amd64",
        runner: "ubuntu-24.04",
    },
    Arch {
        name: "aarch64",
        platform: "linux/arm64",
        runner: "ubuntu-24.04-arm",
    },
];

// ---------------------------------------------------------------------------
// The workflow model. Only what the three workflows need, and nothing that
// must never appear.

/// Closed: `workflow_run` and `pull_request_target`, the two triggers that run
/// elevated over fork-influenced data, have no representation.
enum Trigger {
    PushMain,
    PullRequestMain,
    ReleasePublished,
    WorkflowDispatch,
    WorkflowCall,
}

impl Trigger {
    fn render(&self, out: &mut String) {
        match self {
            Self::PushMain => push_lines(out, &["  push:", "    branches: [main]"]),
            Self::PullRequestMain => push_lines(
                out,
                &[
                    "  pull_request:",
                    "    branches: [main]",
                    "    types: [opened, reopened, synchronize]",
                ],
            ),
            Self::ReleasePublished => push_lines(out, &["  release:", "    types: [published]"]),
            Self::WorkflowDispatch => push_lines(out, &["  workflow_dispatch:"]),
            Self::WorkflowCall => push_lines(out, &["  workflow_call:"]),
        }
    }
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

impl Access {
    const fn render(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A job's capability set. Absent means absent: there is no "default" state.
#[derive(Clone, Copy)]
struct Permissions {
    contents: Option<Access>,
    packages: Option<Access>,
}

impl Permissions {
    const READ: Self = Self {
        contents: Some(Access::Read),
        packages: None,
    };
    /// The publish capability: registry write, checkout read.
    const PUBLISH: Self = Self {
        contents: Some(Access::Read),
        packages: Some(Access::Write),
    };

    fn render(self, indent: usize, out: &mut String) {
        let pad = " ".repeat(indent);
        if self.contents.is_none() && self.packages.is_none() {
            let _ = writeln!(out, "{pad}permissions: {{}}");
            return;
        }
        let _ = writeln!(out, "{pad}permissions:");
        if let Some(a) = self.contents {
            let _ = writeln!(out, "{pad}  contents: {}", a.render());
        }
        if let Some(a) = self.packages {
            let _ = writeln!(out, "{pad}  packages: {}", a.render());
        }
    }
}

struct Concurrency {
    group: &'static str,
    cancel_in_progress: &'static str,
}

enum WithValue {
    Str(&'static str),
    /// Rendered as a literal block scalar.
    Block(&'static [&'static str]),
    /// A single line long enough to need the yamllint escape.
    LongStr(&'static str),
}

enum Step {
    Uses {
        note: &'static [&'static str],
        name: &'static str,
        id: Option<&'static str>,
        action: &'static Action,
        with: &'static [(&'static str, WithValue)],
    },
    Run {
        note: &'static [&'static str],
        name: &'static str,
        id: Option<&'static str>,
        env: &'static [(&'static str, &'static str)],
        working_directory: Option<&'static str>,
        run: &'static str,
    },
}

/// A job either calls the reusable workflow or runs steps. A run job cannot be
/// written without a permission set and a time bound.
enum Job {
    Call {
        id: &'static str,
        uses: &'static str,
        permissions: Permissions,
    },
    Run(RunJob),
}

struct RunJob {
    id: &'static str,
    note: &'static [&'static str],
    name: &'static str,
    needs: &'static [&'static str],
    /// `Some` runs the job once per architecture on that architecture's own
    /// runner; `None` names one runner. Cross-compilation has no field.
    matrix: Option<&'static [Arch]>,
    runner: &'static str,
    timeout_minutes: u16,
    permissions: Permissions,
    /// Values later jobs consume through `needs`.
    outputs: &'static [(&'static str, &'static str)],
    env: &'static [(&'static str, &'static str)],
    steps: &'static [Step],
}

struct Workflow {
    file: &'static str,
    name: &'static str,
    note: &'static [&'static str],
    triggers: &'static [Trigger],
    concurrency: Option<Concurrency>,
    env: &'static [(&'static str, &'static str)],
    jobs: &'static [Job],
}

// ---------------------------------------------------------------------------
// Emission. Deterministic; comments come from the notes.

fn push_lines(out: &mut String, lines: &[&str]) {
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
}

fn push_note(out: &mut String, indent: usize, note: &[&str]) {
    let pad = " ".repeat(indent);
    for line in note {
        if line.is_empty() {
            let _ = writeln!(out, "{pad}#");
        } else {
            let _ = writeln!(out, "{pad}# {line}");
        }
    }
}

fn render_env(out: &mut String, indent: usize, env: &[(&str, &str)]) {
    if env.is_empty() {
        return;
    }
    let pad = " ".repeat(indent);
    let _ = writeln!(out, "{pad}env:");
    for (k, v) in env {
        let _ = writeln!(out, "{pad}  {k}: {v}");
    }
}

fn render_step(out: &mut String, step: &Step) {
    match step {
        Step::Uses {
            note,
            name,
            id,
            action,
            with,
        } => {
            push_note(out, 6, note);
            let _ = writeln!(out, "      - name: {name}");
            if let Some(id) = id {
                let _ = writeln!(out, "        id: {id}");
            }
            let _ = writeln!(out, "        uses: {}", action.render());
            if !with.is_empty() {
                let _ = writeln!(out, "        with:");
                for (k, v) in *with {
                    match v {
                        WithValue::Str(s) => {
                            let _ = writeln!(out, "          {k}: {s}");
                        }
                        WithValue::LongStr(s) => {
                            let _ =
                                writeln!(out, "          # yamllint disable-line rule:line-length");
                            let _ = writeln!(out, "          {k}: {s}");
                        }
                        WithValue::Block(lines) => {
                            let _ = writeln!(out, "          {k}: |");
                            for l in *lines {
                                let _ = writeln!(out, "            {l}");
                            }
                        }
                    }
                }
            }
        }
        Step::Run {
            note,
            name,
            id,
            env,
            working_directory,
            run,
        } => {
            push_note(out, 6, note);
            let _ = writeln!(out, "      - name: {name}");
            if let Some(id) = id {
                let _ = writeln!(out, "        id: {id}");
            }
            render_env(out, 8, env);
            if let Some(dir) = working_directory {
                let _ = writeln!(out, "        working-directory: {dir}");
            }
            if run.contains('\n') {
                let _ = writeln!(out, "        run: |");
                for l in run.lines() {
                    if l.is_empty() {
                        out.push('\n');
                    } else {
                        let _ = writeln!(out, "          {l}");
                    }
                }
            } else {
                let _ = writeln!(out, "        run: {run}");
            }
        }
    }
}

fn render_job(out: &mut String, job: &Job) {
    match job {
        Job::Call {
            id,
            uses,
            permissions,
        } => {
            let _ = writeln!(out, "  {id}:");
            let _ = writeln!(out, "    uses: {uses}");
            permissions.render(4, out);
        }
        Job::Run(j) => {
            push_note(out, 2, j.note);
            let _ = writeln!(out, "  {}:", j.id);
            let _ = writeln!(out, "    name: {}", j.name);
            if !j.needs.is_empty() {
                let _ = writeln!(out, "    needs: [{}]", j.needs.join(", "));
            }
            let _ = writeln!(out, "    runs-on: {}", j.runner);
            let _ = writeln!(out, "    timeout-minutes: {}", j.timeout_minutes);
            j.permissions.render(4, out);
            if !j.outputs.is_empty() {
                let _ = writeln!(out, "    outputs:");
                for (k, v) in j.outputs {
                    let _ = writeln!(out, "      {k}: {v}");
                }
            }
            if let Some(arches) = j.matrix {
                push_lines(
                    out,
                    &[
                        "    strategy:",
                        "      fail-fast: false",
                        "      matrix:",
                        "        include:",
                    ],
                );
                for a in arches {
                    let _ = writeln!(out, "          - arch: {}", a.name);
                    let _ = writeln!(out, "            platform: {}", a.platform);
                    let _ = writeln!(out, "            runner: {}", a.runner);
                }
            }
            render_env(out, 4, j.env);
            let _ = writeln!(out, "    steps:");
            let mut first = true;
            for step in j.steps {
                if !first {
                    out.push('\n');
                }
                first = false;
                render_step(out, step);
            }
        }
    }
}

fn emit(w: &Workflow) -> String {
    let mut out = String::from("---\n");
    let _ = writeln!(out, "name: {}\n", w.name);
    push_note(&mut out, 0, w.note);
    out.push_str("# yamllint disable-line rule:truthy\non:\n");
    for t in w.triggers {
        t.render(&mut out);
    }
    out.push('\n');
    out.push_str("permissions: {}\n");
    if let Some(c) = &w.concurrency {
        out.push('\n');
        let _ = writeln!(out, "concurrency:");
        let _ = writeln!(out, "  group: {}", c.group);
        let _ = writeln!(out, "  cancel-in-progress: {}", c.cancel_in_progress);
    }
    if !w.env.is_empty() {
        out.push('\n');
        render_env(&mut out, 0, w.env);
    }
    out.push_str("\njobs:\n");
    let mut first = true;
    for job in w.jobs {
        if !first {
            out.push('\n');
        }
        first = false;
        render_job(&mut out, job);
    }
    out
}

// ---------------------------------------------------------------------------
// The three workflows. sync-skills.yml is submodule-managed and not ours.

const CI: Workflow = Workflow {
    file: ".github/workflows/ci.yaml",
    name: "CI",
    note: &[
        "GENERATED by `cargo xtask workflows` from xtask/src/workflows.rs (G14).",
        "Edit the source, not this file: a drift test holds them equal.",
        "",
        "Trust boundary: this workflow runs on fork pull requests, so everything it",
        "executes is attacker-controlled (source, build.rs, npm lifecycle scripts).",
        "It therefore receives no secrets, no registry credentials, and no write",
        "capability of any kind. Publishing lives in deploy.yaml, which only fires on",
        "events a fork cannot cause.",
    ],
    triggers: &[
        Trigger::PushMain,
        Trigger::PullRequestMain,
        Trigger::WorkflowDispatch,
    ],
    concurrency: Some(Concurrency {
        group: "ci-${{ github.ref }}",
        cancel_in_progress: "${{ github.event_name == 'pull_request' }}",
    }),
    env: &[],
    jobs: &[Job::Call {
        id: "ci",
        uses: "./.github/workflows/upstream-ci.yaml",
        permissions: Permissions::READ,
    }],
};

const CHECKOUT_STEP: Step = Step::Uses {
    note: &[],
    name: "Check out",
    id: None,
    action: &CHECKOUT,
    with: &[("persist-credentials", WithValue::Str("false"))],
};

const UPSTREAM_CI: Workflow = Workflow {
    file: ".github/workflows/upstream-ci.yaml",
    name: "Reusable CI",
    note: &[
        "GENERATED by `cargo xtask workflows` from xtask/src/workflows.rs (G14).",
        "Edit the source, not this file: a drift test holds them equal.",
        "",
        "No ambient capability. Each job asks for exactly the effects it performs,",
        "and none of them writes anything outside its own runner.",
    ],
    triggers: &[Trigger::WorkflowCall],
    concurrency: None,
    env: &[("CARGO_TERM_COLOR", "always")],
    jobs: &[
        Job::Run(RunJob {
            id: "rust",
            note: &[
                "Independent leaves. `rust` needs no frontend bundle: build.rs writes a",
                "placeholder under GUESTPASS_SKIP_FRONTEND_BUILD, which is all rust-embed",
                "requires to compile. The two run in parallel and join at `image`.",
            ],
            name: "Rust",
            needs: &[],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 20,
            permissions: Permissions::READ,
            outputs: &[],
            env: &[("GUESTPASS_SKIP_FRONTEND_BUILD", "\"1\"")],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Cache cargo",
                    id: None,
                    action: &RUST_CACHE,
                    with: &[],
                },
                Step::Run {
                    note: &[],
                    name: "Format",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "cargo fmt --all --check",
                },
                Step::Run {
                    note: &[],
                    name: "Clippy",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "cargo clippy --workspace --all-targets --locked -- -D warnings",
                },
                Step::Run {
                    note: &[
                        "--workspace includes the xtask crate, whose tests are the CI harness:",
                        "the release tag algebra on fixed inputs, and every gate shown firing.",
                    ],
                    name: "Test",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "cargo test --workspace --locked",
                },
                Step::Run {
                    note: &[],
                    name: "Gates G5, G6, G9, and G11",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "cargo xtask gates",
                },
            ],
        }),
        Job::Run(RunJob {
            id: "deps",
            note: &[
                "Gate G1: the dependency allowlist. Separated from `rust` because it fetches",
                "the advisory database and fails for reasons unrelated to the code.",
            ],
            name: "Dependency policy",
            needs: &[],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 15,
            permissions: Permissions::READ,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "cargo-deny",
                    id: None,
                    action: &CARGO_DENY,
                    with: &[(
                        "command",
                        WithValue::Str("check advisories bans licenses sources"),
                    )],
                },
            ],
        }),
        Job::Run(RunJob {
            id: "frontend",
            note: &[],
            name: "Frontend",
            needs: &[],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 15,
            permissions: Permissions::READ,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Set up Node",
                    id: None,
                    action: &SETUP_NODE,
                    with: &[
                        ("node-version", WithValue::Str("\"24\"")),
                        ("cache", WithValue::Str("npm")),
                        (
                            "cache-dependency-path",
                            WithValue::Str("frontend/package-lock.json"),
                        ),
                    ],
                },
                Step::Run {
                    note: &[
                        "`npm ci` runs lifecycle scripts from the lockfile. On a fork PR that is",
                        "attacker code, which is why this job holds no secrets and no write scope.",
                    ],
                    name: "Install",
                    id: None,
                    env: &[],
                    working_directory: Some("frontend"),
                    run: "npm ci",
                },
                Step::Run {
                    note: &[],
                    name: "Typecheck and build",
                    id: None,
                    env: &[],
                    working_directory: Some("frontend"),
                    run: "npm run build",
                },
                Step::Uses {
                    note: &[],
                    name: "Upload bundle",
                    id: None,
                    action: &UPLOAD_ARTIFACT,
                    with: &[
                        ("name", WithValue::Str("frontend-dist")),
                        ("path", WithValue::Str("frontend/dist")),
                        ("retention-days", WithValue::Str("1")),
                        ("if-no-files-found", WithValue::Str("error")),
                    ],
                },
            ],
        }),
        Job::Run(RunJob {
            id: "workflows",
            note: &[],
            name: "Workflow lint",
            needs: &[],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 10,
            permissions: Permissions::READ,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Set up uv",
                    id: None,
                    action: &SETUP_UV,
                    with: &[],
                },
                Step::Run {
                    note: &[
                        "actionlint also ShellChecks the embedded `run:` blocks, which are the",
                        "only shell in the repository.",
                    ],
                    name: "actionlint",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "docker run --rm -v \"$PWD:/repo\" --workdir /repo \\\n  rhysd/actionlint:1.7.12 -color",
                },
                Step::Run {
                    note: &[],
                    name: "yamllint",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "uvx yamllint@1.37.1 -c .yamllint .",
                },
                Step::Run {
                    note: &[
                        "zizmor audits the workflows themselves for privilege and injection flaws.",
                    ],
                    name: "zizmor",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "uvx zizmor@1.10.0 --persona=pedantic .github/workflows/",
                },
            ],
        }),
        Job::Run(RunJob {
            id: "image",
            note: &[
                "The join. Builds the real image natively on each architecture's own",
                "runner, and never pushes: publication is a capability this workflow does",
                "not hold. Cross-compilation and emulation are unrepresentable here: the",
                "runner and the platform travel together in one matrix constant, and the",
                "gates below prove runtime properties on the machine that will run them.",
                "Gate G11 holds this matrix, the deploy matrix, and the add-on manifest to",
                "one architecture set.",
            ],
            name: "Image ${{ matrix.arch }}",
            needs: &["rust", "frontend"],
            matrix: Some(&ARCHITECTURES),
            runner: "${{ matrix.runner }}",
            timeout_minutes: 30,
            permissions: Permissions::READ,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Download bundle",
                    id: None,
                    action: &DOWNLOAD_ARTIFACT,
                    with: &[
                        ("name", WithValue::Str("frontend-dist")),
                        ("path", WithValue::Str("frontend/dist")),
                    ],
                },
                Step::Uses {
                    note: &[],
                    name: "Set up Buildx",
                    id: None,
                    action: &SETUP_BUILDX,
                    with: &[],
                },
                Step::Uses {
                    note: &[],
                    name: "Build",
                    id: None,
                    action: &BUILD_PUSH,
                    with: &[
                        ("context", WithValue::Str(".")),
                        ("platforms", WithValue::Str("${{ matrix.platform }}")),
                        ("push", WithValue::Str("false")),
                        ("load", WithValue::Str("true")),
                        ("tags", WithValue::Str("guestpass:ci")),
                        (
                            "cache-from",
                            WithValue::Str("type=gha,scope=image-${{ matrix.arch }}"),
                        ),
                        (
                            "cache-to",
                            WithValue::Str("type=gha,mode=max,scope=image-${{ matrix.arch }}"),
                        ),
                    ],
                },
                Step::Run {
                    note: &[
                        "Gate G4: the image must work with no writable path anywhere. A failure",
                        "here means something started persisting state.",
                    ],
                    name: "Statelessness",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "docker run --rm --read-only --network none guestpass:ci gen-token",
                },
                Step::Run {
                    note: &[
                        "The socket directory redirects to the tmpfs the runtime already mounts.",
                        "A build that dereferenced the symlink would need a --tmpfs flag back.",
                    ],
                    name: "Socket directory redirects to /dev/shm",
                    id: None,
                    env: &[],
                    working_directory: None,
                    run: "docker create --name probe guestpass:ci >/dev/null\ndocker export probe > image.tar\ndocker rm probe >/dev/null\ntar -tvf image.tar | grep -q 'run/guestpass -> /dev/shm/guestpass'",
                },
            ],
        }),
    ],
};

const DEPLOY: Workflow = Workflow {
    file: ".github/workflows/deploy.yaml",
    name: "Deploy",
    note: &[
        "GENERATED by `cargo xtask workflows` from xtask/src/workflows.rs (G14).",
        "Edit the source, not this file: a drift test holds them equal.",
        "",
        "Trust boundary: every trigger here is an event a fork cannot cause. A push to",
        "main requires write access; publishing a release requires the same. The",
        "trigger set that runs elevated over fork-influenced data (`workflow_run`,",
        "`pull_request_target`) is unrepresentable in the workflow source. Ordering",
        "with CI is a `needs:` edge rather than a completion event, so the publish",
        "jobs cannot run against code CI has not passed.",
    ],
    triggers: &[
        Trigger::PushMain,
        Trigger::ReleasePublished,
        Trigger::WorkflowDispatch,
    ],
    concurrency: Some(Concurrency {
        group: "deploy-${{ github.ref }}",
        cancel_in_progress: "false",
    }),
    env: &[],
    jobs: &[
        Job::Call {
            id: "ci",
            uses: "./.github/workflows/upstream-ci.yaml",
            permissions: Permissions::READ,
        },
        Job::Run(RunJob {
            id: "meta",
            note: &[
                "The version and tag set come from the typed algebra in",
                "`xtask/src/release.rs` (D-13, G13): a release is exactly the manifest",
                "version plus `latest`; a push to main is the successor patch of the",
                "latest release, named `MAJOR.MINOR.PATCH-dev.<date>.<time>.g<sha7>`,",
                "plus the moving `edge` alias. It refuses a release whose tag is not an",
                "exact triple or disagrees with addon/config.yaml, and reconciles the",
                "manifest image with the one this workflow publishes.",
            ],
            name: "Resolve release identity",
            needs: &["ci"],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 5,
            permissions: Permissions::READ,
            outputs: &[
                ("image", "${{ steps.resolve.outputs.image }}"),
                ("tags", "${{ steps.resolve.outputs.tags }}"),
                ("version", "${{ steps.resolve.outputs.version }}"),
                ("created", "${{ steps.resolve.outputs.created }}"),
            ],
            env: &[],
            steps: &[
                Step::Uses {
                    note: &[
                        "The tag algebra computes the pre-release version from the latest",
                        "shipped release, so it needs the full tag list.",
                    ],
                    name: "Check out",
                    id: None,
                    action: &CHECKOUT,
                    with: &[
                        ("persist-credentials", WithValue::Str("false")),
                        ("fetch-tags", WithValue::Str("true")),
                    ],
                },
                Step::Run {
                    note: &[
                        "The release tag is attacker-influenced only by someone who already",
                        "holds write access, and it crosses as environment data into a process",
                        "that never involves a shell.",
                    ],
                    name: "Resolve",
                    id: Some("resolve"),
                    env: &[
                        ("EVENT", "${{ github.event_name }}"),
                        ("RELEASE_TAG", "${{ github.event.release.tag_name }}"),
                    ],
                    working_directory: None,
                    run: "cargo xtask resolve",
                },
            ],
        }),
        Job::Run(RunJob {
            id: "build",
            note: &[
                "One runner per architecture, each compiling for the machine it runs on.",
                "The runner and the platform travel together in the one matrix constant,",
                "so emulating another architecture is unrepresentable. This job restores",
                "no cache: build caches are writable by workflows that run untrusted pull",
                "request code, so a job that produces a published artifact treats them as",
                "an untrusted input and rebuilds from source.",
            ],
            name: "Build ${{ matrix.arch }}",
            needs: &["meta"],
            matrix: Some(&ARCHITECTURES),
            runner: "${{ matrix.runner }}",
            timeout_minutes: 45,
            permissions: Permissions::PUBLISH,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Set up Buildx",
                    id: None,
                    action: &SETUP_BUILDX,
                    with: &[],
                },
                Step::Uses {
                    note: &[],
                    name: "Log in to GHCR",
                    id: None,
                    action: &LOGIN,
                    with: &[
                        ("registry", WithValue::Str("ghcr.io")),
                        ("username", WithValue::Str("${{ github.actor }}")),
                        ("password", WithValue::Str("${{ secrets.GITHUB_TOKEN }}")),
                    ],
                },
                Step::Uses {
                    note: &[
                        "Pushed by digest and left untagged. A per-architecture tag would be",
                        "pullable, and an add-on that pulled one would run the wrong machine",
                        "code; only the manifest list the next job creates carries a name.",
                    ],
                    name: "Build and push by digest",
                    id: Some("build"),
                    action: &BUILD_PUSH,
                    with: &[
                        ("context", WithValue::Str(".")),
                        ("platforms", WithValue::Str("${{ matrix.platform }}")),
                        ("provenance", WithValue::Str("mode=max")),
                        ("sbom", WithValue::Str("true")),
                        (
                            "outputs",
                            WithValue::LongStr(
                                "type=image,name=${{ needs.meta.outputs.image }},push-by-digest=true,name-canonical=true,push=true",
                            ),
                        ),
                        (
                            "build-args",
                            WithValue::Block(&[
                                "BUILD_ARCH=${{ matrix.arch }}",
                                "BUILD_DATE=${{ needs.meta.outputs.created }}",
                                "BUILD_REF=${{ github.sha }}",
                                "BUILD_REPOSITORY=${{ github.repository }}",
                                "BUILD_VERSION=${{ needs.meta.outputs.version }}",
                            ]),
                        ),
                    ],
                },
                Step::Run {
                    note: &[
                        "The digest is the whole payload: an empty file named after it carries",
                        "one architecture's result to the manifest job.",
                    ],
                    name: "Export digest",
                    id: None,
                    env: &[("DIGEST", "${{ steps.build.outputs.digest }}")],
                    working_directory: None,
                    run: "mkdir -p /tmp/digests\ntouch \"/tmp/digests/${DIGEST#sha256:}\"",
                },
                Step::Uses {
                    note: &[],
                    name: "Upload digest",
                    id: None,
                    action: &UPLOAD_ARTIFACT,
                    with: &[
                        ("name", WithValue::Str("digest-${{ matrix.arch }}")),
                        ("path", WithValue::Str("/tmp/digests/*")),
                        ("if-no-files-found", WithValue::Str("error")),
                        ("retention-days", WithValue::Str("1")),
                    ],
                },
            ],
        }),
        Job::Run(RunJob {
            id: "manifest",
            note: &[
                "The join. `image: ghcr.io/btreeset/guestpass` in addon/config.yaml",
                "resolves here, and the Supervisor picks the architecture out of the list.",
            ],
            name: "Publish manifest list",
            needs: &["meta", "build"],
            matrix: None,
            runner: "ubuntu-latest",
            timeout_minutes: 15,
            permissions: Permissions::PUBLISH,
            outputs: &[],
            env: &[],
            steps: &[
                CHECKOUT_STEP,
                Step::Uses {
                    note: &[],
                    name: "Download digests",
                    id: None,
                    action: &DOWNLOAD_ARTIFACT,
                    with: &[
                        ("path", WithValue::Str("/tmp/digests")),
                        ("pattern", WithValue::Str("digest-*")),
                        ("merge-multiple", WithValue::Str("true")),
                    ],
                },
                Step::Uses {
                    note: &[],
                    name: "Set up Buildx",
                    id: None,
                    action: &SETUP_BUILDX,
                    with: &[],
                },
                Step::Uses {
                    note: &[],
                    name: "Log in to GHCR",
                    id: None,
                    action: &LOGIN,
                    with: &[
                        ("registry", WithValue::Str("ghcr.io")),
                        ("username", WithValue::Str("${{ github.actor }}")),
                        ("password", WithValue::Str("${{ secrets.GITHUB_TOKEN }}")),
                    ],
                },
                Step::Run {
                    note: &[
                        "Typed argument assembly, no shell word-splitting: the digests are",
                        "validated as sha256 names and the docker invocation is exec'd direct.",
                    ],
                    name: "Create and inspect manifest list",
                    id: None,
                    env: &[
                        ("IMAGE", "${{ needs.meta.outputs.image }}"),
                        ("TAGS", "${{ needs.meta.outputs.tags }}"),
                    ],
                    working_directory: None,
                    run: "cargo xtask manifest --digests /tmp/digests",
                },
            ],
        }),
    ],
};

/// Every workflow this repository owns.
const ALL: [&Workflow; 3] = [&CI, &UPSTREAM_CI, &DEPLOY];

/// Write the committed artifacts. `cargo xtask workflows`.
pub fn write_all(root: &std::path::Path) -> std::io::Result<()> {
    for w in ALL {
        std::fs::write(root.join(w.file), emit(w))?;
        println!("wrote {}", w.file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate G14: the committed YAML is exactly what the definitions emit.
    /// A hand edit to either side without the other fails here.
    #[test]
    fn the_committed_workflows_match_their_source() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("root");
        for w in ALL {
            let committed = std::fs::read_to_string(root.join(w.file)).expect(w.file);
            assert!(
                committed == emit(w),
                "{} has drifted from xtask/src/workflows.rs; run `cargo xtask workflows`",
                w.file
            );
        }
    }

    /// The emitter produces well-formed YAML with the expected spine.
    #[test]
    fn emissions_parse_as_yaml() {
        for w in ALL {
            let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&emit(w)).expect("parses");
            assert!(value.get("jobs").is_some(), "{}", w.file);
            assert_eq!(
                value.get("permissions"),
                Some(&serde_yaml_ng::Value::Mapping(Default::default())),
                "{}: ambient permissions must be empty",
                w.file
            );
        }
    }
}
