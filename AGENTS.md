# AGENTS.md

guestpass exposes six hardcoded Home Assistant calls to anonymous guests holding
a high-entropy URL. Its security argument is that there is very little code and
the set of things it can do is a compile-time constant. Changes that make the
program larger weaken that argument, including changes framed as security
improvements.

Read [docs/threat-model.md](docs/threat-model.md) and
[docs/decisions.md](docs/decisions.md) before proposing anything security-related.
They hold the premises every constraint below rests on.

## Premises

Check every proposed change against these four. A change is sound when the
premise it depends on still holds here.

* **P1 — Rotating a secret costs a trip to a printer.** Tokens live on printed
  cards and NFC tags. The owner knows when a leak happened and rotates then.
* **P2 — Nobody watches a dashboard.** There is one owner, no operator, no
  alerting rota. A control that works by someone noticing does not work.
* **P3 — The exposed surface is six `&'static str`.** It is fixed at compile
  time, independent of configuration and of Home Assistant releases.
* **P4 — The secret is 128 bits of CSPRNG output.** Uniformly random, machine
  generated, read from a QR code.

## Invariants

Each is enforced by a gate.

**I-1 — The vocabulary is closed.** `Verb` has exactly two variants, `Controllable`
exactly three. `service_of` is a `const fn` returning one of six `&'static str`.
No service path is assembled from parts. *G2*

**I-2 — The process holds no state.** Nothing written is read back. Rate buckets
and the entity-state cache are disposable. The container runs read-only. *G4*

**I-3 — One config file is the complete denotation of the external surface.**
Runtime adds no authority. *G7*

**I-4 — Every `Authorized` value is constructed at config load.** `Authorized` and
`Admitted` have private fields and no public constructors. `ha::execute` accepts
`Admitted`. *G3*

**I-5 — The Cloudflare Tunnel is the sole ingress.** The guest surface is a UNIX
socket at a path fixed in code. No network listener exists and the container maps
no ports. *G9*

**I-6 — The config file and the add-on log are the management interface.** *G1, G5*

**I-7 — Tokens are long-lived. Revocation is rotation.** *G5*

**I-8 — Verbs are absolute and idempotent.** *G2*

**I-9 — URLs are stable.** A printed card's meaning changes when the config
changes. *G5*

**I-10 — The pure core takes time as an argument.** `policy/` and `gate/` perform
no I/O and read no clock. *G6*

## Constraints

Do not add these. Do not add a narrower version. Do not add one behind a feature
flag, a config option, or a `cfg` attribute — a feature that ships off by default
is still code, still reviewed, still maintained, and one flag from being on.

When a change matches a row, name the row, cite the decision, and stop.

| # | Constraint | Governing premise |
| --- | --- | --- |
| C-1 | Tokens carry no expiry, TTL, or refresh flow | P1, D-3 |
| C-2 | No admin UI, management page, or audit viewer | P2, D-4 |
| C-3 | No database, no state directory, no persisted counters | D-5 |
| C-4 | No sessions, cookies, or CSRF machinery | D-5 |
| C-5 | `Controllable` and `Verb` variants are owner-only | P3, D-2 |
| C-6 | No generic service passthrough, service allowlist, or free-form parameters | P3, D-2 |
| C-7 | Verbs are absolute; relative and toggle forms stay unrepresentable | D-7 |
| C-8 | URLs carry no signature, nonce, or embedded expiry | D-3 |
| C-9 | Token hashing is SHA-256 for lookup; key stretching is out of scope | P4, D-9 |
| C-10 | The listener is a UNIX socket at a constant path; no network listener, no host ports, and the path is never a setting | D-6 |
| C-11 | TLS termination, ACME, and certificate storage stay outside the program | D-6 |
| C-12 | Process supervision is the in-crate `step` machine | D-8 |
| C-13 | Responses issue no redirects and no URL canonicalisation | D-7 |
| C-14 | Cloudflare Access, CAPTCHA, bot challenge, and IP allowlists stay off | D-6 |
| C-15 | Config is declarative data: no templates, expressions, or plugins | D-1 |
| C-16 | One config file, no includes and no interpolation layers | D-5 |
| C-17 | The guest listener serves the six calls and the page | D-6 |
| C-18 | Token entropy is 128 bits | P4, D-9 |
| C-19 | No QR encoder, image codec, font, or PDF writer in the binary | D-10 |

**These constrain agents acting on their own judgment. They do not constrain the
owner.** When the owner asks for something in this table, name the row and the
premise it depends on, then build what they asked for. The owner owns the
tradeoff.

## Change protocol

Every non-trivial change states, in its commit message or PR body:

1. Which invariants it touches, by number, or `none`.
2. Which decision it operates under.
3. Whether it adds a dependency, and why the standard library suffices or does
   not.

A change touching an invariant needs the owner.

## Gates

Prose here is advisory. Gates are mechanical, and they exist before the first
non-trivial merge. Create them alongside the crate.

* **G1 — dependency allowlist.** `deny.toml`, run by `cargo-deny` in CI. Each
  ban names the invariant it protects, and the license allowlist names exactly
  the licenses in the shipped tree.
* **G2 — vocabulary lock.** `domain::tests::vocabulary_is_closed` asserts
  `Verb::ALL.len() == 2`, `Controllable::ALL.len() == 3`, and that `service_of`
  over the full product equals a hardcoded six-element literal.
* **G3 — barrier lock.** Not yet mechanical. `Authorized` and `Admitted` have
  private fields, so the barrier holds by module privacy; a `trybuild`
  compile-fail case proving it is still owed.
* **G4 — statelessness.** CI runs the built image with `--read-only` and
  `--network none`, and asserts the image ships `/run/guestpass` as a symlink to
  `/dev/shm/guestpass`.
* **G5 — banned identifiers.** `cargo xtask gates` (`xtask/src/gates.rs`),
  with an inline `// ALLOW-BANNED: <reason>` escape.
* **G6 — pure core.** `cargo xtask gates` asserts `src/policy/` and
  `src/gate/` contain no clock read and no I/O.
* **G7 — docs match code.** `config::tests::the_shipped_example_compiles`
  parses `guestpass.example.yaml` and asserts the URL list it denotes.
  `addon::tests::the_shipped_addon_manifest_matches_this_struct` parses
  `addon/config.yaml` and asserts its option keys and defaults equal
  `addon::Options`.
* **G8 — lints.** `#![deny(unsafe_code)]` crate-wide with one documented
  `#[allow]` in `tunnel::spawn` for `PR_SET_PDEATHSIG`, plus
  `cargo clippy --all-targets -- -D warnings`. (`forbid` cannot be locally
  overridden, so the gate is `deny` plus a single justified exception.)
* **G9 — no network listener.** `cargo xtask gates` scans `src/` for `TcpListener`,
  `SocketAddr`, and `0.0.0.0`. Proving the absence is stronger than checking a
  bind address: a program that cannot name a TCP listener cannot be configured
  into opening one.
* **G10 — workflow hygiene.** `actionlint` (which ShellChecks the embedded
  `run:` one-liners, the only shell in the repository), `zizmor
  --persona=pedantic`, and `yamllint` run over the workflows.
* **G12 — QR alphanumeric emission.** `tex::tests::urls_stay_qr_alphanumeric`
  asserts every emitted card URL is drawn from the QR alphanumeric set, so a
  card never falls back to byte mode. It holds by construction: `Origin`
  admits no path, and tokens, device ids, and verbs are upper-safe.
* **G11 — add-on publish parity.** `cargo xtask gates` asserts that the `arch:` list
  in `addon/config.yaml` equals the architecture set of the `deploy.yaml` build
  matrix, and that `image:` carries no `{arch}` placeholder. The Supervisor
  installs `<image>:<version>`, so an architecture the manifest offers and the
  matrix never builds is an install that fails at pull time.
* **G13 — release identity.** The typed algebra in `xtask/src/release.rs` is
  the only producer of published versions and tags (D-13); `cargo xtask
  resolve` is its shell. Its tests pin every branch on fixed inputs, and the
  gate tests show each gate firing: a gate that cannot fail is decoration.
  Both run under `cargo test --workspace` in CI and in `cargo xtask verify`.

A gate that fires marks the change for reconsideration. Weakening a gate to pass
requires the owner.

## CI trust boundary

`ci.yaml` runs on fork pull requests, so everything it executes is
attacker-controlled: the source, `build.rs`, and npm lifecycle scripts. It holds
`contents: read` and nothing else, receives no secrets, and publishes nothing.

`deploy.yaml` fires only on events a fork cannot cause: a push to `main`, a
published release, or a manual dispatch. There is deliberately no
`workflow_run` trigger, which would run with the base repository's elevated
token after a workflow a fork PR started. Ordering with CI is a `needs:` edge
instead.

The `build` and `manifest` jobs hold `packages: write` and are the only jobs in
the repository with any write capability. They restore **no cache**: build
caches are writable by workflows that run untrusted pull request code, so a job
producing a published artifact treats them as untrusted input and rebuilds from
source.

`build` runs one runner per architecture, each compiling for the machine it runs
on: `ubuntu-24.04` for amd64 and `ubuntu-24.04-arm` for aarch64. Each pushes by
digest under no tag, and `manifest` joins the digests into the one list that
`addon/config.yaml` names.

Every `uses:` is pinned to a full commit SHA. Every job declares
`timeout-minutes`. No `${{ }}` is interpolated into a `run:` block; values cross
through `env:` and are referenced as quoted shell variables.

## Repository shape

```
src/
  main.rs        shell: wiring, signals, shutdown ordering
  domain/        EntityId, Verb, Controllable, Vocabulary, TokenDigest, indices
  config/        RawConfig (serde) → compile → Registry     ← the one parse boundary
  policy/        Registry, position, apply, authorize, Authorized
  gate/          liveness, quota, admit, Admitted           ← pure, clock as argument
  ha/            the only module that speaks to Home Assistant
  http/          axum router, handlers, embedded frontend
  tunnel/        step (pure) + interpreter (shell)
  tex/           LaTeX emitter, unreachable from the service path
frontend/        Vite + React, embedded by rust-embed at build time
docs/            design, threat model, decisions
```

Dependencies point downward. `policy` depends on `domain` alone. `http` and `ha`
are unnameable from `policy` and `gate`.

## Conventions

* Rust 2024 edition. `let`-`else`, let-chains, and one `match` with guards.
* Alternatives are closed enums eliminated exhaustively. A new variant breaks the
  build everywhere it must be handled.
* Untrusted input crosses one smart constructor. Raw constructors stay private to
  their module.
* `Option` for expected absence, `Result` for expected failure. `unwrap`,
  `expect`, indexing, and `unreachable!` carry a comment naming the invariant that
  makes them total.
* Tests ship with the code, covering every variant and every rejection path.
* Commits follow Conventional Commits.

## Boundaries

Freely:

* Fix bugs, improve error messages, add tests, tighten types.
* Delete code and show the tests still pass.
* Correct documentation, including this file where it misdescribes the code.

Ask the owner:

* Anything touching an invariant.
* Anything in the constraints table.
* Any new dependency.
* Any change to the six-call table.

Never:

* Weaken or delete a gate to make a change pass.
* Ship a constrained feature behind a flag.
* Widen `Controllable` or `Verb` on your own judgment.
