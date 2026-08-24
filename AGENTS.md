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

**I-5 — The Cloudflare Tunnel is the sole ingress.** The guest listener binds
loopback. The container maps no host ports. *G9*

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
| C-10 | The listener binds loopback; the container maps no host ports | D-6 |
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

* **G1 — dependency allowlist.** `cargo-deny` with an explicit `[bans]` list.
  Denied by name at minimum: `sqlx`, `rusqlite`, `diesel`, `redis`, `sled`,
  `jsonwebtoken`, `argon2`, `bcrypt`, `pbkdf2`, `tower-sessions`, `tower-cookies`,
  `rustls-acme`, `openssl`, `mlua`, `rhai`, `tera`, `handlebars`, `qrcode`,
  `qrcodegen`, `image`, `printpdf`, `resvg`, `usvg`.
* **G2 — vocabulary lock.** A test asserting `Verb::COUNT == 2`,
  `Controllable::COUNT == 3`, and that `service_of` over the full cartesian
  product equals a hardcoded six-element literal. Its failure message cites I-1.
* **G3 — barrier lock.** `trybuild` compile-fail cases proving `Authorized` and
  `Admitted` are unconstructable outside `policy` and `gate`, and that
  `ha::execute` accepts only `Admitted`.
* **G4 — statelessness.** A CI job running the container with `--read-only` and
  no writable volumes through a full request smoke test.
* **G5 — banned identifiers.** A grep over `src/**/*.rs` for `cookie`, `session`,
  `jwt`, `sqlite`, `redirect`, `nonce`, `expires_in`, `refresh_token`. An inline
  `// ALLOW-BANNED: <reason>` suppresses one line; writing the reason is the
  point.
* **G6 — pure core.** A grep asserting `src/policy/` and `src/gate/` contain no
  `Instant::now`, `SystemTime::now`, `std::fs`, `tokio`, or `reqwest`.
* **G7 — docs match code.** A test that parses the config example in `README.md`,
  runs `compile` and `explain`, and asserts the URL list matches the README table.
* **G8 — lints.** `#![forbid(unsafe_code)]` crate-wide, with one documented
  `#[allow(unsafe_code)]` in `tunnel::spawn` for `PR_SET_PDEATHSIG`.
  `cargo clippy -- -D warnings` in CI.
* **G9 — loopback bind.** A test that the guest listener constructor rejects any
  non-loopback address.

A gate that fires marks the change for reconsideration. Weakening a gate to pass
requires the owner.

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
