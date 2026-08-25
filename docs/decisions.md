# Decisions

Each entry states the local premise it rests on, the decision, and what follows.
The premise is the part that transfers: a change to guestpass is sound when the
premise still holds.

---

## D-1 — A capability server over a finite call tree

**Premise.** The owner needs to answer *"what can this token do?"* by reading a
file, and the guest UI is generated from that answer.

**Decision.** Authority is a finite, enumerable tree of calls declared in
configuration. `authorize` returns the constructed call. Policy is declarative
data with no computation: no templates, no expression language, no plugins.

**Consequences.**

* `explain` prints the complete denotation of a config at load.
* The tap-to-control page is generated from the same tree that authorizes.
* The effect boundary receives a call built by guestpass, so there is no guest
  request left to forward at the point of the effect.
* Evaluation on the request path is bounded by construction.

---

## D-2 — A closed vocabulary of six calls

**Premise.** Home Assistant's service surface grows every release. Guest exposure
must stay fixed across those releases without maintenance.

**Decision.** `Verb ∈ {On, Off}` and `Controllable ∈ {Light, Switch, Fan}`.
`service_of` is a `const fn` returning one of six `&'static str`. `Domain` is
absent from the type system, so `lock`, `cover`, `scene`, `script`,
`automation`, and `input_boolean` have no representation.

**Consequences.**

* The reachable endpoint set is a compile-time constant, independent of upstream
  releases and of configuration.
* `compile` needs no Home Assistant round-trip, so config validity holds while
  Home Assistant is down.
* Security review is reading one 3×2 table.
* `scene` and `input_boolean` stay out because their effect is defined by
  owner-supplied automation.
* Growth path: a new `Verb` variant, which breaks `service_of` and every
  exhaustive match until updated.

---

## D-3 — Rotation as the revocation mechanism

**Premise.** Tokens live on printed cards and NFC tags. Reissuing one costs a
trip to a printer. The owner knows when a leak happened: the party ended, the
contractor left, someone photographed the tag.

**Decision.** Tokens carry no expiry by default. Revocation is replacing the
token in the config file. `tokens` is a list whose head is current; entries with
`accepted_until` are retiring, giving an overlap window for swapping physical
tags.

**Consequences.**

* Steady-state cost is zero. Cost is incurred per incident, as one print.
* A printed card's meaning is a function of the config file, so control ids and
  pass ids are a published interface. Renaming one breaks cards.
* Printed cards cover head tokens only, so a page matches the wall.
* Deleting a `tokens` entry revokes immediately, with no window.
* URLs stay stable: no signatures, no nonces, no embedded expiry.

---

## D-4 — No management surface

**Premise.** The owner is one person who already edits YAML and already reads
Home Assistant's add-on log. Every operator-facing control that depends on
someone watching a dashboard would go unwatched.

**Decision.** The config file is the management interface. `explain` prints every
URL, call, and quota to the log on each reload. Tunnel faults raise
`persistent_notification.create` inside Home Assistant. Printable cards are a
LaTeX document emitted by a one-shot subcommand, or printed to the log for
installs without a shell.

**Consequences.**

* There are no admin routes, no authentication, and no authenticated surface
  adjacent to the anonymous one.
* Management actions diff, revert, and version-control.
* The config compiler is the only reviewer in the system, so its checks carry the
  safety that an operator would otherwise provide.

---

## D-5 — Stateless, one config file

**Premise.** Quotas are rates, and revocation lives
in the config. Nothing the process learns at runtime needs to outlive it.

**Decision.** The process persists nothing. Rate buckets and the entity-state
cache are disposable. The container runs read-only. One YAML file holds
everything, tokens inline. A served page reads its token from the path it was
served at.

**Consequences.**

* Restarts are free: no migrations, no backup, no corruption, no fsync.
* The URL carries the whole credential, so possession is the entire check and
  there is no second secret for a page to hold or a request to forge.
* The config file is a secret and needs `0600`.
* "What is exposed?" is answered by reading one file with no layering or
  interpolation to resolve.

---

## D-6 — The Cloudflare Tunnel is the sole ingress, over a UNIX socket

**Premise.** The deployment target is a home network behind NAT or CGNAT, run by
someone who does not want to manage certificates or port forwarding. Printed
cards make a stable hostname a requirement (D-3, I-9).

**Decision.** cloudflared holds the only inbound path, configured by a connector
token; Cloudflare holds the routing and terminates TLS. guestpass listens on a
UNIX domain socket and opens no network port. The tunnel's public hostname names
`unix:<socket>`.

**Consequences.**

* Certificate management, ACME, renewal, port forwarding, and dynamic DNS are all
  outside the program.
* Ingress configuration is outside the program, so there is nothing to generate,
  validate, or keep in sync with Cloudflare.
* A socket is a filesystem object, so no container network setting can expose the
  guest surface. Reachability rests on directory permissions (0700) and the
  socket mode (0600) rather than on a bind address plus a namespace
  configuration a later edit could flip.
* Exactly one peer reaches the listener and it is cloudflared in this container,
  so `CF-Connecting-IP` is trustworthy and per-IP limits hold.
* The socket needs a writable directory. The image ships `/run/guestpass` as a
  symlink to `/dev/shm/guestpass`, the one tmpfs every OCI runtime mounts, so a
  read-only rootfs holds the socket with no mount flag. `bind` follows a
  symlinked parent directory, so the path guestpass binds and the path named in
  the portal are one string. A tmpfs is memory, so statelessness holds.
* The socket path is a crate constant, not a setting. How guestpass and
  cloudflared are wired is an implementation detail of this program, so the fact
  lives in one place and the owner names it once in the portal. Its length and
  absoluteness are proved at compile time rather than checked at startup.
* Cloudflare reads request paths in plaintext, tokens included. Pass authority is
  one device and one verb, quota-bounded, which sets what such a log entry is
  worth.
* A Cloudflare outage means guests cannot reach the lamp, including guests
  standing in the room.
* A connector token is required, because a printed pass URL must keep working
  across restarts (I-9).

---

## D-7 — `GET` fires, and verbs are absolute

**Premise.** NFC tags, ESP32 buttons, and URL-fetch clients can issue a `GET` and
nothing else. Link previews, prefetchers, and scanners will fetch any URL a guest
pastes.

**Decision.** A pass marked `trigger: direct` fires on `GET`. Both verbs are
absolute, so the world state after N fetches equals the state after one. `HEAD`
never fires. Responses carry `no-store`. There are no redirects.

**Consequences.**

* A tag read twice, a retried request, and five link-preview fetches all leave
  one outcome.
* `toggle` and relative verbs are unrepresentable, which is what supports the
  above.
* A URL means one thing regardless of request headers; `User-Agent` and
  `Sec-Fetch-*` carry no authority.
* The URL a client is given is the URL that works, with no canonicalisation
  bounce.
* Passes without `trigger: direct` render a confirmation page on `GET` and fire
  on `POST`.

---

## D-8 — cloudflared supervised in-process

**Premise.** Transient Cloudflare faults are routine. Rate-limit buckets live in
memory, so a process restart resets them.

**Decision.** A pure Mealy machine supervises the child: readiness by `/ready`
probe, `Degraded` for a live process with zero edge connections, decorrelated
jittered backoff capped at 900 s, reset after 60 s of `Ready`.

**Consequences.**

* A transient upstream fault is absorbed without dropping guest connections or
  resetting quota state.
* A live-but-useless connector is detected and restarted.
* The full self-healing behaviour is testable with a fake clock and no processes.
* Docker's `init: true` supplies a `waitpid` reaper.

---

## D-9 — 128-bit bearer tokens, digest-keyed lookup

**Premise.** Tokens are generated by a CSPRNG and read from a QR code. Entropy is
free; QR density is not.

**Decision.** 128 bits, base32 unpadded, 26 characters. Storage and lookup are by
SHA-256 digest of the case-folded token in a `HashMap`.

**Consequences.**

* A full URL is about 55 characters, which stays a small QR at error-correction
  level H, scannable off a card.
* Guessing costs 2¹²⁷ expected requests against a rate-limited endpoint, so
  discovery is the vector that matters.
* After `compile` returns, the process holds digests only: there is no
  plaintext token for a log line, a `Debug` impl, or a future endpoint to
  leak. The config file and Cloudflare's edge logs still hold plaintext, so
  the digest closes exactly one channel: process memory.
* No comparison ever touches a secret. `PassToken` has no `PartialEq`; it is
  parsed, digested, dropped. The map is keyed by the full 256-bit digest, and
  its per-process SipHash key keeps bucket placement unsteerable. This is also
  why the map stays a `HashMap` at n ≈ 10, where a linear scan usually wins:
  the scan would need a constant-time comparison on every entry to close the
  early-exit timing signal, which is more machinery than the map.
* An unkeyed fast hash is correct because the preimage is a uniformly random
  128-bit secret; key-stretching KDFs compensate for low-entropy passwords and
  would buy startup latency and nothing else.

---

## D-10 — Printing is a LaTeX document

**Premise.** The owner has a printer and either a TeX installation or a browser.
Add-on installs offer no shell, so any command must be reachable from the Home
Assistant UI or from a copy of the config on the owner's own machine.

**Decision.** `guestpass tex` writes a complete LaTeX document to stdout, and the
add-on option `emit_tex: true` prints the same document to the log. Rendering
happens in the owner's toolchain.

**Consequences.**

* No QR encoder, image codec, font, or PDF writer enters the binary.
* `tex` is a pure function of the config, so the standalone binary run against a
  copy of `guestpass.yaml` produces the same bytes as the add-on.
* The service needs no writable path, and the output reaches the owner through
  the log they already read.
* The card layout is a text file the owner can edit.
* The document depends on `qrcode` (LPPL 1.3), which draws with the TeX `\rule`
  primitive and needs no shell-escape, external program, or graphics package. It
  has been at v1.51 since 2015 and implements ISO 18004:2006, which is frozen.

---

## D-11 — One manifest list, built natively per architecture

**Premise.** The Supervisor installs `<image>:<version>` and picks the entry
matching the machine it runs on. Both facts come from `addon/config.yaml`.
GitHub offers `ubuntu-24.04-arm`, free and unlimited on public repositories.

**Decision.** `deploy.yaml` runs one runner per architecture, each compiling for
the machine it runs on, pushing by digest under no tag. A final job joins the
digests into one manifest list, which is what `image:` names.

**Consequences.**

* A Rust release build compiles at native speed. The emulator leaves the tree.
* The runner label lives in the workflow and the architecture list lives in the
  manifest. Gate G11 asserts the two architecture sets agree.
* No architecture-suffixed tag is pullable, so an install cannot pull machine
  code for the wrong architecture.
* A release whose git tag disagrees with the manifest `version` stops the
  workflow, because the Supervisor would otherwise be told to pull a tag nobody
  published.
* Each architecture carries its own provenance and SBOM attestation, produced by
  the build that pushed it.

---

## D-12 — Case-insensitive tokens, uppercase QR encoding

**Premise.** QR alphanumeric mode covers `0-9 A-Z $ % * + - . / :` and space at
5.5 bits per character; byte mode costs 8. At a fixed card width fewer modules
print larger, and module size is what makes a hallway scan work.

**Decision.** Tokens are case-insensitive. `PassToken::parse` folds to ASCII
lowercase and is the type's only constructor, and `PassToken::digest` is
`TokenDigest`'s only constructor, so the config side and the request side
cannot disagree about spelling. Cards encode the whole URL uppercased.
`tunnel.public_url` is parsed to a pathless `Origin`.

**Consequences.**

* Measured at error-correction level H: a 51-character pass URL drops from
  version 6 (41×41 modules) to version 5 (37×37); a 78-character device/verb
  URL drops from version 8 (49×49) to version 6 (41×41). Modules print 11% and
  20% larger at the same card width.
* RFC 3986 makes scheme and host case-insensitive and paths case-sensitive, so
  uppercasing is meaning-preserving exactly when the URL has no owner-supplied
  path. `Origin` rejects one at compile, which is what makes the emitter total.
* The folded alphabet holds 36 symbols, so 26 characters carry about 134 bits
  and the 128-bit floor of D-9 stands.
* Device ids and verbs match path segments case-insensitively, folded at the
  comparison, allocation-free. The `/t/` literal's case-variant set has
  cardinality 2 and both are routes.
* Embedded asset paths keep exact case: Vite content hashes are mixed-case,
  which is why normalization happens where the closed vocabulary is consulted
  and never on the raw path.
* Gate G12 asserts every emitted card URL stays inside the QR alphanumeric set.
