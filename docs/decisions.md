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
* QR images cover head tokens only, so the output folder matches the wall.
* Deleting a `tokens` entry revokes immediately, with no window.
* URLs stay stable: no signatures, no nonces, no embedded expiry.

---

## D-4 — No management surface

**Premise.** The owner is one person who already edits YAML and already reads
Home Assistant's add-on log. Every operator-facing control that depends on
someone watching a dashboard would go unwatched.

**Decision.** The config file is the management interface. `explain` prints every
URL, call, and quota to the log on each reload. Tunnel faults raise
`persistent_notification.create` inside Home Assistant. QR images are written by
a separate one-shot command.

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
everything, tokens inline. The guest SPA holds its token in memory and sends a
bearer header.

**Consequences.**

* Restarts are free: no migrations, no backup, no corruption, no fsync.
* A bearer header is not attached cross-origin by browsers, so cross-site request
  forgery has no mechanism.
* The config file is a secret and needs `0600`.
* "What is exposed?" is answered by reading one file with no layering or
  interpolation to resolve.

---

## D-6 — The Cloudflare Tunnel is the sole ingress

**Premise.** The deployment target is a home network behind NAT or CGNAT, run by
someone who does not want to manage certificates or port forwarding.

**Decision.** cloudflared holds the only inbound path. The guest listener binds
loopback and refuses any other address. The container maps no host ports.
Cloudflare terminates TLS.

**Consequences.**

* Certificate management, ACME, renewal, port forwarding, and dynamic DNS are all
  outside the program.
* Exactly one hop reaches the listener, always on loopback, so `CF-Connecting-IP`
  is trustworthy and per-IP limits hold.
* Cloudflare reads request paths in plaintext, which includes `/t/` tokens. The
  `/g#` fragment form keeps interactive tokens local to the browser.
* Guest hostname configuration belongs to the owner: single-label subdomain, Bot
  Fight Mode off, Cache Everything off, Access off.
* A Cloudflare outage means guests cannot reach the lamp, including guests
  standing in the room.
* The guest listener serves the six calls and the page. Metrics and health live
  on loopback only.

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
SHA-256 digest in a `HashMap`.

**Consequences.**

* A full URL is about 55 characters, a version-3 QR, scannable off a small card.
* Guessing costs 2¹²⁷ expected requests against a rate-limited endpoint, so
  discovery is the vector that matters.
* Lookup is O(1) and timing-independent: an attacker cannot steer a digest, so
  there is no comparison to make constant-time.
* Fast hashing is correct for a uniformly random 128-bit secret; key-stretching
  work factors address low-entropy secrets.
