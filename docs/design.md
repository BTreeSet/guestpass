# Design

The URL is an object capability naming a position in a finite tree of calls. Path
segments after the token apply arguments. guestpass constructs the upstream call
from its own configuration; the guest supplies only a position in that tree.

## Pipeline

```
YAML ──compile──▶ Registry ──apply*──▶ PartialCall ──admit──▶ Admitted ──execute──▶ HA
     (parse boundary)  (pure fold)                 (pure, clock as arg)   (shell)
```

`compile` runs at load. `apply` and `admit` run per request and touch no I/O.

Two clocks, deliberately distinct: `OffsetDateTime` for validity windows, which
must survive a restart and match what the owner wrote in the config;
`Instant` for backoff and probe scheduling, which must be monotonic.

## Domain model

### Refined primitives

Constructors are private. Each type has one parse boundary.

```rust
pub struct PassToken(SecretBox<str>);   // ≥128 bits; no Debug/Display/Serialize
pub struct TokenDigest([u8; 32]);       // SHA-256(token) — the stored form
pub struct DeviceId(Box<str>);          // guest-visible name, matched against path segments
pub struct PassIx(u16);                 // index into Registry::passes
pub struct DeviceIx(u16);               // index into Registry::devices
```

`PassToken` has no `Debug` impl, so no code path formats it into a log line.

`DeviceId` is the wire name; `DeviceIx` is the resolved reference. `compile`
converts one into the other.

### Vocabulary

Both closed vocabularies share one interface. This is the shape a fourth
`Controllable` slots into.

```rust
pub trait Vocabulary: Copy + Sized + 'static {
    const ALL: &'static [Self];
    fn token(self) -> &'static str;

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.token() == s)
    }
}

pub enum Verb { On, Off }
pub enum Controllable { Light, Switch, Fan }

impl Vocabulary for Verb {
    const ALL: &'static [Self] = &[Self::On, Self::Off];
    fn token(self) -> &'static str { match self { Self::On => "on", Self::Off => "off" } }
}

impl Vocabulary for Controllable {
    const ALL: &'static [Self] = &[Self::Light, Self::Switch, Self::Fan];
    fn token(self) -> &'static str {
        match self { Self::Light => "light", Self::Switch => "switch", Self::Fan => "fan" }
    }
}
```

`parse` is written once and derived from `ALL`, so a new variant reaches path
parsing and config parsing without an edit. Cost is a linear scan over `ALL`,
which is 2 and 3 elements.

```rust
pub struct EntityId { kind: Controllable, object_id: Box<str> }

const fn service_of(k: Controllable, v: Verb) -> &'static str {
    match (k, v) {
        (Light,  On) => "light/turn_on",   (Light,  Off) => "light/turn_off",
        (Switch, On) => "switch/turn_on",  (Switch, Off) => "switch/turn_off",
        (Fan,    On) => "fan/turn_on",     (Fan,    Off) => "fan/turn_off",
    }
}
```

`service_of` stays an explicit match over literals, so a new `Controllable`
forces a decision at exactly the point that carries security weight. Deriving it
from `token` would assemble a path from parts, which I-1 forbids.

`Domain` is absent from the type system. `EntityId::parse` accepts the prefixes
`Controllable::ALL` yields; restriction lives in the vocabulary. `compile` has no
classification stage.

`Verb` has two variants, both absolute, so idempotence is a property of the type.

The one string built at runtime is the request body
`{"entity_id":"light.living_room_floor"}`, from two components that already
crossed the parse boundary.

**Adding a fourth `Controllable` is three edits**, each caught by the compiler or
by a gate: one entry in `ALL` plus a `token` arm, two arms in `service_of`, and
G2's expected literal.

### Authority

```rust
pub struct Authorized { entity: EntityId, verb: Verb }   // private fields, no public constructor
pub struct Admitted(Authorized);                         // private field, no public constructor

impl Admitted {
    pub(crate) fn service(&self) -> &'static str { service_of(self.0.entity.kind, self.0.verb) }
    pub(crate) fn entity(&self) -> &EntityId { &self.0.entity }
}
```

The service path is derived on demand, so an `Authorized` naming a fan and a
`light/turn_on` path is unrepresentable.

`ha::execute` accepts `Admitted`. `Admitted`'s only constructor is `admit`, whose
only input is `Authorized`, whose only constructor is `authorize`. The type
system carries the proof that every call reaching Home Assistant was authorized
and passed the quota.

`Authorized` values live in the `Registry` for the life of a config. `Admitted`
values are per-request. The second newtype is what forces the quota check into
every path to the effect.

`Authorized` derives `Clone`: cloning a value already held creates no authority.

### Position

Config-time and request-time positions share one ladder. `compile` resolves the
first; the request fold walks the second.

```rust
pub enum Scope {                                   // stored, owned
    Pass   { devices: Box<[DeviceIx]> },           // arity 2
    Device { device:  DeviceIx },                  // arity 1
    Call   { call:    Authorized },                // arity 0
}

pub enum PartialCall<'r> {                         // in flight, borrowed
    Pass   { pass: &'r CompiledPass },
    Device { pass: &'r CompiledPass, device: &'r Device },
    Call   { call: Authorized },
}

pub fn position<'r>(pass: &'r CompiledPass) -> PartialCall<'r>;   // total, three arms
```

Same variant names and same order, so the correspondence is checkable by eye.
The borrow is why they are two types.

### Registry

Immutable, replaced wholesale behind an `ArcSwap` on reload.

```rust
pub struct Registry {
    by_digest: HashMap<TokenDigest, TokenBinding>,
    passes:    Box<[CompiledPass]>,
    devices:   Box<[Device]>,
    pinned:    HashSet<EntityId>,       // union, for the state subscription
}

pub struct TokenBinding {
    pass:           PassIx,
    accepted_until: Option<OffsetDateTime>,   // None ⇒ current, Some ⇒ retiring
}
```

Currency is read off `accepted_until`, so a token that is both current and
retiring has no representation. `compile` admits one `None` binding per pass,
taken from the head of the `tokens` list.

`Box<[T]>` states that these collections never grow after compile.

Each request clones the `Arc` once at entry and sees one config snapshot for its
whole lifetime.

## The request fold

```rust
pub fn apply<'r>(p: PartialCall<'r>, seg: &str) -> Result<PartialCall<'r>, Denial>;
```

```rust
let end = segments.iter().try_fold(position(pass), apply)?;

match end {
    PartialCall::Call { call }   => fire(admit(call, liveness, quota)?),
    PartialCall::Device { .. }   => render(Verb::ALL),
    PartialCall::Pass { pass }   => render(pass.devices()),
}
```

The fold's result is the answer. An unsaturated position is a page to render, so
there is no separate forcing step and no error type for arriving short.

Each `apply` step narrows. `apply` on a `Call` position returns
`Denial::TrailingSegment`.

Bounds: at most 2 segments, at most 512 bytes of URL. Query strings are rejected,
leaving one binding mechanism.

Device lookup inside `apply` is a linear scan over the pass's `Box<[DeviceIx]>`
comparing `DeviceId`, which is O(D) with D ≈ 10 over contiguous memory.

## Denial

```rust
pub enum ShapeDenial    { NoSuchDevice, NoSuchVerb, TrailingSegment }   // policy
pub enum LivenessDenial { Expired, Retired, QuotaExhausted { retry_after } }  // gate
```

The two are produced by different functions and eliminated at different sites,
so they stay separate types.

Every `ShapeDenial` renders as the same bare 404 the router serves for an
unknown token and an unknown path, which keeps probe responses uniform without a
coarsening function to maintain.

`LivenessDenial` detail reaches the guest, being actionable and public.
`Retired` returns plain text an Apple Shortcut can display: *"This pass has been
replaced. Ask your host for a new one."*

## Effect boundary

| Effect | Idempotent | Retry | Scope |
| --- | --- | --- | --- |
| `POST /api/services/<six>` | yes, by construction | one, 5 s timeout, jittered | single call |
| HA WebSocket subscribe | — | reconnect, jittered backoff | refetch `get_states`, readings go `Stale` until it lands |
| Config reload (inotify) | yes | none | last-good `Registry` retained on parse error |
| cloudflared lifecycle | — | capped backoff | pure `step` plus interpreter |

### Home Assistant link

```rust
pub struct HaLink { base: Url, token: SecretString }

pub fn detect(env: &Env) -> Result<HaLink, LinkError>;
```

`SUPERVISOR_TOKEN` with `http://supervisor/core`, or a configured long-lived
token with a configured base. Both reduce to a bearer and a base, so provenance
is logged at detection and carried no further. The add-on requests
`homeassistant_api: true`, the narrowest grant reaching the six endpoints.

### Read path

Every pinned entity is polled on a 15 second interval. At around ten entities on
a LAN service that is 40 requests a minute, which removes the WebSocket client,
its auth handshake, and its reconnect state machine from the program.

```rust
pub enum Reading {
    Unknown,                    // no reading yet, or Home Assistant reports unknown
    Offline,                    // Home Assistant reports the device unavailable
    Live  { on: bool },
    Stale { on: bool },         // last known, upstream read failing
}
```

Four variants, each rendering differently. A failed read degrades `Live` to
`Stale` and keeps the value, so a broken link shows what was true rather than
nothing.

Readings are a cache held in one `RwLock<HashMap<EntityId, Reading>>`. Losing
them on restart costs one poll interval, which is why nothing here is persisted.

After a fired call the entity is re-read immediately, so the response reports
what happened rather than predicting it.

The projection from a Home Assistant state payload into `Reading` is an
allowlist total function, so a new upstream attribute stays invisible until
named.

### Ingress

```rust
pub const SOCKET_PATH: &str = "/run/guestpass/guest.sock";

const _: () = assert!(SOCKET_PATH.len() <= MAX_SOCKET_PATH);   // sun_path holds 108 bytes
const _: () = assert!(SOCKET_PATH.as_bytes()[0] == b'/');

pub fn bind_socket() -> Result<tokio::net::UnixListener, SocketError>;
```

The guest surface is a UNIX domain socket and there is no network listener. A
socket is a filesystem object, so no container network setting can expose it:
reachability rests on the directory mode (0700) and the socket mode (0600).

The path is a constant. How guestpass and cloudflared are wired is an
implementation detail of this program, so the fact lives in one place and the
owner names it once, as the public hostname's service in the Zero Trust portal.
Its length and absoluteness are proved at compile time. The runtime errors that
remain are a live socket already held and plain filesystem failure.

cloudflared runs as `cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:<m>
run --token <T>`. Cloudflare holds the routing, so no origin argument is passed
here; cloudflared decodes remote configuration through the same `validateIngress`
that handles the `unix:` scheme locally.

`tunnel.public_url` is required, so `explain` and the LaTeX emitter always render
whole URLs.

### Tunnel supervisor

A Mealy machine over the child process. `step` is pure, so a fake clock and a
scripted event sequence exercise a forty-restart crash loop in microseconds.

```rust
pub enum Supervised {
    Faulted { fault: PreflightFault },             // owner action needed; re-checked on reload
    Backoff { until: Instant, attempt: u32 },
    Running { child: Pid, since: Instant, phase: Phase },
    Stopped,
}

pub enum Phase {
    Starting { attempt: u32 },
    Ready    { conns: NonZeroU8 },
    Degraded { misses: u8 },
    Draining { deadline: Instant },
}

pub struct Transition { next: Supervised, act: Option<Act>, wake: Option<Instant> }

pub enum Act { Spawn, Probe, Signal(Sig), Notify(Health) }

pub fn step(s: Supervised, e: Event, now: Instant) -> Transition;
```

`child` and `since` are factored into `Running`, so "is there a process to
signal?" is one match arm. A new phase inherits child handling.

`PreflightFault` covers missing credentials, missing binary, wrong architecture,
and unreadable credentials.

`Act::Signal` carries no `Pid`: the interpreter reads it from `Running`.

Transitions are logged by the interpreter, uniformly, as `from → event → to`.
Instrumentation stays at the effect boundary and out of `step`.

Readiness comes from cloudflared's `/ready` metrics endpoint on loopback, which
reports connected edge connections and is stable across versions.

`Degraded` covers a live process with zero edge connections. Three consecutive
misses, about 45 seconds, trigger a restart.

Backoff resets after `Ready` has held for 60 seconds, so a process that is ready
for 200 ms and dies keeps escalating.

Timing budget: readiness probe 1 s, deadline 30 s; health probe 15 s; degraded
tolerance 3 misses; backoff decorrelated jitter, base 1 s, cap 900 s; child grace
20 s; total shutdown deadline 30 s.

### Lifecycle guarantees

While guestpass runs, a healthy connector is running or actively retrying. When
guestpass stops, cloudflared stops with it, enforced in three layers:
`kill_on_drop(true)`, a `Drop` guard sending TERM then KILL, and
`prctl(PR_SET_PDEATHSIG, SIGKILL)` in `pre_exec` with a `getppid() == 1` re-check
closing the fork/prctl race. The third layer survives `kill -9` of the parent.

Shutdown order: SIGTERM cloudflared so it drains, drain the HTTP server, exit.

stderr is drained into a bounded ring and forwarded at `DEBUG`, dropping with a
counter on overflow. A consumed pipe keeps the child from blocking on a full
buffer.

## Complexity budget

Sizes: devices D ≈ 10, passes P ≈ 10, tokens T ≈ 2P, guests G ≈ 10², Home
Assistant events ≈ 10²/s against ~10⁴ entities.

| Operation | Bound | Structure |
| --- | --- | --- |
| token → pass | O(1), timing-independent | `HashMap<TokenDigest, TokenBinding>`; an attacker cannot steer a SHA-256 digest |
| `Vocabulary::parse` | O(\|ALL\|), ≤3 | linear scan over a `&'static` slice |
| device lookup in `apply` | O(D), D ≈ 10 | linear scan over contiguous `Box<[DeviceIx]>` |
| path fold | O(D), ≤2 segments | two `apply` steps |
| `service_of` | O(1) | `const fn` over a 3×2 match |
| liveness + quota | O(1) | in-memory token bucket |
| per-IP limit | O(1) amortized, bounded memory | fixed-capacity LRU; capacity is the memory bound |
| HA event ingest | O(1)/event | `HashSet` on `pinned` |
| state fan-out | O(1) publish, O(waiters) wake | `watch` per entity |
| `step` | O(1) | one match |
| compile | O(D + P) | one pass, no HA round-trip |
| brute force | 2¹²⁷ expected requests | see threat model |

Device lookup stays a scan because D ≈ 10 over contiguous memory beats a per-pass
hash map on both memory and cache behaviour. A `HashMap<DeviceId, DeviceIx>` per
pass becomes worthwhile past roughly D ≈ 64.

Guest-supplied strings are `HashMap` keys in small bounded maps, where std's
randomly-seeded SipHash covers collision flooding. Request bodies cap at 4 KiB.

## Module layout

```
domain/   EntityId, Verb, Controllable, Vocabulary, TokenDigest, indices
config/   RawConfig (serde) → compile → Registry     ← the one parse boundary
policy/   position, apply, authorize, Authorized     ← pure
gate/     liveness, quota, admit, Admitted           ← pure, clock as argument
ha/       the only module that speaks to Home Assistant
http/     axum router, extractors, responses
tunnel/   step (pure) + interpreter (shell)
tex/      one-shot LaTeX emitter, unreachable from the service path
```

`Registry` lives in `policy` because `Scope::Call` holds an `Authorized`, whose
constructor is private to the barrier module.

Dependencies point downward. `policy` depends on `domain` alone. `http` and `ha`
are unnameable from `policy` and `gate`.

`compile` accumulates independent errors across devices and passes, and fails
fast within one dependent chain: resolve the device, then check the verb against
its `Controllable`. One run reports every mistake in the file.

## Evolution

Sums likely to grow, where exhaustive matching turns an addition into
compiler-guided edits:

* **`Controllable`** — three edits, listed above. Owner-only; see `AGENTS.md`.
* **`Verb`** — brightness fits as `Verb::Level(Percent)`, keeping the vocabulary
  closed and `service_of` exhaustive. Costs one path segment, and `Reading` keeps
  its alignment because state stays a `Verb`.
* **`Window`** — `Always | Until(t) | Daily { from, to }`. The daily variant is
  the declarative, stateless bound on hours of use.
* **`ShapeDenial` / `LivenessDenial`** — new refusal reasons. Shape additions are
  coarsened structurally.
* **`Phase`** — new supervisor phases inherit child handling from `Running`.

Wire formats carry `version: 1` (config) and `schema: 1` (page payloads).

The invariant most at risk: a maintainer who needs one uncovered Home Assistant
service and adds a passthrough variant. Gate G2 fires on that. The supported
route is a new `Verb` variant, which is a twenty-line change.
