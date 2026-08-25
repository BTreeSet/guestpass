//! Compiled authority and the request fold. Pure: no I/O, no clock, no randomness.
//!
//! [`Authorized`] has private fields, so [`authorize`] is the only way to obtain
//! one anywhere in the program. Every value of that type in the process is
//! constructed by `config::compile` before the first request arrives.

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::domain::{
    DeviceId, DeviceIx, EntityId, Origin, PassIx, TokenDigest, Verb, Vocabulary, service_of,
};

/// A call guestpass is permitted to make.
///
/// The service path is derived on demand rather than stored, so an `Authorized`
/// naming a fan alongside a `light/turn_on` path has no representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    entity: EntityId,
    verb: Verb,
}

impl Authorized {
    #[must_use]
    pub fn service(&self) -> &'static str {
        service_of(self.entity.kind(), self.verb)
    }

    #[must_use]
    pub const fn entity(&self) -> &EntityId {
        &self.entity
    }

    #[must_use]
    pub const fn verb(&self) -> Verb {
        self.verb
    }
}

/// The sole constructor of [`Authorized`].
#[must_use]
pub fn authorize(device: &Device, verb: Verb) -> Authorized {
    Authorized {
        entity: device.entity.clone(),
        verb,
    }
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: DeviceId,
    pub label: Box<str>,
    pub entity: EntityId,
}

/// Whether a plain `GET` on a saturated path fires the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// `GET` renders a confirmation; `POST` fires. The default.
    Interactive,
    /// `GET` fires. Required by NFC tags and URL-fetch clients.
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Always,
    Until(OffsetDateTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub per_minute: u32,
}

/// How much of the call a pass has already applied.
///
/// Mirrors [`PartialCall`] variant for variant; the borrow is why they are two
/// types rather than one.
#[derive(Debug, Clone)]
pub enum Scope {
    /// Arity 2: `/t/<token>/<device>/<verb>`
    Pass { devices: Box<[DeviceIx]> },
    /// Arity 1: `/t/<token>/<verb>`
    Device { device: DeviceIx },
    /// Arity 0: `/t/<token>`
    Call { call: Authorized },
}

#[derive(Debug, Clone)]
pub struct CompiledPass {
    pub id: Box<str>,
    pub label: Box<str>,
    pub scope: Scope,
    pub trigger: Trigger,
    pub window: Window,
    pub quota: Quota,
}

/// A token's binding. Currency is read off `accepted_until`, so a token that is
/// both current and retiring has no representation.
#[derive(Debug, Clone, Copy)]
pub struct TokenBinding {
    pub pass: PassIx,
    pub accepted_until: Option<OffsetDateTime>,
}

/// The compiled config: immutable, replaced wholesale on reload.
#[derive(Debug)]
pub struct Registry {
    by_digest: HashMap<TokenDigest, TokenBinding>,
    passes: Box<[CompiledPass]>,
    devices: Box<[Device]>,
    pinned: Box<[EntityId]>,
    origin: Origin,
}

impl Registry {
    #[must_use]
    pub fn new(
        by_digest: HashMap<TokenDigest, TokenBinding>,
        passes: Box<[CompiledPass]>,
        devices: Box<[Device]>,
        origin: Origin,
    ) -> Self {
        let mut pinned: Vec<EntityId> = devices.iter().map(|d| d.entity.clone()).collect();
        pinned.sort_unstable_by_key(ToString::to_string);
        pinned.dedup();
        Self {
            by_digest,
            passes,
            devices,
            pinned: pinned.into_boxed_slice(),
            origin,
        }
    }

    #[must_use]
    pub fn binding(&self, digest: &TokenDigest) -> Option<TokenBinding> {
        self.by_digest.get(digest).copied()
    }

    #[must_use]
    pub fn pass(&self, ix: PassIx) -> &CompiledPass {
        &self.passes[ix.0 as usize]
    }

    #[must_use]
    pub fn device(&self, ix: DeviceIx) -> &Device {
        &self.devices[ix.0 as usize]
    }

    #[must_use]
    pub fn passes(&self) -> &[CompiledPass] {
        &self.passes
    }

    #[must_use]
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    /// Entities any pass can reach, for the state poller.
    #[must_use]
    pub fn pinned(&self) -> &[EntityId] {
        &self.pinned
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        self.origin.as_str()
    }
}

/// A refusal produced by the request fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeDenial {
    NoSuchDevice,
    NoSuchVerb,
    TrailingSegment,
}

/// How much of the call the request has applied so far.
#[derive(Debug, Clone)]
pub enum PartialCall<'r> {
    Pass {
        pass: &'r CompiledPass,
        devices: &'r [DeviceIx],
    },
    Device {
        pass: &'r CompiledPass,
        device: &'r Device,
    },
    Call {
        pass: &'r CompiledPass,
        call: Authorized,
    },
}

impl<'r> PartialCall<'r> {
    #[must_use]
    pub const fn pass(&self) -> &'r CompiledPass {
        match self {
            Self::Pass { pass, .. } | Self::Device { pass, .. } | Self::Call { pass, .. } => pass,
        }
    }
}

/// The request fold's starting position, taken from the pass's declared scope.
#[must_use]
pub fn position<'r>(registry: &'r Registry, pass: &'r CompiledPass) -> PartialCall<'r> {
    match &pass.scope {
        Scope::Pass { devices } => PartialCall::Pass { pass, devices },
        Scope::Device { device } => PartialCall::Device {
            pass,
            device: registry.device(*device),
        },
        Scope::Call { call } => PartialCall::Call {
            pass,
            call: call.clone(),
        },
    }
}

/// Apply one path segment. Each step narrows; no step widens.
///
/// # Errors
/// Returns [`ShapeDenial`] when the segment names no device or verb the position
/// admits, or when the position is already saturated.
pub fn apply<'r>(
    registry: &'r Registry,
    position: PartialCall<'r>,
    segment: &str,
) -> Result<PartialCall<'r>, ShapeDenial> {
    match position {
        // Linear scan over the pass's devices: D is around 10 over contiguous
        // memory, which beats a per-pass hash map on memory and cache behaviour
        // until roughly D = 64.
        PartialCall::Pass { pass, devices } => devices
            .iter()
            .map(|ix| registry.device(*ix))
            // Case-insensitive against the canonical lowercase id (D-12): the
            // fold fuses into the comparison, so the scan stays allocation-free.
            .find(|d| d.id.as_str().eq_ignore_ascii_case(segment))
            .map(|device| PartialCall::Device { pass, device })
            .ok_or(ShapeDenial::NoSuchDevice),

        PartialCall::Device { pass, device } => Verb::parse(segment)
            .map(|verb| PartialCall::Call {
                pass,
                call: authorize(device, verb),
            })
            .ok_or(ShapeDenial::NoSuchVerb),

        // Extra segments are rejected, never ignored.
        PartialCall::Call { .. } => Err(ShapeDenial::TrailingSegment),
    }
}

/// Fold a whole path. At most two segments reach this.
///
/// # Errors
/// Propagates the first [`ShapeDenial`] any step produces.
pub fn walk<'r, I>(
    registry: &'r Registry,
    pass: &'r CompiledPass,
    segments: I,
) -> Result<PartialCall<'r>, ShapeDenial>
where
    I: IntoIterator<Item = &'r str>,
{
    segments
        .into_iter()
        .try_fold(position(registry, pass), |p, s| apply(registry, p, s))
}

/// Every call a pass can reach, with the device it names, for `explain` and the
/// LaTeX emitter. The device travels alongside the call because a printed card
/// is titled with the physical object, not with the credential.
#[must_use]
pub fn reachable<'r>(
    registry: &'r Registry,
    pass: &CompiledPass,
) -> Vec<(String, &'r Device, Verb)> {
    match &pass.scope {
        Scope::Call { call } => registry
            .devices()
            .iter()
            .find(|d| &d.entity == call.entity())
            .map(|d| vec![(String::new(), d, call.verb())])
            .unwrap_or_default(),
        Scope::Device { device } => {
            let d = registry.device(*device);
            Verb::ALL
                .iter()
                .map(|&v| (format!("/{}", v.token()), d, v))
                .collect()
        }
        Scope::Pass { devices } => devices
            .iter()
            .map(|ix| registry.device(*ix))
            .flat_map(|d| {
                Verb::ALL
                    .iter()
                    .map(move |&v| (format!("/{}/{}", d.id, v.token()), d, v))
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, entity: &str) -> Device {
        Device {
            id: DeviceId::parse(id).expect("device id"),
            label: id.into(),
            entity: EntityId::parse(entity).expect("entity"),
        }
    }

    fn registry_with(scope: Scope) -> Registry {
        let devices = vec![
            device("lamp", "light.living_room_floor"),
            device("plug", "switch.desk"),
        ];
        let pass = CompiledPass {
            id: "guest".into(),
            label: "Guest".into(),
            scope,
            trigger: Trigger::Interactive,
            window: Window::Always,
            quota: Quota { per_minute: 6 },
        };
        Registry::new(
            HashMap::new(),
            vec![pass].into_boxed_slice(),
            devices.into_boxed_slice(),
            Origin::parse("https://gp.example.com").expect("origin"),
        )
    }

    fn arity2() -> Registry {
        registry_with(Scope::Pass {
            devices: vec![DeviceIx(0), DeviceIx(1)].into_boxed_slice(),
        })
    }

    #[test]
    fn fold_reaches_a_call_at_arity_two() {
        let reg = arity2();
        let pass = reg.pass(PassIx(0));
        let end = walk(&reg, pass, ["lamp", "on"]).expect("saturates");
        let PartialCall::Call { call, .. } = end else {
            panic!("expected a saturated position")
        };
        assert_eq!(call.service(), "light/turn_on");
        assert_eq!(call.entity().to_string(), "light.living_room_floor");
    }

    #[test]
    fn stopping_short_yields_a_renderable_position() {
        let reg = arity2();
        let pass = reg.pass(PassIx(0));
        assert!(matches!(
            walk(&reg, pass, []).expect("valid"),
            PartialCall::Pass { .. }
        ));
        assert!(matches!(
            walk(&reg, pass, ["lamp"]).expect("valid"),
            PartialCall::Device { .. }
        ));
    }

    /// A QR card prints the whole URL uppercased (D-12), so the fold walks
    /// the same tree the lowercase spelling does.
    #[test]
    fn uppercase_segments_walk_the_same_tree() {
        let reg = arity2();
        let pass = reg.pass(PassIx(0));
        assert!(matches!(
            walk(&reg, pass, ["LAMP", "ON"]).expect("call"),
            PartialCall::Call { .. }
        ));
        assert!(matches!(
            walk(&reg, pass, ["Lamp", "oFf"]).expect("call"),
            PartialCall::Call { .. }
        ));
    }

    #[test]
    fn unknown_segments_are_rejected() {
        let reg = arity2();
        let pass = reg.pass(PassIx(0));
        assert_eq!(
            walk(&reg, pass, ["nope"]).unwrap_err(),
            ShapeDenial::NoSuchDevice
        );
        assert_eq!(
            walk(&reg, pass, ["lamp", "toggle"]).unwrap_err(),
            ShapeDenial::NoSuchVerb
        );
        assert_eq!(
            walk(&reg, pass, ["lamp", "on", "extra"]).unwrap_err(),
            ShapeDenial::TrailingSegment
        );
    }

    #[test]
    fn arity_zero_fires_with_no_segments_and_rejects_any() {
        let reg = registry_with(Scope::Call {
            call: authorize(&device("lamp", "light.living_room_floor"), Verb::On),
        });
        let pass = reg.pass(PassIx(0));
        assert!(matches!(
            walk(&reg, pass, []).expect("valid"),
            PartialCall::Call { .. }
        ));
        assert_eq!(
            walk(&reg, pass, ["on"]).unwrap_err(),
            ShapeDenial::TrailingSegment
        );
    }

    #[test]
    fn arity_one_takes_only_a_verb() {
        let reg = registry_with(Scope::Device {
            device: DeviceIx(1),
        });
        let pass = reg.pass(PassIx(0));
        let end = walk(&reg, pass, ["off"]).expect("saturates");
        let PartialCall::Call { call, .. } = end else {
            panic!("expected a saturated position")
        };
        assert_eq!(call.service(), "switch/turn_off");
        assert_eq!(
            walk(&reg, pass, ["lamp"]).unwrap_err(),
            ShapeDenial::NoSuchVerb
        );
    }

    /// A pass reaches only the devices its scope names, at any segment sequence.
    #[test]
    fn a_pass_never_reaches_a_device_outside_its_scope() {
        let reg = registry_with(Scope::Pass {
            devices: vec![DeviceIx(0)].into_boxed_slice(),
        });
        let pass = reg.pass(PassIx(0));
        assert_eq!(
            walk(&reg, pass, ["plug"]).unwrap_err(),
            ShapeDenial::NoSuchDevice
        );
        assert_eq!(
            walk(&reg, pass, ["plug", "on"]).unwrap_err(),
            ShapeDenial::NoSuchDevice
        );
    }

    /// The fold's whole reachable set stays inside the six constants, for every
    /// device and every segment sequence a pass admits.
    #[test]
    fn every_reachable_call_is_one_of_six_constants() {
        const SIX: [&str; 6] = [
            "light/turn_on",
            "light/turn_off",
            "switch/turn_on",
            "switch/turn_off",
            "fan/turn_on",
            "fan/turn_off",
        ];
        let reg = arity2();
        let pass = reg.pass(PassIx(0));
        let calls = reachable(&reg, pass);
        assert_eq!(calls.len(), 4);
        for (suffix, device, verb) in calls {
            let call = authorize(device, verb);
            assert!(SIX.contains(&call.service()), "escaped: {}", call.service());
            let segments: Vec<&str> = suffix.split('/').filter(|s| !s.is_empty()).collect();
            let end = walk(&reg, pass, segments).expect("reachable path folds");
            assert!(matches!(end, PartialCall::Call { .. }));
        }
    }

    #[test]
    fn controllable_decides_the_service_not_the_device_name() {
        let fan = device("lamp", "fan.ceiling");
        assert_eq!(authorize(&fan, Verb::On).service(), "fan/turn_on");
    }
}
