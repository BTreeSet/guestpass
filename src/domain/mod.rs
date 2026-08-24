//! Domain types. No logic beyond parsing and total projections.
//!
//! The security argument of this crate rests on two facts established here:
//! `Controllable` and `Verb` are closed, and [`service_of`] returns one of six
//! `&'static str`. No service path is ever assembled from parts.

use std::fmt;

use sha2::{Digest, Sha256};

/// A closed vocabulary parsed from, and rendered into, a URL path segment.
///
/// `parse` is derived from `ALL`, so a new variant reaches both path parsing
/// and config parsing without an edit. The scan is over 2 or 3 elements.
pub trait Vocabulary: Copy + Sized + PartialEq + 'static {
    const ALL: &'static [Self];

    fn token(self) -> &'static str;

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.token() == s)
    }
}

/// The verbs a guest may name. Both are absolute: applying either twice leaves
/// the same state as applying it once. A relative verb such as `toggle` has no
/// representation, which is what makes GET-fired triggers and NFC double-reads
/// survivable (docs/decisions.md D-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    On,
    Off,
}

impl Vocabulary for Verb {
    const ALL: &'static [Self] = &[Self::On, Self::Off];

    fn token(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// The Home Assistant domains guestpass can address.
///
/// `Domain` as a general concept is absent from this crate: `lock`, `cover`,
/// `scene`, `script`, and `input_boolean` have no representation, so no
/// configuration reaches them and no flag enables them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Controllable {
    Light,
    Switch,
    Fan,
}

impl Vocabulary for Controllable {
    const ALL: &'static [Self] = &[Self::Light, Self::Switch, Self::Fan];

    fn token(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Switch => "switch",
            Self::Fan => "fan",
        }
    }
}

/// The complete set of Home Assistant endpoints this program can address.
///
/// Deriving this from `Controllable::token` would assemble a path from parts,
/// which invariant I-1 forbids. The explicit match puts the friction of a new
/// variant exactly where review belongs.
#[must_use]
pub const fn service_of(kind: Controllable, verb: Verb) -> &'static str {
    match (kind, verb) {
        (Controllable::Light, Verb::On) => "light/turn_on",
        (Controllable::Light, Verb::Off) => "light/turn_off",
        (Controllable::Switch, Verb::On) => "switch/turn_on",
        (Controllable::Switch, Verb::Off) => "switch/turn_off",
        (Controllable::Fan, Verb::On) => "fan/turn_on",
        (Controllable::Fan, Verb::Off) => "fan/turn_off",
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("entity id must be `<domain>.<object_id>`")]
    Shape,
    #[error("`{0}` is not a controllable domain; guestpass addresses light, switch, and fan")]
    UnknownDomain(String),
    #[error("object id must be 1-200 characters of [a-z0-9_]")]
    ObjectId,
}

/// A Home Assistant entity guestpass can address.
///
/// The only constructor validates the domain against [`Controllable`], so
/// `kind` is total afterwards and no downstream code re-splits the string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId {
    kind: Controllable,
    object_id: Box<str>,
}

impl EntityId {
    /// # Errors
    /// Returns [`IdError`] when the shape, domain, or object id is rejected.
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        let (domain, object) = raw.split_once('.').ok_or(IdError::Shape)?;
        let Some(kind) = Controllable::parse(domain) else {
            return Err(IdError::UnknownDomain(domain.to_owned()));
        };
        let ok = !object.is_empty()
            && object.len() <= 200
            && object
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !ok {
            return Err(IdError::ObjectId);
        }
        Ok(Self {
            kind,
            object_id: object.into(),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> Controllable {
        self.kind
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.kind.token(), self.object_id)
    }
}

/// A guest-visible device name, matched against a path segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(Box<str>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("device id must be 1-64 characters of [a-z0-9-]")]
pub struct DeviceIdError;

impl DeviceId {
    /// # Errors
    /// Returns [`DeviceIdError`] when the name is empty, over-long, or contains
    /// anything outside `[a-z0-9-]`. The character set keeps a device id safe to
    /// place in a path segment without escaping.
    pub fn parse(raw: &str) -> Result<Self, DeviceIdError> {
        let ok = !raw.is_empty()
            && raw.len() <= 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(raw.into()))
        } else {
            Err(DeviceIdError)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Index into `Registry::passes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PassIx(pub u16);

/// Index into `Registry::devices`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIx(pub u16);

/// Minimum accepted token entropy, in base32 characters. 26 characters carry
/// 130 bits, which is the smallest encoding of a 128-bit secret.
pub const MIN_TOKEN_CHARS: usize = 26;

/// A pass token, held only long enough to be digested.
///
/// There is no `Debug`, `Display`, or `Serialize` impl that reveals the value,
/// so no code path can format one into a log line.
#[derive(Clone)]
pub struct PassToken(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("token must be at least {MIN_TOKEN_CHARS} characters of [A-Za-z0-9]")]
pub struct TokenError;

impl PassToken {
    /// # Errors
    /// Returns [`TokenError`] for a token below the entropy floor or containing
    /// characters outside the alphabet.
    pub fn parse(raw: &str) -> Result<Self, TokenError> {
        let ok = raw.len() >= MIN_TOKEN_CHARS && raw.bytes().all(|b| b.is_ascii_alphanumeric());
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(TokenError)
        }
    }

    #[must_use]
    pub fn digest(&self) -> TokenDigest {
        TokenDigest::of(&self.0)
    }
}

impl fmt::Debug for PassToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PassToken(<redacted>)")
    }
}

/// SHA-256 of a pass token: the only form retained after config load.
///
/// Lookup keyed by digest is timing-independent without a constant-time
/// comparison, because an attacker cannot steer a digest (docs/decisions.md D-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    #[must_use]
    pub fn of(raw: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        Self(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate G2: the reachable endpoint set is a compile-time constant.
    /// Adding a `Controllable` or `Verb` variant fails here first.
    #[test]
    fn vocabulary_is_closed() {
        assert_eq!(
            Verb::ALL.len(),
            2,
            "Verb gained a variant: see AGENTS.md I-1"
        );
        assert_eq!(
            Controllable::ALL.len(),
            3,
            "Controllable gained a variant: see AGENTS.md I-1"
        );

        let mut reachable: Vec<&'static str> = Vec::new();
        for &kind in Controllable::ALL {
            for &verb in Verb::ALL {
                reachable.push(service_of(kind, verb));
            }
        }
        reachable.sort_unstable();

        assert_eq!(
            reachable,
            [
                "fan/turn_off",
                "fan/turn_on",
                "light/turn_off",
                "light/turn_on",
                "switch/turn_off",
                "switch/turn_on",
            ],
            "the set of reachable Home Assistant endpoints changed: see AGENTS.md I-1"
        );
    }

    #[test]
    fn vocabulary_roundtrips_through_token() {
        for &v in Verb::ALL {
            assert_eq!(Verb::parse(v.token()), Some(v));
        }
        for &c in Controllable::ALL {
            assert_eq!(Controllable::parse(c.token()), Some(c));
        }
        assert_eq!(Verb::parse("toggle"), None);
        assert_eq!(Controllable::parse("lock"), None);
    }

    #[test]
    fn entity_parse_admits_only_controllable_domains() {
        let e = EntityId::parse("light.living_room_floor").expect("valid");
        assert_eq!(e.kind(), Controllable::Light);
        assert_eq!(e.to_string(), "light.living_room_floor");

        assert_eq!(
            EntityId::parse("lock.front_door"),
            Err(IdError::UnknownDomain("lock".to_owned()))
        );
        assert_eq!(
            EntityId::parse("scene.movie_night"),
            Err(IdError::UnknownDomain("scene".to_owned()))
        );
        assert_eq!(
            EntityId::parse("input_boolean.guest"),
            Err(IdError::UnknownDomain("input_boolean".to_owned()))
        );
        assert_eq!(EntityId::parse("light"), Err(IdError::Shape));
        assert_eq!(EntityId::parse("light."), Err(IdError::ObjectId));
        assert_eq!(EntityId::parse("light.Bad-Id"), Err(IdError::ObjectId));
    }

    #[test]
    fn device_id_is_path_safe() {
        assert!(DeviceId::parse("lamp").is_ok());
        assert!(DeviceId::parse("floor-lamp-2").is_ok());
        assert_eq!(DeviceId::parse(""), Err(DeviceIdError));
        assert_eq!(DeviceId::parse("Lamp"), Err(DeviceIdError));
        assert_eq!(DeviceId::parse("lamp/../etc"), Err(DeviceIdError));
        assert_eq!(DeviceId::parse(&"x".repeat(65)), Err(DeviceIdError));
    }

    #[test]
    fn token_enforces_the_entropy_floor() {
        assert!(PassToken::parse("K7QF3M2X9WPLNA4RTVBC6DHJ8Z").is_ok());
        assert_eq!(PassToken::parse("short").unwrap_err(), TokenError);
        assert_eq!(PassToken::parse(&"!".repeat(30)).unwrap_err(), TokenError);
    }

    #[test]
    fn token_never_formats_its_value() {
        let t = PassToken::parse("K7QF3M2X9WPLNA4RTVBC6DHJ8Z").expect("valid");
        assert_eq!(format!("{t:?}"), "PassToken(<redacted>)");
    }

    #[test]
    fn digest_is_stable_and_distinguishing() {
        let a = TokenDigest::of("K7QF3M2X9WPLNA4RTVBC6DHJ8Z");
        assert_eq!(a, TokenDigest::of("K7QF3M2X9WPLNA4RTVBC6DHJ8Z"));
        assert_ne!(a, TokenDigest::of("K7QF3M2X9WPLNA4RTVBC6DHJ8A"));
    }
}
