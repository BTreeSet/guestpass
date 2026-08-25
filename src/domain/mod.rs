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

    /// Case-insensitive: the request side may arrive uppercased from a QR
    /// card (docs/decisions.md D-12). The fold fuses into the comparison, so
    /// matching against the canonical table allocates nothing.
    fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.token().eq_ignore_ascii_case(s))
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

/// Minimum accepted token length. Tokens are compared after ASCII case
/// folding, so the alphabet holds 36 symbols and 26 characters carry
/// 26 x log2(36), about 134 bits, above the 128-bit floor of D-9. `gen-token`
/// output is base32, whose 26 characters encode exactly 130 bits.
pub const MIN_TOKEN_CHARS: usize = 26;

/// Maximum accepted token length. The request side hashes any segment that
/// parses, so this bound is what keeps an adversarial path segment from
/// buying unbounded hashing work.
pub const MAX_TOKEN_CHARS: usize = 64;

/// A pass token in canonical form: ASCII lowercase alphanumeric, held only
/// long enough to be digested.
///
/// `parse` folds case, so the config side and the request side cannot disagree
/// about it; two spellings differing only in case are one value. There is no
/// `Debug`, `Display`, or `Serialize` impl that reveals the value, so no code
/// path can format one into a log line. There is deliberately no `PartialEq`:
/// canonical form would make a non-constant-time `==` on a secret look
/// correct, and comparison belongs to digests (D-9).
#[derive(Clone)]
pub struct PassToken(Box<str>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("token must be {MIN_TOKEN_CHARS}-{MAX_TOKEN_CHARS} characters of [A-Za-z0-9]")]
pub struct TokenError;

impl PassToken {
    /// The one constructor, and the one place case is folded.
    ///
    /// # Errors
    /// Returns [`TokenError`] for a token outside the length bounds or the
    /// alphabet.
    pub fn parse(raw: &str) -> Result<Self, TokenError> {
        let ok = (MIN_TOKEN_CHARS..=MAX_TOKEN_CHARS).contains(&raw.len())
            && raw.bytes().all(|b| b.is_ascii_alphanumeric());
        if ok {
            Ok(Self(raw.to_ascii_lowercase().into_boxed_str()))
        } else {
            Err(TokenError)
        }
    }

    /// SHA-256 of the canonical form: the only comparable representation a
    /// token ever has. Parse it, digest it, drop it.
    #[must_use]
    pub fn digest(&self) -> TokenDigest {
        TokenDigest(Sha256::digest(self.0.as_bytes()).into())
    }
}

impl fmt::Debug for PassToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PassToken(<redacted>)")
    }
}

/// SHA-256 of a canonical pass token: the only form the process retains after
/// config load, and the only comparable one.
///
/// The primitive choice is deliberate and narrow. An unkeyed fast hash is
/// correct because the preimage is a uniformly random 128-bit secret;
/// key-stretching KDFs compensate for low-entropy passwords and would buy
/// nothing here but startup latency. The map key is the full 256-bit digest,
/// so producing a colliding key is a birthday search over 2^128 SHA-256
/// evaluations, and the `HashMap`'s per-process SipHash key keeps bucket
/// placement unsteerable. No constant-time comparison exists because no
/// comparison touches a secret (docs/decisions.md D-9).
///
/// [`PassToken::digest`] is the only constructor, which is what makes "both
/// sides folded the same way" a property of the type rather than a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

/// The scheme and authority every printed URL starts with: `http(s)://host[:port]`.
///
/// RFC 3986 makes the scheme (section 3.1) and host (3.2.2) case-insensitive
/// and the path (3.3) case-sensitive. An `Origin` has no path, so uppercasing
/// a URL rooted in one is meaning-preserving, which is what lets the card
/// emitter use QR alphanumeric mode (D-12). `parse` is the proof: anything
/// carrying a path, query, fragment, or userinfo is rejected, and the
/// survivor is folded to lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(Box<str>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("must be http(s)://host[:port] with no path, query, or fragment")]
pub struct OriginError;

impl Origin {
    /// # Errors
    /// Returns [`OriginError`] for a missing scheme, an empty authority, or
    /// anything beyond `host[:port]`.
    pub fn parse(raw: &str) -> Result<Self, OriginError> {
        // Scheme and host are case-insensitive and nothing case-sensitive can
        // survive the charset below, so folding the whole string is sound.
        let folded = raw.to_ascii_lowercase();
        let rest = folded
            .strip_prefix("https://")
            .or_else(|| folded.strip_prefix("http://"))
            .ok_or(OriginError)?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        let ok = !authority.is_empty()
            && authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if ok {
            let scheme = &folded[..folded.len() - rest.len()];
            Ok(Self(format!("{scheme}{authority}").into_boxed_str()))
        } else {
            Err(OriginError)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
        let d = |raw: &str| PassToken::parse(raw).expect("token").digest();
        let a = d("K7QF3M2X9WPLNA4RTVBC6DHJ8Z");
        assert_eq!(a, d("K7QF3M2X9WPLNA4RTVBC6DHJ8Z"));
        assert_ne!(a, d("K7QF3M2X9WPLNA4RTVBC6DHJ8A"));
    }

    /// The fold lives in the constructor, so case-insensitivity is a theorem
    /// about digests rather than a rule each lookup site must remember.
    #[test]
    fn case_folds_to_one_token() {
        let d = |raw: &str| PassToken::parse(raw).expect("token").digest();
        assert_eq!(
            d("K7QF3M2X9WPLNA4RTVBC6DHJ8Z"),
            d("k7qf3m2x9wplna4rtvbc6dhj8z")
        );
        assert_eq!(
            d("K7qf3M2x9WplNa4RtvBc6DhJ8z"),
            d("k7qf3m2x9wplna4rtvbc6dhj8z")
        );
    }

    #[test]
    fn over_long_tokens_are_rejected() {
        assert_eq!(PassToken::parse(&"a".repeat(65)).unwrap_err(), TokenError);
        assert!(PassToken::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn an_origin_is_pathless_and_folded() {
        let o = Origin::parse("HTTPS://GP.Example.com/").expect("origin");
        assert_eq!(o.as_str(), "https://gp.example.com");
        assert!(Origin::parse("https://gp.example.com:8443").is_ok());
        for bad in [
            "https://gp.example.com/gp",
            "https://gp.example.com?x=1",
            "https://gp.example.com#f",
            "https://user@gp.example.com",
            "https://",
            "gp.example.com",
        ] {
            assert_eq!(Origin::parse(bad).unwrap_err(), OriginError, "{bad}");
        }
    }
}
