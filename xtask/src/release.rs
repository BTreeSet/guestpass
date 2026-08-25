//! The release tag algebra (docs/decisions.md D-13, gate G13).
//!
//! Pure: the clock, the tag list, and the commit arrive as arguments, so every
//! branch is pinned by the tests below on fixed inputs. The shell that gathers
//! them lives in `main.rs`.

use std::fmt;

use time::OffsetDateTime;
use time::macros::format_description;

/// A release triple. Field order is the precedence law: the derived `Ord`
/// compares major, then minor, then patch, which is exactly SemVer precedence
/// on pre-release-free versions. What the shell spelled `sort -V` is a derive
/// here, and what it could not spell at all, the compiler now checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

/// The identity of `max` over releases: a repository that has never shipped.
pub const ORIGIN: Version = Version {
    major: 0,
    minor: 0,
    patch: 0,
};

impl Version {
    /// The next patch: what a build published between releases claims to be
    /// working toward.
    #[must_use]
    pub const fn successor(self) -> Self {
        Self {
            patch: self.patch + 1,
            ..self
        }
    }

    /// Strictly `v` plus a triple. Everything else, pre-release tags included,
    /// is not a release and does not participate in `max`.
    #[must_use]
    pub fn parse_release_tag(tag: &str) -> Option<Self> {
        Self::parse_triple(tag.strip_prefix('v')?)
    }

    /// Three numeric fields. SemVer 2.0.0 forbids leading zeros in numeric
    /// identifiers, so `01` is a refusal, not a 1.
    #[must_use]
    pub fn parse_triple(s: &str) -> Option<Self> {
        let mut fields = s.split('.').map(numeric_identifier);
        let (major, minor, patch) = (fields.next()??, fields.next()??, fields.next()??);
        fields.next().is_none().then_some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// `u64::from_str` accepts a leading `+`; a SemVer numeric identifier does not,
/// nor a leading zero. Parse the stricter grammar.
fn numeric_identifier(s: &str) -> Option<u64> {
    let well_formed = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && !(s.len() > 1 && s.starts_with('0'));
    if well_formed { s.parse().ok() } else { None }
}

/// A UTC instant rendered `yyyy-mm-dd.hh-mm-ss`. Fixed width and zero-padded,
/// so lexical order on the rendering equals chronological order on the
/// instant: the monotonicity law, tested below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp(OffsetDateTime);

impl Stamp {
    #[must_use]
    pub fn from_unix(secs: i64) -> Option<Self> {
        OffsetDateTime::from_unix_timestamp(secs).ok().map(Self)
    }

    /// RFC 3339, for the `org.opencontainers.image.created` label.
    #[must_use]
    pub fn created(self) -> String {
        self.0
            .format(format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
            ))
            .expect("a fixed description formats any timestamp")
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .0
            .format(format_description!(
                "[year]-[month]-[day].[hour]-[minute]-[second]"
            ))
            .expect("a fixed description formats any timestamp");
        f.write_str(&s)
    }
}

/// Seven hex digits of the commit, rendered with git-describe's `g` prefix so
/// the identifier is always alphanumeric: an all-digit hash starting with 0
/// would be an invalid SemVer numeric identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha7([u8; 7]);

impl Sha7 {
    #[must_use]
    pub fn parse(full: &str) -> Option<Self> {
        let bytes = full.as_bytes();
        (bytes.len() >= 7 && bytes.iter().all(u8::is_ascii_hexdigit))
            .then(|| Self(bytes[..7].try_into().expect("length checked")))
    }
}

impl fmt::Display for Sha7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "g{}", str::from_utf8(&self.0).expect("hex is UTF-8"))
    }
}

/// The publish-triggering events. `workflow_dispatch` is a `Push` at the call
/// site: same denotation, different finger.
#[derive(Debug)]
pub enum Event {
    Push,
    Release { tag: String },
}

/// Why a release event was refused. Each variant carries what the operator
/// needs to fix it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("release tag '{tag}' is not vMAJOR.MINOR.PATCH")]
    NotARelease { tag: String },
    #[error("release is {tag}; the manifest says {declared}")]
    ManifestDisagrees { tag: Version, declared: Version },
}

/// What a publish denotes: either a shipped release or a named pre-release.
#[derive(Debug, PartialEq, Eq)]
pub enum Publish {
    Release(Version),
    Pre {
        version: Version,
        stamp: Stamp,
        sha: Sha7,
    },
}

impl Publish {
    /// The immutable image tag. SemVer orders every `Pre` above the release it
    /// follows and below the release it precedes, so history sorts by tag.
    #[must_use]
    pub fn version_tag(&self) -> String {
        match self {
            Self::Release(v) => v.to_string(),
            Self::Pre {
                version,
                stamp,
                sha,
            } => format!("{version}-dev.{stamp}.{sha}"),
        }
    }

    /// The full tag set: the immutable tag plus the moving alias, which is a
    /// projection of "most recent", never a name the algebra reasons about.
    #[must_use]
    pub fn tags(&self) -> Vec<String> {
        let alias = match self {
            Self::Release(_) => "latest",
            Self::Pre { .. } => "edge",
        };
        vec![self.version_tag(), alias.to_owned()]
    }
}

/// The whole algebra. Total on `Push`; on `Release` defined exactly when the
/// tag is a strict triple agreeing with the manifest, because the Supervisor
/// installs `<image>:<manifest version>` and a disagreement ships an add-on
/// nobody can install.
///
/// `released` carries already-parsed versions: strings stop at the boundary.
/// Cost: one `max` fold, O(n) in the tag count with the identity [`ORIGIN`].
pub fn resolve(
    event: &Event,
    declared: Version,
    released: impl IntoIterator<Item = Version>,
    now: Stamp,
    sha: Sha7,
) -> Result<Publish, Refusal> {
    match event {
        Event::Release { tag } => {
            let version = Version::parse_release_tag(tag)
                .ok_or_else(|| Refusal::NotARelease { tag: tag.clone() })?;
            if version == declared {
                Ok(Publish::Release(version))
            } else {
                Err(Refusal::ManifestDisagrees {
                    tag: version,
                    declared,
                })
            }
        }
        Event::Push => Ok(Publish::Pre {
            version: released.into_iter().max().unwrap_or(ORIGIN).successor(),
            stamp: now,
            sha,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_787_695_200; // 2026-08-25 22:00:00 UTC

    fn v(s: &str) -> Version {
        Version::parse_triple(s).expect("triple")
    }

    fn fixtures() -> (Stamp, Sha7) {
        (
            Stamp::from_unix(T0).expect("stamp"),
            Sha7::parse("23471a1000000000000000000000000000000000").expect("sha"),
        )
    }

    fn pre(declared: &str, tags: &[&str]) -> Publish {
        let (now, sha) = fixtures();
        let released = tags.iter().filter_map(|t| Version::parse_release_tag(t));
        resolve(&Event::Push, v(declared), released, now, sha).expect("push is total")
    }

    #[test]
    fn a_repository_that_never_shipped_starts_from_origin() {
        assert_eq!(
            pre("0.1.0", &[]).version_tag(),
            "0.0.1-dev.2026-08-25.22-00-00.g23471a1"
        );
    }

    #[test]
    fn a_pre_release_is_the_successor_patch_of_the_latest_release() {
        assert_eq!(
            pre("0.1.0", &["v0.1.0"]).version_tag(),
            "0.1.1-dev.2026-08-25.22-00-00.g23471a1"
        );
    }

    #[test]
    fn latest_is_numeric_order_not_lexical() {
        let p = pre("0.1.0", &["v0.2.0", "v0.10.0", "v0.9.9"]);
        assert_eq!(p.version_tag(), "0.10.1-dev.2026-08-25.22-00-00.g23471a1");
    }

    #[test]
    fn non_releases_do_not_participate() {
        let p = pre(
            "0.1.0",
            &[
                "v0.1.0",
                "v0.1.1-dev.2026-08-01.00-00-00.gabc1234",
                "v0.2.0-rc1",
                "vnext",
                "v01.0.0", // leading zero: not a SemVer numeric identifier
            ],
        );
        assert_eq!(p.version_tag(), "0.1.1-dev.2026-08-25.22-00-00.g23471a1");
    }

    #[test]
    fn the_tag_set_carries_the_moving_alias() {
        assert_eq!(
            pre("0.1.0", &["v0.1.0"]).tags(),
            ["0.1.1-dev.2026-08-25.22-00-00.g23471a1", "edge"]
        );
    }

    /// Lexical order on renderings equals chronological order on instants.
    #[test]
    fn stamps_are_monotonic() {
        let offsets = [0, 1, 59, 60, 3599, 3600, 86_399, 86_400, 2_678_400];
        let stamps: Vec<String> = offsets
            .iter()
            .map(|d| Stamp::from_unix(T0 + d).expect("stamp").to_string())
            .collect();
        let mut sorted = stamps.clone();
        sorted.sort();
        assert_eq!(stamps, sorted);
    }

    #[test]
    fn a_release_is_reconciled_with_the_manifest() {
        let (now, sha) = fixtures();
        let event = Event::Release {
            tag: "v0.1.0".to_owned(),
        };
        let p = resolve(&event, v("0.1.0"), [], now, sha).expect("agrees");
        assert_eq!(p.version_tag(), "0.1.0");
        assert_eq!(p.tags(), ["0.1.0", "latest"]);
    }

    #[test]
    fn release_refusals_name_their_reason() {
        let (now, sha) = fixtures();
        let refuse = |tag: &str, declared: &str| {
            resolve(
                &Event::Release {
                    tag: tag.to_owned(),
                },
                v(declared),
                [],
                now,
                sha,
            )
            .expect_err("refused")
        };
        assert_eq!(
            refuse("v0.1.0", "0.2.0"),
            Refusal::ManifestDisagrees {
                tag: v("0.1.0"),
                declared: v("0.2.0")
            }
        );
        for tag in ["v0.1", "v0.1.0-rc1", "0.1.0", "v0.1.00", "v0.1.0.0"] {
            assert!(
                matches!(refuse(tag, "0.1.0"), Refusal::NotARelease { .. }),
                "{tag}"
            );
        }
    }

    /// The interval law, on the type itself: Ord over triples places every
    /// pre-release's base version strictly between its neighbours.
    #[test]
    fn the_successor_sits_between_releases() {
        let latest = v("0.1.0");
        assert!(latest < latest.successor());
        assert!(latest.successor() <= v("0.2.0"));
    }
}
