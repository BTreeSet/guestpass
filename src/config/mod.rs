//! The one parse boundary: untrusted YAML becomes a [`Registry`] or a list of
//! errors. Errors across devices and passes accumulate, so one run reports
//! every mistake in the file; the chain within one pass fails fast, because
//! resolving a device precedes checking a verb against it.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::Deserialize;
use time::OffsetDateTime;

use crate::domain::{DeviceId, DeviceIx, EntityId, Origin, PassIx, PassToken, TokenDigest, Verb};
use crate::policy::{
    CompiledPass, Device, Quota, Registry, Scope, TokenBinding, Trigger, Window, authorize,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub version: u8,
    pub tunnel: RawTunnel,
    #[serde(default)]
    pub devices: Vec<RawDevice>,
    #[serde(default)]
    pub passes: Vec<RawPass>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTunnel {
    /// Connector token from Cloudflare Zero Trust.
    pub token: String,
    /// The hostname the tunnel serves. Needed to print URLs and cards.
    pub public_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDevice {
    pub id: String,
    pub label: String,
    pub entity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPass {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub tokens: Vec<RawToken>,
    #[serde(default)]
    pub devices: Option<Vec<String>>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub verb: Option<Verb>,
    #[serde(default)]
    pub trigger: Option<RawTrigger>,
    #[serde(default)]
    pub quota: Option<RawQuota>,
    #[serde(default)]
    pub valid: Option<RawWindow>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawTrigger {
    Interactive,
    Direct,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawQuota {
    pub per_minute: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawWindow {
    #[serde(with = "time::serde::rfc3339")]
    pub until: OffsetDateTime,
}

/// A head token is a bare string; a retiring token carries its sunset.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawToken {
    Current(String),
    Retiring {
        value: String,
        #[serde(with = "time::serde::rfc3339")]
        accepted_until: OffsetDateTime,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CompileErrors(pub String);

/// Default standing limit. Quota is the bound on what a leaked token can do,
/// so a pass that omits it still gets one.
const DEFAULT_PER_MINUTE: u32 = 6;

/// Turn untrusted YAML into compiled authority.
///
/// # Errors
/// Returns every rejection found, one per line.
#[allow(clippy::too_many_lines)]
pub fn compile(raw: &RawConfig) -> Result<Registry, CompileErrors> {
    let mut errors: Vec<String> = Vec::new();

    if raw.version != 1 {
        errors.push(format!("version: expected 1, found {}", raw.version));
    }

    // --- devices ---------------------------------------------------------
    let mut devices: Vec<Device> = Vec::with_capacity(raw.devices.len());
    let mut device_index: HashMap<String, DeviceIx> = HashMap::new();

    for d in &raw.devices {
        let id = match DeviceId::parse(&d.id) {
            Ok(id) => id,
            Err(e) => {
                errors.push(format!("device `{}`: {e}", d.id));
                continue;
            }
        };
        let entity = match EntityId::parse(&d.entity) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("device `{}`: {e}", d.id));
                continue;
            }
        };
        if device_index.contains_key(&d.id) {
            errors.push(format!("device `{}`: duplicate id", d.id));
            continue;
        }
        let Ok(ix) = u16::try_from(devices.len()) else {
            errors.push("more than 65535 devices".to_owned());
            break;
        };
        device_index.insert(d.id.clone(), DeviceIx(ix));
        devices.push(Device {
            id,
            label: d.label.as_str().into(),
            entity,
        });
    }

    // --- passes ----------------------------------------------------------
    let mut passes: Vec<CompiledPass> = Vec::with_capacity(raw.passes.len());
    let mut by_digest: HashMap<TokenDigest, TokenBinding> = HashMap::new();

    for p in &raw.passes {
        let Ok(pass_ix) = u16::try_from(passes.len()) else {
            errors.push("more than 65535 passes".to_owned());
            break;
        };
        let pass_ix = PassIx(pass_ix);

        let scope = match resolve_scope(p, &device_index, &devices) {
            Ok(scope) => scope,
            Err(message) => {
                errors.push(format!("pass `{}`: {message}", p.id));
                continue;
            }
        };

        let mut current_seen = false;
        let mut bindings: Vec<(TokenDigest, Option<OffsetDateTime>)> = Vec::new();
        for t in &p.tokens {
            let (value, until) = match t {
                RawToken::Current(v) => (v, None),
                RawToken::Retiring {
                    value,
                    accepted_until,
                } => (value, Some(*accepted_until)),
            };
            match PassToken::parse(value) {
                Ok(token) => {
                    if until.is_none() {
                        if current_seen {
                            errors.push(format!(
                                "pass `{}`: only the head token may omit `accepted_until`",
                                p.id
                            ));
                            continue;
                        }
                        current_seen = true;
                    }
                    bindings.push((token.digest(), until));
                }
                Err(e) => errors.push(format!("pass `{}`: {e}", p.id)),
            }
        }
        if !current_seen {
            errors.push(format!("pass `{}`: needs one current token", p.id));
        }
        for (digest, until) in bindings {
            if by_digest
                .insert(
                    digest,
                    TokenBinding {
                        pass: pass_ix,
                        accepted_until: until,
                    },
                )
                .is_some()
            {
                errors.push(format!("pass `{}`: token is used by another pass", p.id));
            }
        }

        passes.push(CompiledPass {
            id: p.id.as_str().into(),
            label: p.label.as_deref().unwrap_or(&p.id).into(),
            scope,
            trigger: match p.trigger {
                Some(RawTrigger::Direct) => Trigger::Direct,
                Some(RawTrigger::Interactive) | None => Trigger::Interactive,
            },
            window: p
                .valid
                .as_ref()
                .map_or(Window::Always, |w| Window::Until(w.until)),
            quota: Quota {
                per_minute: p
                    .quota
                    .as_ref()
                    .map_or(DEFAULT_PER_MINUTE, |q| q.per_minute),
            },
        });
    }

    // --- origin -----------------------------------------------------------
    // Parsed to a pathless origin so that uppercasing an emitted card URL for
    // QR alphanumeric mode cannot change which resource it names (D-12).
    let origin = match Origin::parse(&raw.tunnel.public_url) {
        Ok(origin) => Some(origin),
        Err(e) => {
            errors.push(format!("tunnel.public_url: {e}"));
            None
        }
    };

    if let Some(origin) = origin.filter(|_| errors.is_empty()) {
        Ok(Registry::new(
            by_digest,
            passes.into_boxed_slice(),
            devices.into_boxed_slice(),
            origin,
        ))
    } else {
        let mut out = String::new();
        for e in &errors {
            let _ = writeln!(out, "  {e}");
        }
        Err(CompileErrors(out))
    }
}

/// The scope fields a pass declares determine its arity. Combinations that name
/// two arities at once are rejected here rather than represented.
fn resolve_scope(
    p: &RawPass,
    index: &HashMap<String, DeviceIx>,
    devices: &[Device],
) -> Result<Scope, String> {
    match (&p.devices, &p.device, p.verb) {
        (Some(list), None, None) => {
            if list.is_empty() {
                return Err("`devices` is empty".to_owned());
            }
            let mut ixs = Vec::with_capacity(list.len());
            for name in list {
                ixs.push(
                    *index
                        .get(name)
                        .ok_or_else(|| format!("no device `{name}`"))?,
                );
            }
            Ok(Scope::Pass {
                devices: ixs.into_boxed_slice(),
            })
        }
        (None, Some(name), None) => {
            let ix = *index
                .get(name)
                .ok_or_else(|| format!("no device `{name}`"))?;
            Ok(Scope::Device { device: ix })
        }
        (None, Some(name), Some(verb)) => {
            let ix = *index
                .get(name)
                .ok_or_else(|| format!("no device `{name}`"))?;
            Ok(Scope::Call {
                call: authorize(&devices[ix.0 as usize], verb),
            })
        }
        (None, None, _) => Err("needs `devices` or `device`".to_owned()),
        (Some(_), Some(_), _) => Err("`devices` and `device` are alternatives".to_owned()),
        (Some(_), None, Some(_)) => Err("`verb` needs `device`, not `devices`".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
version: 1
tunnel:
  token: "eyJhIjoidGVzdCJ9"
  public_url: "https://gp.example.com"
devices:
  - id: lamp
    label: "Living room lamp"
    entity: light.living_room_floor
passes:
  - id: guest
    label: "Guest pass"
    tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"]
    devices: [lamp]
    quota: { per_minute: 6 }
  - id: door-tag
    tokens: ["P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"]
    device: lamp
    verb: on
    trigger: direct
"#;

    /// `tunnel` is required, and every fixture below is about something else.
    /// Supply a valid block when the fixture does not carry its own, so each
    /// test reads as the one thing it asserts.
    const TUNNEL: &str = r#"
tunnel:
  token: "eyJhIjoidGVzdCJ9"
  public_url: "https://gp.example.com"
"#;

    /// Through the one constructor, as every caller must go.
    fn digest_of(raw: &str) -> TokenDigest {
        PassToken::parse(raw).expect("token").digest()
    }

    fn parse(yaml: &str) -> RawConfig {
        let text = if yaml.contains("tunnel:") {
            yaml.to_owned()
        } else {
            format!("{yaml}{TUNNEL}")
        };
        serde_yaml_ng::from_str(&text).expect("yaml parses")
    }

    /// Gate G7: the example shipped with the repository must compile, so the
    /// documentation cannot drift away from the parser.
    #[test]
    fn the_shipped_example_compiles() {
        let text = include_str!("../../guestpass.example.yaml");
        let raw: RawConfig = serde_yaml_ng::from_str(text).expect("example parses");
        let reg = compile(&raw).expect("example compiles");
        assert_eq!(reg.base_url(), "https://gp.example.com");
        let urls: Vec<String> = reg
            .passes()
            .iter()
            .flat_map(|p| {
                crate::policy::reachable(&reg, p)
                    .into_iter()
                    .map(move |(suffix, _, _)| format!("/t/<{}>{suffix}", p.id))
            })
            .collect();
        assert_eq!(
            urls,
            ["/t/<guest>/lamp/on", "/t/<guest>/lamp/off", "/t/<door-tag>",]
        );
    }

    #[test]
    fn a_good_config_compiles() {
        let reg = compile(&parse(GOOD)).expect("compiles");
        assert_eq!(reg.passes().len(), 2);
        assert_eq!(reg.devices().len(), 1);
        assert_eq!(reg.pinned().len(), 1);
        assert_eq!(reg.base_url(), "https://gp.example.com");
        assert!(matches!(reg.pass(PassIx(0)).scope, Scope::Pass { .. }));
        assert!(matches!(reg.pass(PassIx(1)).scope, Scope::Call { .. }));
        assert_eq!(reg.pass(PassIx(1)).trigger, Trigger::Direct);
    }

    #[test]
    fn a_token_resolves_to_its_pass() {
        let reg = compile(&parse(GOOD)).expect("compiles");
        let digest = digest_of("K7QF3M2X9WPLNA4RTVBC6DHJ8Z");
        assert_eq!(reg.binding(&digest).expect("bound").pass, PassIx(0));
        assert!(
            reg.binding(&digest_of("aaaaaaaaaaaaaaaaaaaaaaaaaa"))
                .is_none()
        );
    }

    #[test]
    fn a_pass_without_a_quota_still_gets_one() {
        let reg = compile(&parse(GOOD)).expect("compiles");
        assert_eq!(reg.pass(PassIx(1)).quota.per_minute, DEFAULT_PER_MINUTE);
    }

    #[test]
    fn errors_accumulate_across_the_file() {
        let yaml = r#"
version: 1
devices:
  - id: BAD
    label: x
    entity: light.ok
  - id: locky
    label: x
    entity: lock.front_door
passes:
  - id: p
    tokens: ["short"]
    device: nothere
"#;
        let err = compile(&parse(yaml)).expect_err("rejects");
        let lines: Vec<&str> = err.0.lines().collect();
        assert!(lines.len() >= 3, "expected several errors, got: {}", err.0);
        assert!(err.0.contains("BAD"), "{}", err.0);
        assert!(err.0.contains("lock"), "{}", err.0);
        assert!(err.0.contains("nothere"), "{}", err.0);
    }

    #[test]
    fn a_lock_entity_cannot_be_configured() {
        let yaml = r#"
version: 1
devices: [{ id: door, label: Door, entity: lock.front_door }]
passes: [{ id: p, tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"], device: door }]
"#;
        let err = compile(&parse(yaml)).expect_err("rejects");
        assert!(err.0.contains("not a controllable domain"), "{}", err.0);
    }

    #[test]
    fn two_current_tokens_are_rejected() {
        let yaml = r#"
version: 1
devices: [{ id: lamp, label: Lamp, entity: light.a }]
passes:
  - id: p
    tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z", "P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"]
    device: lamp
"#;
        let err = compile(&parse(yaml)).expect_err("rejects");
        assert!(err.0.contains("head token"), "{}", err.0);
    }

    /// The config side and the request side meet at the digest, so an
    /// uppercase spelling in the file and a lowercase one in the URL are one
    /// credential (D-12).
    #[test]
    fn a_token_is_case_insensitive_across_the_config_boundary() {
        let reg = compile(&parse(GOOD)).expect("compiles");
        assert!(
            reg.binding(&digest_of("k7qf3m2x9wplna4rtvbc6dhj8z"))
                .is_some()
        );
    }

    #[test]
    fn a_public_url_with_a_path_is_rejected() {
        let yaml = r#"
version: 1
tunnel:
  token: "eyJhIjoidGVzdCJ9"
  public_url: "https://gp.example.com/gp"
devices: [{ id: lamp, label: Lamp, entity: light.a }]
passes: [{ id: p, tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"], device: lamp, verb: "on" }]
"#;
        let err = compile(&parse(yaml)).expect_err("rejects");
        assert!(err.0.contains("public_url"), "{}", err.0);
    }

    #[test]
    fn a_retiring_token_is_accepted_alongside_the_head() {
        let yaml = r#"
version: 1
devices: [{ id: lamp, label: Lamp, entity: light.a }]
passes:
  - id: p
    tokens:
      - "K7QF3M2X9WPLNA4RTVBC6DHJ8Z"
      - value: "P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"
        accepted_until: 2026-09-07T00:00:00Z
    device: lamp
"#;
        let reg = compile(&parse(yaml)).expect("compiles");
        assert!(
            reg.binding(&digest_of("K7QF3M2X9WPLNA4RTVBC6DHJ8Z"))
                .expect("head")
                .accepted_until
                .is_none()
        );
        assert!(
            reg.binding(&digest_of("P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"))
                .expect("retiring")
                .accepted_until
                .is_some()
        );
    }

    /// YAML 1.1 reads a bare `on` as boolean true. serde_yaml_ng follows the
    /// 1.2 core schema and reads it as a string, so both spellings must land on
    /// the same verb; other YAML tooling in the ecosystem disagrees, which is
    /// why the shipped examples quote it.
    #[test]
    fn a_bare_on_is_the_verb_not_a_boolean() {
        for spelling in ["on", "\"on\"", "'on'"] {
            let yaml = format!(
                r#"
version: 1
devices: [{{ id: lamp, label: Lamp, entity: light.a }}]
passes: [{{ id: p, tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"], device: lamp, verb: {spelling} }}]
"#
            );
            let reg = compile(&parse(&yaml)).unwrap_or_else(|e| panic!("{spelling}: {}", e.0));
            let Scope::Call { ref call } = reg.pass(PassIx(0)).scope else {
                panic!("{spelling}: expected a saturated scope")
            };
            assert_eq!(call.service(), "light/turn_on", "spelling {spelling}");
        }
    }

    #[test]
    fn conflicting_scope_fields_are_rejected() {
        let yaml = r#"
version: 1
devices: [{ id: lamp, label: Lamp, entity: light.a }]
passes: [{ id: p, tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"], devices: [lamp], verb: on }]
"#;
        let err = compile(&parse(yaml)).expect_err("rejects");
        assert!(err.0.contains("`verb` needs `device`"), "{}", err.0);
    }
}
