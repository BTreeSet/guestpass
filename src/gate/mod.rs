//! Liveness and quota. Pure given a clock reading and a bucket snapshot.
//!
//! [`Admitted`] has a private field, so [`admit`] is the only way to obtain one.
//! `ha::execute` accepts nothing else, which is what forces the quota check into
//! every path that reaches the effect.

use std::time::Duration;

use time::OffsetDateTime;

use crate::policy::{Authorized, CompiledPass, TokenBinding, Window};

/// A refusal that is actionable and carries no probe value, so its detail
/// reaches the guest unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessDenial {
    Expired,
    Retired,
    QuotaExhausted { retry_after: Duration },
}

/// A call that passed both the authority check and the standing limits.
#[derive(Debug, Clone)]
pub struct Admitted(Authorized);

impl Admitted {
    #[must_use]
    pub const fn call(&self) -> &Authorized {
        &self.0
    }
}

/// Whether a pass and the token that named it are usable at `now`.
#[must_use]
pub fn liveness(
    pass: &CompiledPass,
    binding: TokenBinding,
    now: OffsetDateTime,
) -> Option<LivenessDenial> {
    if let Some(until) = binding.accepted_until
        && now >= until
    {
        return Some(LivenessDenial::Retired);
    }
    match pass.window {
        Window::Always => None,
        Window::Until(end) if now < end => None,
        Window::Until(_) => Some(LivenessDenial::Expired),
    }
}

/// A fixed-window counter over one minute.
///
/// A fixed window admits at most `per_minute` calls per window and up to twice
/// that across a window boundary. At six calls a minute against a light switch
/// the distinction does not matter, and the state is two words with no timer.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    window_start: OffsetDateTime,
    used: u32,
}

impl Bucket {
    #[must_use]
    pub const fn new(now: OffsetDateTime) -> Self {
        Self {
            window_start: now,
            used: 0,
        }
    }

    /// Charge one call. Returns the refusal when the window is full.
    pub fn charge(&mut self, per_minute: u32, now: OffsetDateTime) -> Option<LivenessDenial> {
        let elapsed = now - self.window_start;
        if elapsed >= time::Duration::MINUTE {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= per_minute {
            let remaining = time::Duration::MINUTE - (now - self.window_start);
            return Some(LivenessDenial::QuotaExhausted {
                retry_after: remaining.try_into().unwrap_or(Duration::from_secs(60)),
            });
        }
        self.used += 1;
        None
    }
}

/// The sole constructor of [`Admitted`].
///
/// # Errors
/// Returns the first [`LivenessDenial`] that applies.
pub fn admit(
    call: Authorized,
    pass: &CompiledPass,
    binding: TokenBinding,
    bucket: &mut Bucket,
    now: OffsetDateTime,
) -> Result<Admitted, LivenessDenial> {
    if let Some(denial) = liveness(pass, binding, now) {
        return Err(denial);
    }
    if let Some(denial) = bucket.charge(pass.quota.per_minute, now) {
        return Err(denial);
    }
    Ok(Admitted(call))
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::domain::{DeviceId, DeviceIx, EntityId, PassIx, Verb};
    use crate::policy::{Device, Quota, Scope, Trigger, authorize};

    fn pass(window: Window, per_minute: u32) -> CompiledPass {
        CompiledPass {
            id: "guest".into(),
            label: "Guest".into(),
            scope: Scope::Device {
                device: DeviceIx(0),
            },
            trigger: Trigger::Interactive,
            window,
            quota: Quota { per_minute },
        }
    }

    fn current() -> TokenBinding {
        TokenBinding {
            pass: PassIx(0),
            accepted_until: None,
        }
    }

    fn call() -> Authorized {
        let d = Device {
            id: DeviceId::parse("lamp").expect("id"),
            label: "Lamp".into(),
            entity: EntityId::parse("light.living_room_floor").expect("entity"),
        };
        authorize(&d, Verb::On)
    }

    const T0: OffsetDateTime = datetime!(2026-08-24 12:00:00 UTC);

    #[test]
    fn an_always_window_is_live() {
        assert_eq!(liveness(&pass(Window::Always, 6), current(), T0), None);
    }

    #[test]
    fn a_closed_window_expires_at_its_boundary() {
        let p = pass(Window::Until(datetime!(2026-08-24 12:00:00 UTC)), 6);
        assert_eq!(
            liveness(&p, current(), T0),
            Some(LivenessDenial::Expired),
            "the window is half-open: the end instant is already expired"
        );
        assert_eq!(liveness(&p, current(), T0 - time::Duration::SECOND), None);
    }

    #[test]
    fn a_retiring_token_stops_at_its_sunset() {
        let binding = TokenBinding {
            pass: PassIx(0),
            accepted_until: Some(datetime!(2026-08-25 00:00:00 UTC)),
        };
        assert_eq!(liveness(&pass(Window::Always, 6), binding, T0), None);
        assert_eq!(
            liveness(
                &pass(Window::Always, 6),
                binding,
                datetime!(2026-08-25 00:00:01 UTC)
            ),
            Some(LivenessDenial::Retired)
        );
    }

    #[test]
    fn quota_admits_exactly_per_minute_calls() {
        let p = pass(Window::Always, 3);
        let mut b = Bucket::new(T0);
        for i in 0..3 {
            assert!(
                admit(call(), &p, current(), &mut b, T0).is_ok(),
                "call {i} should be admitted"
            );
        }
        assert!(matches!(
            admit(call(), &p, current(), &mut b, T0),
            Err(LivenessDenial::QuotaExhausted { .. })
        ));
    }

    #[test]
    fn quota_refills_on_the_next_window() {
        let p = pass(Window::Always, 1);
        let mut b = Bucket::new(T0);
        assert!(admit(call(), &p, current(), &mut b, T0).is_ok());
        assert!(admit(call(), &p, current(), &mut b, T0).is_err());
        let later = T0 + time::Duration::seconds(61);
        assert!(admit(call(), &p, current(), &mut b, later).is_ok());
    }

    #[test]
    fn a_dead_pass_is_refused_before_the_quota_is_charged() {
        let p = pass(Window::Until(T0), 5);
        let mut b = Bucket::new(T0);
        assert_eq!(
            admit(call(), &p, current(), &mut b, T0).unwrap_err(),
            LivenessDenial::Expired
        );
        assert_eq!(b.used, 0, "a refused call must not consume quota");
    }
}
