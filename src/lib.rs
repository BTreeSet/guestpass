//! guestpass: a closed vocabulary of six Home Assistant calls, exposed to guests
//! holding a high-entropy URL.
//!
//! See `docs/design.md` for the model and `AGENTS.md` for the invariants that
//! govern changes to it.
//!
//! Gate G8: unsafe code is denied crate-wide. The one exception is
//! `tunnel::spawn`, which sets `PR_SET_PDEATHSIG` so cloudflared cannot outlive
//! this process, and carries its own justification.

#![deny(unsafe_code)]

pub mod addon;
pub mod config;
pub mod domain;
pub mod gate;
pub mod ha;
pub mod http;
pub mod policy;
pub mod tex;
pub mod tunnel;
