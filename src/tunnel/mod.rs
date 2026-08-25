//! cloudflared supervision. `step` is pure, so the whole self-healing behaviour
//! is exercised with a fake clock and no processes.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightFault {
    BinaryMissing,
    NotExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Starting { attempt: u32 },
    Ready { conns: u8 },
    Degraded { misses: u8 },
    Draining { deadline: Instant },
}

/// `child` and `since` are factored into `Running`, so "is there a process to
/// signal?" is one match arm and a new phase inherits child handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervised {
    Faulted {
        fault: PreflightFault,
    },
    Backoff {
        until: Instant,
        attempt: u32,
    },
    Running {
        child: u32,
        since: Instant,
        phase: Phase,
    },
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Spawned { child: u32 },
    SpawnFailed { fault: PreflightFault },
    Probed { ready_connections: u8 },
    ProbeFailed,
    Exited,
    Tick,
    ShutdownRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Spawn,
    Probe,
    Terminate,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub next: Supervised,
    pub act: Option<Act>,
    pub wake: Option<Instant>,
}

pub const READY_DEADLINE: Duration = Duration::from_secs(30);
pub const PROBE_STARTING: Duration = Duration::from_secs(1);
pub const PROBE_HEALTHY: Duration = Duration::from_secs(15);
pub const DEGRADED_TOLERANCE: u8 = 3;
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);
pub const BACKOFF_CAP: Duration = Duration::from_secs(900);
/// Backoff resets only after `Ready` has held this long. Resetting on first
/// `Ready` would let a process that is ready for 200ms and dies hammer forever.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);
pub const GRACE: Duration = Duration::from_secs(20);

/// Decorrelated backoff without a random source: a deterministic ramp, jittered
/// by the caller if it wishes. Doubling is capped.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX))
        .min(BACKOFF_CAP)
}

/// Total transition. Every state has a bounded path to `Stopped` under
/// `ShutdownRequested`.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn step(state: Supervised, event: Event, now: Instant) -> Transition {
    use Event as E;
    use Supervised as S;

    let stay = |next: Supervised| Transition {
        next,
        act: None,
        wake: None,
    };

    match (state, event) {
        // Shutdown from anywhere with a child.
        (S::Running { child, since, .. }, E::ShutdownRequested) => Transition {
            next: S::Running {
                child,
                since,
                phase: Phase::Draining {
                    deadline: now + GRACE,
                },
            },
            act: Some(Act::Terminate),
            wake: Some(now + GRACE),
        },
        (S::Backoff { .. } | S::Faulted { .. } | S::Stopped, E::ShutdownRequested) => {
            stay(S::Stopped)
        }

        (
            S::Running {
                phase: Phase::Draining { deadline },
                ..
            },
            E::Tick,
        ) if now >= deadline => Transition {
            next: S::Stopped,
            act: Some(Act::Kill),
            wake: None,
        },
        (
            S::Running {
                phase: Phase::Draining { .. },
                ..
            },
            E::Exited,
        ) => stay(S::Stopped),

        // Spawn outcomes.
        (S::Backoff { attempt, .. }, E::Spawned { child }) => Transition {
            next: S::Running {
                child,
                since: now,
                phase: Phase::Starting { attempt },
            },
            act: Some(Act::Probe),
            wake: Some(now + PROBE_STARTING),
        },
        (S::Stopped | S::Faulted { .. }, E::Spawned { child }) => Transition {
            next: S::Running {
                child,
                since: now,
                phase: Phase::Starting { attempt: 0 },
            },
            act: Some(Act::Probe),
            wake: Some(now + PROBE_STARTING),
        },
        (_, E::SpawnFailed { fault }) => stay(S::Faulted { fault }),

        // Starting.
        (
            S::Running {
                child,
                since,
                phase: Phase::Starting { attempt },
            },
            E::Probed { ready_connections },
        ) => {
            if ready_connections > 0 {
                Transition {
                    next: S::Running {
                        child,
                        since: now,
                        phase: Phase::Ready {
                            conns: ready_connections,
                        },
                    },
                    act: None,
                    wake: Some(now + PROBE_HEALTHY),
                }
            } else if now.duration_since(since) >= READY_DEADLINE {
                restart(attempt, now)
            } else {
                Transition {
                    next: S::Running {
                        child,
                        since,
                        phase: Phase::Starting { attempt },
                    },
                    act: Some(Act::Probe),
                    wake: Some(now + PROBE_STARTING),
                }
            }
        }
        (
            S::Running {
                child,
                since,
                phase: Phase::Starting { attempt },
            },
            E::ProbeFailed | E::Tick,
        ) => {
            if now.duration_since(since) >= READY_DEADLINE {
                restart(attempt, now)
            } else {
                Transition {
                    next: S::Running {
                        child,
                        since,
                        phase: Phase::Starting { attempt },
                    },
                    act: Some(Act::Probe),
                    wake: Some(now + PROBE_STARTING),
                }
            }
        }

        // Healthy and degraded. Liveness is not health: a live process with zero
        // edge connections is useless and must be restarted.
        (
            S::Running {
                child,
                since,
                phase: Phase::Ready { .. },
            },
            E::Probed { ready_connections },
        ) => {
            let phase = if ready_connections > 0 {
                Phase::Ready {
                    conns: ready_connections,
                }
            } else {
                Phase::Degraded { misses: 1 }
            };
            Transition {
                next: S::Running {
                    child,
                    since,
                    phase,
                },
                act: None,
                wake: Some(now + PROBE_HEALTHY),
            }
        }
        (
            S::Running {
                child,
                since,
                phase: Phase::Ready { .. },
            },
            E::ProbeFailed,
        ) => Transition {
            next: S::Running {
                child,
                since,
                phase: Phase::Degraded { misses: 1 },
            },
            act: None,
            wake: Some(now + PROBE_HEALTHY),
        },
        (
            S::Running {
                child,
                since,
                phase: Phase::Degraded { .. },
            },
            E::Probed { ready_connections },
        ) if ready_connections > 0 => Transition {
            next: S::Running {
                child,
                since,
                phase: Phase::Ready {
                    conns: ready_connections,
                },
            },
            act: None,
            wake: Some(now + PROBE_HEALTHY),
        },
        (
            S::Running {
                child,
                since,
                phase: Phase::Degraded { misses },
            },
            E::Probed { .. } | E::ProbeFailed,
        ) => {
            if misses + 1 >= DEGRADED_TOLERANCE {
                Transition {
                    next: S::Backoff {
                        until: now + backoff(0),
                        attempt: 0,
                    },
                    act: Some(Act::Terminate),
                    wake: Some(now + backoff(0)),
                }
            } else {
                Transition {
                    next: S::Running {
                        child,
                        since,
                        phase: Phase::Degraded { misses: misses + 1 },
                    },
                    act: None,
                    wake: Some(now + PROBE_HEALTHY),
                }
            }
        }

        // Exit while running: a run that held Ready long enough starts over at
        // attempt 0; anything shorter keeps escalating.
        (S::Running { since, phase, .. }, E::Exited) => {
            let attempt = match phase {
                Phase::Starting { attempt } => attempt,
                _ if now.duration_since(since) >= STABLE_AFTER => 0,
                Phase::Ready { .. } | Phase::Degraded { .. } => 1,
                Phase::Draining { .. } => 0,
            };
            restart(attempt, now)
        }

        (S::Backoff { until, attempt }, E::Tick) if now >= until => Transition {
            next: S::Backoff { until, attempt },
            act: Some(Act::Spawn),
            wake: None,
        },

        (
            S::Running {
                child,
                since,
                phase,
            },
            E::Tick,
        ) => Transition {
            next: S::Running {
                child,
                since,
                phase,
            },
            act: Some(Act::Probe),
            wake: Some(now + PROBE_HEALTHY),
        },

        (other, _) => stay(other),
    }
}

fn restart(attempt: u32, now: Instant) -> Transition {
    let attempt = attempt.saturating_add(1);
    let wait = backoff(attempt);
    Transition {
        next: Supervised::Backoff {
            until: now + wait,
            attempt,
        },
        act: Some(Act::Terminate),
        wake: Some(now + wait),
    }
}

// ---------------------------------------------------------------------------
// Interpreter: the thin shell around `step`. Every decision above is pure.
// ---------------------------------------------------------------------------

const METRICS_PORT: u16 = 20241;

/// Drive the state machine against a real cloudflared process.
///
/// Transitions are logged uniformly here, so instrumentation stays at the effect
/// boundary and out of `step`.
pub async fn supervise(token: String) {
    // The image records which release the build resolved (Dockerfile stage 3);
    // outside the container the file is simply absent.
    if let Ok(version) = std::fs::read_to_string("/etc/cloudflared.version") {
        tracing::info!(version = version.trim(), "cloudflared packaged at build");
    }

    let mut state = Supervised::Stopped;
    let mut child: Option<tokio::process::Child> = None;

    // Kick the machine.
    let mut pending = Some(Act::Spawn);

    loop {
        if let Some(act) = pending.take() {
            match act {
                Act::Spawn => match spawn(&token) {
                    Ok(proc) => {
                        let id = proc.id().unwrap_or(0);
                        child = Some(proc);
                        state = apply(state, Event::Spawned { child: id }, &mut pending);
                    }
                    Err(fault) => {
                        state = apply(state, Event::SpawnFailed { fault }, &mut pending);
                    }
                },
                Act::Probe => {
                    let event = match probe_ready().await {
                        Some(n) => Event::Probed {
                            ready_connections: n,
                        },
                        None => Event::ProbeFailed,
                    };
                    state = apply(state, event, &mut pending);
                }
                Act::Terminate => {
                    if let Some(mut proc) = child.take() {
                        // SIGTERM first so cloudflared drains in-flight edge
                        // requests, then wait bounded.
                        let _ = proc.start_kill();
                        let _ = tokio::time::timeout(GRACE, proc.wait()).await;
                    }
                }
                Act::Kill => {
                    if let Some(mut proc) = child.take() {
                        let _ = proc.kill().await;
                    }
                }
            }
            continue;
        }

        let delay = match state {
            Supervised::Backoff { until, .. } => until.saturating_duration_since(Instant::now()),
            Supervised::Running {
                phase: Phase::Starting { .. },
                ..
            } => PROBE_STARTING,
            Supervised::Running { .. } => PROBE_HEALTHY,
            // A preflight fault needs owner action; re-check on the slow tick.
            Supervised::Faulted { .. } => BACKOFF_CAP,
            Supervised::Stopped => return,
        };

        tokio::time::sleep(delay).await;
        state = apply(state, Event::Tick, &mut pending);
    }
}

fn apply(state: Supervised, event: Event, pending: &mut Option<Act>) -> Supervised {
    let t = step(state, event, Instant::now());
    if t.next != state {
        match t.next {
            // A preflight fault means there is no ingress at all and needs owner
            // action, so it must survive a raised log filter.
            Supervised::Faulted { fault } => {
                tracing::error!(
                    ?fault,
                    "tunnel cannot start; the guest surface is unreachable"
                );
            }
            _ => tracing::info!(from = ?state, ?event, to = ?t.next, "tunnel"),
        }
    }
    *pending = t.act;
    t.next
}

#[allow(
    unsafe_code,
    reason = "PR_SET_PDEATHSIG is the only guarantee that survives SIGKILL of the parent"
)]
fn spawn(token: &str) -> Result<tokio::process::Child, PreflightFault> {
    let metrics = format!("127.0.0.1:{METRICS_PORT}");
    let mut cmd = tokio::process::Command::new("cloudflared");
    cmd.arg("tunnel")
        // Auto-update would replace the build-resolved binary at runtime from
        // the network, outside the image and its provenance.
        .arg("--no-autoupdate")
        .arg("--metrics")
        .arg(&metrics)
        .arg("run")
        .arg("--token")
        .arg(token);

    // Cloudflare holds the routing configuration, so cloudflared takes no origin
    // argument here. The tunnel's public hostname must name `unix:<socket>` in
    // the dashboard; cloudflared decodes remote config through the same
    // `validateIngress` that handles the `unix:` scheme locally.

    // cloudflared must never outlive guestpass: an orphaned connector fronting a
    // dead socket is worse than no tunnel.
    cmd.kill_on_drop(true);

    #[cfg(target_os = "linux")]
    unsafe {
        // SAFETY: pre_exec runs between fork and exec in the child. Both calls
        // are async-signal-safe and touch only this process. The getppid check
        // closes the race where the parent dies before prctl takes effect.
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if libc::getppid() == 1 {
                libc::_exit(1);
            }
            Ok(())
        });
    }

    cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => PreflightFault::BinaryMissing,
        _ => PreflightFault::NotExecutable,
    })
}

/// Readiness comes from cloudflared's metrics endpoint, never from its log
/// output: a log format is not an API.
async fn probe_ready() -> Option<u8> {
    let url = format!("http://127.0.0.1:{METRICS_PORT}/ready");
    let response = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body: serde_json::Value = response.json().await.ok()?;
    let n = body.get("readyConnections")?.as_u64()?;
    u8::try_from(n).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_ready_probe_promotes_a_starting_child() {
        let now = t0();
        let s = Supervised::Running {
            child: 7,
            since: now,
            phase: Phase::Starting { attempt: 0 },
        };
        let t = step(
            s,
            Event::Probed {
                ready_connections: 2,
            },
            now,
        );
        assert!(matches!(
            t.next,
            Supervised::Running {
                phase: Phase::Ready { conns: 2 },
                ..
            }
        ));
    }

    #[test]
    fn a_live_child_with_no_edge_connections_is_restarted() {
        let now = t0();
        let mut s = Supervised::Running {
            child: 7,
            since: now,
            phase: Phase::Ready { conns: 1 },
        };
        for _ in 0..DEGRADED_TOLERANCE {
            s = step(s, Event::ProbeFailed, now).next;
        }
        assert!(
            matches!(s, Supervised::Backoff { .. }),
            "expected a restart after {DEGRADED_TOLERANCE} misses, got {s:?}"
        );
    }

    #[test]
    fn backoff_escalates_and_caps() {
        assert_eq!(backoff(0), BACKOFF_BASE);
        assert!(backoff(3) > backoff(1));
        assert_eq!(backoff(40), BACKOFF_CAP);
    }

    /// A process that reaches Ready for 200ms and dies must keep escalating,
    /// otherwise a crash loop hammers at one second forever.
    #[test]
    fn a_brief_ready_does_not_reset_backoff() {
        let now = t0();
        let brief = Supervised::Running {
            child: 1,
            since: now,
            phase: Phase::Ready { conns: 1 },
        };
        let Supervised::Backoff { attempt, .. } = step(brief, Event::Exited, now).next else {
            panic!("expected backoff")
        };
        assert_eq!(attempt, 2, "a short-lived Ready still escalates");
    }

    #[test]
    fn a_long_ready_run_resets_backoff() {
        let now = t0();
        let stable = Supervised::Running {
            child: 1,
            since: now - STABLE_AFTER - Duration::from_secs(1),
            phase: Phase::Ready { conns: 1 },
        };
        let Supervised::Backoff { attempt, .. } = step(stable, Event::Exited, now).next else {
            panic!("expected backoff")
        };
        assert_eq!(attempt, 1, "a stable run restarts the ramp");
    }

    #[test]
    fn every_state_reaches_stopped_on_shutdown() {
        let now = t0();
        let states = [
            Supervised::Stopped,
            Supervised::Faulted {
                fault: PreflightFault::BinaryMissing,
            },
            Supervised::Backoff {
                until: now,
                attempt: 3,
            },
            Supervised::Running {
                child: 1,
                since: now,
                phase: Phase::Ready { conns: 1 },
            },
        ];
        for s in states {
            let t = step(s, Event::ShutdownRequested, now);
            let settled = match t.next {
                Supervised::Stopped => Supervised::Stopped,
                // A draining child is killed at the deadline.
                running @ Supervised::Running { .. } => {
                    step(running, Event::Tick, now + GRACE + Duration::from_secs(1)).next
                }
                other => other,
            };
            assert_eq!(settled, Supervised::Stopped, "stuck from {s:?}");
        }
    }

    #[test]
    fn a_preflight_fault_does_not_spin() {
        let now = t0();
        let t = step(
            Supervised::Backoff {
                until: now,
                attempt: 1,
            },
            Event::SpawnFailed {
                fault: PreflightFault::BinaryMissing,
            },
            now,
        );
        assert_eq!(
            t.next,
            Supervised::Faulted {
                fault: PreflightFault::BinaryMissing
            }
        );
        assert_eq!(t.act, None, "a faulted supervisor issues no work");
    }
}
