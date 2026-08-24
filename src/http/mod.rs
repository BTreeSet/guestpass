//! The guest surface. Serves the embedded page, folds the request path, and
//! fires admitted calls. This router is bound to loopback and reached only
//! through the Cloudflare tunnel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rust_embed::RustEmbed;
use time::OffsetDateTime;

use crate::domain::{DeviceIx, TokenDigest, Verb, Vocabulary};
use crate::gate::{Bucket, LivenessDenial, admit};
use crate::ha::{HaLink, Reading, Readings};
use crate::policy::{CompiledPass, Device, PartialCall, Registry, ShapeDenial, Trigger, walk};

#[derive(RustEmbed)]
#[folder = "frontend/dist/"]
struct Assets;

pub struct AppState {
    pub registry: Arc<ArcSwap<Registry>>,
    pub readings: Arc<Readings>,
    pub link: Arc<HaLink>,
    /// One fixed-window counter per pass. Bounded by the pass count, in memory,
    /// and disposable: a restart costs at most one window.
    pub buckets: Mutex<HashMap<u16, Bucket>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("the guest listener must bind loopback; refusing {0}")]
pub struct NotLoopback(pub std::net::IpAddr);

/// Gate G9. The security argument for trusting `CF-Connecting-IP` is exactly
/// this bind address: one hop reaches the listener and it is always cloudflared
/// in this container's own namespace.
///
/// # Errors
/// Returns [`NotLoopback`] for any address reachable from outside the namespace.
pub fn bind_addr(ip: std::net::IpAddr, port: u16) -> Result<std::net::SocketAddr, NotLoopback> {
    if ip.is_loopback() {
        Ok(std::net::SocketAddr::new(ip, port))
    } else {
        Err(NotLoopback(ip))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/t/{token}", get(entry).post(entry).head(probe))
        .route(
            "/t/{token}/{*rest}",
            get(entry_rest).post(entry_rest).head(probe),
        )
        .fallback(nothing_here)
        .with_state(state)
}

/// A bare 404 with no product name, no version, and no hint that a token-shaped
/// path exists. Identical for an unknown token and a wrong path.
async fn nothing_here() -> Response {
    (StatusCode::NOT_FOUND, guard_headers(), "Not found").into_response()
}

/// `HEAD` never fires. Scanners and proxies send it, so it gets a free probe.
async fn probe() -> Response {
    (StatusCode::OK, guard_headers()).into_response()
}

fn guard_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    // A cached 200 would stop the call ever reaching guestpass again.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    // The token is in the path, so stop it propagating from anything we serve.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    h
}

async fn entry(
    state: State<Arc<AppState>>,
    method: axum::http::Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    handle(state, method, &headers, &token, "").await
}

async fn entry_rest(
    state: State<Arc<AppState>>,
    method: axum::http::Method,
    headers: HeaderMap,
    Path((token, rest)): Path<(String, String)>,
) -> Response {
    handle(state, method, &headers, &token, &rest).await
}

async fn handle(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    headers: &HeaderMap,
    token: &str,
    rest: &str,
) -> Response {
    let registry = state.registry.load_full();

    // Resolve the token first, so assets are reachable only behind a valid pass
    // and an invalid token learns nothing from any path.
    let Some(binding) = registry.binding(&TokenDigest::of(token)) else {
        return nothing_here().await;
    };

    // The page uses relative asset URLs, so its bundle resolves under the pass
    // path. Serve those before folding, since they name no device.
    if let Some(asset) = Assets::get(rest.trim_start_matches('/')) {
        let mime = mime_guess::from_path(rest).first_or_octet_stream();
        return (
            guard_headers(),
            [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
            Body::from(asset.data.into_owned()),
        )
            .into_response();
    }

    let pass = registry.pass(binding.pass);
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() > 2 {
        return nothing_here().await;
    }

    let position = match walk(&registry, pass, segments) {
        Ok(p) => p,
        // A shape refusal is indistinguishable from an unknown path, so probing
        // for devices and verbs learns nothing.
        Err(ShapeDenial::NoSuchDevice | ShapeDenial::NoSuchVerb | ShapeDenial::TrailingSegment) => {
            return nothing_here().await;
        }
    };

    let fires = match (&method, &position) {
        (&axum::http::Method::POST, PartialCall::Call { .. }) => true,
        (&axum::http::Method::GET, PartialCall::Call { .. }) => pass.trigger == Trigger::Direct,
        (&axum::http::Method::POST, _) => return nothing_here().await,
        _ => false,
    };

    if fires {
        let PartialCall::Call { call, .. } = position else {
            unreachable!("`fires` is set only at a saturated position")
        };
        return fire(&state, &registry, pass, binding, call, headers).await;
    }

    render(&state, &registry, pass, &position, headers)
}

async fn fire(
    state: &Arc<AppState>,
    registry: &Registry,
    pass: &CompiledPass,
    binding: crate::policy::TokenBinding,
    call: crate::policy::Authorized,
    headers: &HeaderMap,
) -> Response {
    let now = OffsetDateTime::now_utc();
    let entity = call.entity().clone();

    let admitted = {
        let mut buckets = state.buckets.lock().expect("bucket mutex");
        let bucket = buckets
            .entry(binding.pass.0)
            .or_insert_with(|| Bucket::new(now));
        admit(call, pass, binding, bucket, now)
    };

    let admitted = match admitted {
        Ok(a) => a,
        Err(denial) => {
            tracing::info!(pass = %pass.id, ?denial, "refused");
            return refusal(denial, headers);
        }
    };

    tracing::info!(
        pass = %pass.id,
        service = admitted.call().service(),
        entity = %entity,
        "fired"
    );

    match state.link.execute(&admitted).await {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!(pass = %pass.id, error = %e, "home assistant call failed");
            return (
                StatusCode::BAD_GATEWAY,
                guard_headers(),
                "The hub did not accept that. Try again in a moment.",
            )
                .into_response();
        }
    }

    // Report what actually happened rather than predicting it.
    let reading = state.readings.refresh(&state.link, &entity).await;

    if wants_json(headers) {
        (guard_headers(), Json(reading)).into_response()
    } else {
        let _ = registry;
        (
            guard_headers(),
            plain(said(reading, admitted.call().verb())),
        )
            .into_response()
    }
}

fn refusal(denial: LivenessDenial, headers: &HeaderMap) -> Response {
    // Liveness detail is actionable and carries no probe value, so it reaches
    // the guest unchanged.
    let (status, text) = match denial {
        LivenessDenial::Expired => (
            StatusCode::GONE,
            "This pass has expired. Ask your host.".to_owned(),
        ),
        LivenessDenial::Retired => (
            StatusCode::GONE,
            "This pass has been replaced. Ask your host for a new one.".to_owned(),
        ),
        LivenessDenial::QuotaExhausted { retry_after } => (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Too many requests. Try again in {} seconds.",
                retry_after.as_secs().max(1)
            ),
        ),
    };
    let mut h = guard_headers();
    if let LivenessDenial::QuotaExhausted { retry_after } = denial
        && let Ok(v) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
    {
        h.insert(header::RETRY_AFTER, v);
    }
    if wants_json(headers) {
        (status, h, text).into_response()
    } else {
        (status, h, plain(text)).into_response()
    }
}

fn render(
    state: &Arc<AppState>,
    registry: &Registry,
    pass: &CompiledPass,
    position: &PartialCall<'_>,
    headers: &HeaderMap,
) -> Response {
    if wants_json(headers) {
        return (
            guard_headers(),
            Json(view_of(state, registry, pass, position)),
        )
            .into_response();
    }
    match Assets::get("index.html") {
        Some(index) => (
            guard_headers(),
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            Body::from(index.data.into_owned()),
        )
            .into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            guard_headers(),
            "The page is not available in this build.",
        )
            .into_response(),
    }
}

/// The wire shape the page parses. One variant per arity of the fold.
#[derive(serde::Serialize)]
#[serde(tag = "at", rename_all = "lowercase")]
enum ViewDto {
    Devices {
        label: String,
        devices: Vec<DeviceDto>,
    },
    Verbs {
        label: String,
        device: DeviceDto,
    },
    Call {
        label: String,
        device: DeviceDto,
        verb: &'static str,
    },
}

#[derive(serde::Serialize)]
struct DeviceDto {
    id: String,
    label: String,
    reading: Reading,
}

fn device_dto(state: &Arc<AppState>, device: &Device) -> DeviceDto {
    DeviceDto {
        id: device.id.to_string(),
        label: device.label.to_string(),
        reading: state.readings.get(&device.entity),
    }
}

fn view_of(
    state: &Arc<AppState>,
    registry: &Registry,
    pass: &CompiledPass,
    position: &PartialCall<'_>,
) -> ViewDto {
    let label = pass.label.to_string();
    match position {
        PartialCall::Pass { devices, .. } => ViewDto::Devices {
            label,
            devices: devices
                .iter()
                .map(|ix: &DeviceIx| device_dto(state, registry.device(*ix)))
                .collect(),
        },
        PartialCall::Device { device, .. } => ViewDto::Verbs {
            label,
            device: device_dto(state, device),
        },
        PartialCall::Call { call, .. } => {
            let device = registry
                .devices()
                .iter()
                .find(|d| &d.entity == call.entity())
                .expect("a saturated call names a configured device");
            ViewDto::Call {
                label,
                device: device_dto(state, device),
                verb: call.verb().token(),
            }
        }
    }
}

/// `Accept` decides presentation only. Being wrong here is cosmetic, never
/// semantic: the same URL means the same thing to every client.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"))
}

fn plain(text: String) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        text,
    )
        .into_response()
}

/// Server-authored text a URL-fetch client can show in a notification.
fn said(reading: Reading, verb: Verb) -> String {
    match reading {
        Reading::Live { on } | Reading::Stale { on } => if on { "On." } else { "Off." }.to_owned(),
        Reading::Offline => "Sent, but the device reports unavailable.".to_owned(),
        Reading::Unknown => format!("Sent {}.", verb.token()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn only_loopback_may_carry_the_guest_surface() {
        assert!(bind_addr(Ipv4Addr::LOCALHOST.into(), 8099).is_ok());
        assert!(bind_addr(Ipv6Addr::LOCALHOST.into(), 8099).is_ok());
        assert_eq!(
            bind_addr(Ipv4Addr::UNSPECIFIED.into(), 8099).unwrap_err(),
            NotLoopback(Ipv4Addr::UNSPECIFIED.into()),
            "0.0.0.0 would make the container's mapped port a bypass around the tunnel"
        );
        assert!(bind_addr(Ipv4Addr::new(192, 168, 1, 10).into(), 8099).is_err());
    }
}
