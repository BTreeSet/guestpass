//! The only module that speaks to Home Assistant. Every request it can make is
//! one of the six constants [`crate::domain::service_of`] returns.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::domain::EntityId;
use crate::gate::Admitted;

/// What the server last knew about a device.
///
/// `Unknown` and `Offline` are distinct: the first is our link to Home
/// Assistant, the second is the device. `Stale` retains the last good reading
/// so a degraded link shows what was true rather than nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Reading {
    Unknown,
    Offline,
    Live { on: bool },
    Stale { on: bool },
}

impl Reading {
    /// Degrade a reading when the link fails, preserving what was last known.
    #[must_use]
    const fn degraded(self) -> Self {
        match self {
            Self::Live { on } | Self::Stale { on } => Self::Stale { on },
            Self::Unknown | Self::Offline => Self::Unknown,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("no Home Assistant credential: set SUPERVISOR_TOKEN or GUESTPASS_HA_TOKEN(_FILE)")]
    NoCredential,
    #[error("GUESTPASS_HA_TOKEN_FILE could not be read: {0}")]
    TokenFile(#[from] std::io::Error),
    #[error("could not build the HTTP client: {0}")]
    Client(#[from] reqwest::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum HaError {
    #[error("Home Assistant did not respond: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Home Assistant refused the call: {0}")]
    Status(reqwest::StatusCode),
}

/// A bearer credential and a base URL. Provenance is logged at detection and
/// carried no further, because both sources reduce to the same two values.
pub struct HaLink {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl HaLink {
    /// # Errors
    /// Returns [`LinkError`] when no credential is present or the client fails.
    pub fn detect() -> Result<Self, LinkError> {
        let (base, token, source) = if let Ok(t) = std::env::var("SUPERVISOR_TOKEN") {
            ("http://supervisor/core".to_owned(), t, "supervisor")
        } else {
            let base = std::env::var("GUESTPASS_HA_URL")
                .unwrap_or_else(|_| "http://homeassistant:8123".to_owned());
            let token = match std::env::var("GUESTPASS_HA_TOKEN") {
                Ok(t) => t,
                Err(_) => {
                    let path = std::env::var("GUESTPASS_HA_TOKEN_FILE")
                        .map_err(|_| LinkError::NoCredential)?;
                    std::fs::read_to_string(path)?.trim().to_owned()
                }
            };
            (base, token, "long-lived token")
        };
        tracing::info!(source, base = %base, "home assistant link");
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            token,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
        })
    }

    /// Perform an admitted call. The only mutating request this program makes.
    ///
    /// Both verbs are absolute, so this is idempotent and a transport retry is
    /// safe. Retries are left to the caller.
    ///
    /// # Errors
    /// Returns [`HaError`] on transport failure or a non-success status.
    pub async fn execute(&self, admitted: &Admitted) -> Result<(), HaError> {
        let call = admitted.call();
        let url = format!("{}/api/services/{}", self.base, call.service());
        let body = serde_json::json!({ "entity_id": call.entity().to_string() });
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(HaError::Status(response.status()))
        }
    }

    async fn poll(&self, entity: &EntityId) -> Result<Reading, HaError> {
        let url = format!("{}/api/states/{entity}", self.base);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(HaError::Status(response.status()));
        }
        let body: serde_json::Value = response.json().await?;
        Ok(
            match body.get("state").and_then(serde_json::Value::as_str) {
                Some("on") => Reading::Live { on: true },
                Some("off") => Reading::Live { on: false },
                Some("unavailable") => Reading::Offline,
                _ => Reading::Unknown,
            },
        )
    }
}

/// Latest reading per entity.
///
/// Readings are a cache: losing them on restart costs one poll interval and
/// nothing else, which is why nothing here is persisted.
#[derive(Debug, Default)]
pub struct Readings(RwLock<HashMap<String, Reading>>);

impl Readings {
    #[must_use]
    pub fn get(&self, entity: &EntityId) -> Reading {
        self.0
            .read()
            .map(|m| {
                m.get(&entity.to_string())
                    .copied()
                    .unwrap_or(Reading::Unknown)
            })
            .unwrap_or(Reading::Unknown)
    }

    fn set(&self, entity: &EntityId, reading: Reading) {
        if let Ok(mut m) = self.0.write() {
            m.insert(entity.to_string(), reading);
        }
    }

    /// Refresh one entity now, so a fired call reports what actually happened
    /// instead of predicting it.
    pub async fn refresh(&self, link: &HaLink, entity: &EntityId) -> Reading {
        match link.poll(entity).await {
            Ok(reading) => {
                self.set(entity, reading);
                reading
            }
            Err(e) => {
                tracing::warn!(%entity, error = %e, "state read failed");
                let degraded = self.get(entity).degraded();
                self.set(entity, degraded);
                degraded
            }
        }
    }
}

/// Poll every pinned entity forever.
///
/// At around ten entities on a LAN service, one request each per interval is a
/// negligible load and removes the WebSocket client, its auth handshake, and its
/// reconnect state machine from the program.
pub async fn run_poller(
    link: std::sync::Arc<HaLink>,
    readings: std::sync::Arc<Readings>,
    registry: std::sync::Arc<arc_swap::ArcSwap<crate::policy::Registry>>,
    interval: Duration,
) {
    loop {
        let pinned: Vec<EntityId> = registry.load().pinned().to_vec();
        for entity in &pinned {
            readings.refresh(&link, entity).await;
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_read_keeps_the_last_known_value() {
        assert_eq!(
            Reading::Live { on: true }.degraded(),
            Reading::Stale { on: true }
        );
        assert_eq!(
            Reading::Stale { on: false }.degraded(),
            Reading::Stale { on: false }
        );
        assert_eq!(Reading::Unknown.degraded(), Reading::Unknown);
        assert_eq!(Reading::Offline.degraded(), Reading::Unknown);
    }

    #[test]
    fn readings_serialize_to_the_shape_the_page_parses() {
        let json = serde_json::to_string(&Reading::Live { on: true }).expect("serializes");
        assert_eq!(json, r#"{"state":"live","on":true}"#);
        assert_eq!(
            serde_json::to_string(&Reading::Unknown).expect("serializes"),
            r#"{"state":"unknown"}"#
        );
    }

    #[test]
    fn an_unseen_entity_reads_as_unknown() {
        let r = Readings::default();
        let e = EntityId::parse("light.a").expect("entity");
        assert_eq!(r.get(&e), Reading::Unknown);
    }
}
