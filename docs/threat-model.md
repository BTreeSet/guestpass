# Threat model

## Assets

| Asset | Exposure |
| --- | --- |
| The six calls, on declared devices | reachable by any holder of a pass token |
| On/off state of declared devices | readable by any holder of an interactive pass |
| The config file, including tokens | on the Home Assistant host, mode `0600` |
| The Home Assistant credential | held by guestpass, never transmitted outward |
| Home Assistant itself | LAN only, no inbound path |

## Adversary

**In scope.**

* **Opportunistic internet scanners.** Automated hosts probing every name that
  appears in Certificate Transparency logs and every common path.
* **A guest who turns rogue after leaving.** Someone who legitimately received a
  pass and later uses it uninvited.
* **A casual observer of a physical artifact.** Someone who photographs a QR code
  at a party.

**Out of scope.**

* A determined attacker targeting this household specifically.
* An attacker with access to the Home Assistant host or the config file.
* Cloudflare as an adversary. Cloudflare terminates TLS and reads request paths.
* A guest with physical access to the devices themselves, who can reach the light
  switch by hand.

## Security property

The token is a shared secret distributed by physical presence — a QR code on a
wall, an NFC tag on a table. The claim it supports:

> *You were in my home at some point.*

The claim is about the past, which is why rotation is the control
(see [D-3](decisions.md)).

## Discovery

Guessing costs 2¹²⁷ expected requests against a rate-limited endpoint. Discovery
is the vector that matters, and it has three surfaces:

**The hostname.** Certificate Transparency logs are public and scanned within
minutes of an issuance, so a hostname that carries its own certificate is known
shortly after it exists. Discovery of the hostname leaves 2¹²⁷ expected requests
to reach a pass.

**The 404.** Requests reaching the correct hostname with a wrong path arrive at
guestpass. The response carries no product name, no version header, and no
indication that a token-shaped path exists. Lookup is digest-keyed, so timing is
uniform across "no such token" and "valid token, wrong verb".

**The physical artifact.** A photographed QR code is a leak. Rotation is the
response.

Sustained invalid-token traffic is logged at a rate-limited `WARN`, and crossing
a threshold raises one Home Assistant notification per day.

## Worst case

An attacker holds every token in the config.

They can turn declared lights, switches, and fans on and off, up to
`quota.per_minute` each, and read the on/off state of those devices. That is the
complete list. They cannot enumerate other entities, reach any other service,
read state beyond the projection, or reach Home Assistant, which is bound to the
LAN and addressed through six constant paths on loopback.

## Residual risks

**Power cycling.** Repeated on/off can shorten a lamp's life or stress a motor.
`quota.per_minute` is the bound, which is why it is a standing setting rather
than an optional one.

**Presence inference.** The on/off state of a light indicates whether someone is
home. This applies to passes that render a page, which shows device state.
Direct-trigger passes expose no read path.

**Cloudflare sees tokens.** TLS terminates at the edge, so request paths appear
in Cloudflare's logs. A pass carries one device and one verb under a rate quota,
which sets the ceiling on what such a log entry is worth.

**Nuisance in the small hours.** A leaked token can flip a light at 3am until
rotated. The `Window::Daily` variant bounds hours of use when wanted.

## Non-goals

* Guest access to locks, alarms, garage doors, scripts, scenes, or helpers.
* Per-guest identity, accounting, or attribution.
* Remote access to Home Assistant for the owner.
* Availability during a Cloudflare outage.
* Confidentiality of request paths from Cloudflare.
