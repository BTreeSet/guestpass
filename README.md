# guestpass

Give a visitor a QR code that turns on your living room lamp from anywhere on the
internet.

guestpass exposes a closed vocabulary of six Home Assistant calls to anyone
holding a high-entropy URL. Home Assistant stays on the LAN. The only route in is
an outbound Cloudflare Tunnel.

```
guest phone ── https ──▶ Cloudflare edge ──▶ [tunnel] ──▶ guestpass ──▶ Home Assistant
                                                          (loopback)     (LAN only)
```

Every call it can make:

| | `on` | `off` |
| --- | --- | --- |
| `light` | `light.turn_on` | `light.turn_off` |
| `switch` | `switch.turn_on` | `switch.turn_off` |
| `fan` | `fan.turn_on` | `fan.turn_off` |

`Controllable` has three variants and `Verb` has two. Configuration selects among
these six calls.

There are no accounts, no login, and no admin page. The config file is the
interface.

## URLs

```
https://gp.example.com/g#K7QF3M2X9WPLNA4RTVBC6DHJ8Z          tap-to-control page
https://gp.example.com/t/K7QF3M2X9WPLNA4RTVBC6DHJ8Z/lamp/on  device and verb in path
https://gp.example.com/t/P2LX8KJ4NRQ7WM3VBZ9CDT6HFA          one fixed call
```

The `/g#` form carries the token in the URL fragment, which browsers keep local.
It reaches no server log, no `Referer` header, and no Cloudflare log. Hand this
form to guests who open a page.

The `/t/` form serves clients that can only fetch a URL: NFC tags, ESP32 buttons,
Apple Shortcuts, `curl`.

## Install

### Home Assistant add-on

Add this repository under **Settings → Add-ons → Add-on Store → ⋮ →
Repositories**, install guestpass, set `policy_file` in the options.

The add-on receives `SUPERVISOR_TOKEN` automatically. It maps no host ports.

### Docker Compose

For Home Assistant Container, supply a long-lived access token:

```yaml
services:
  guestpass:
    image: ghcr.io/btreemap/guestpass:latest
    read_only: true
    environment:
      GUESTPASS_HA_URL: http://homeassistant:8123
      GUESTPASS_HA_TOKEN_FILE: /run/secrets/ha_token
    volumes:
      - ./guestpass.yaml:/config/guestpass.yaml:ro
      - ./tunnel.json:/config/tunnel.json:ro
```

guestpass keeps no state and runs read-only.

### Cloudflare

1. Create a tunnel under **Zero Trust → Networks → Tunnels** and download its
   credentials JSON.
2. Point a single-label subdomain at it, such as `gp.example.com`. Cloudflare's
   Universal SSL wildcard covers one level, so the name stays out of public
   Certificate Transparency logs.
3. Set **Bot Fight Mode** to off for that hostname. NFC tags and microcontrollers
   cannot solve a JavaScript challenge.
4. Leave **Cache Everything** disabled. A cached `200` stops the call reaching
   guestpass.
5. Leave **Cloudflare Access** off this hostname. Guests are anonymous.

guestpass generates cloudflared's config, including a catch-all `404`, so one
hostname reaches one port.

## Configuration

One file describes everything the internet can reach.

```yaml
version: 1

tunnel:
  hostname: gp.example.com
  credentials_file: tunnel.json

devices:
  - id: lamp
    label: "Living room lamp"
    entity: light.living_room_floor

passes:
  - id: guest                       # arity 2 → https://HOST/g#<token>
    label: "Guest pass"
    tokens: ["K7QF3M2X9WPLNA4RTVBC6DHJ8Z"]
    devices: [lamp]
    quota: { per_minute: 6 }

  - id: door-tag                    # arity 0 → https://HOST/t/<token>
    tokens: ["P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"]
    device: lamp
    verb: on
    trigger: direct
    quota: { per_minute: 6 }
```

Tokens are inline, so this file is a secret: mode `0600`, same handling as
`secrets.yaml`. `guestpass gen-token` prints a fresh one.

A pass's URL shape follows from the scope fields it declares:

| Declares | URL |
| --- | --- |
| `devices: [a, b]` | `/t/<token>/<device>/<verb>` |
| `device: a` | `/t/<token>/<verb>` |
| `device: a` + `verb: on` | `/t/<token>` |

`trigger: direct` makes a plain `GET` fire the call, which NFC tags and buttons
require. Anything that fetches such a URL fires it, link previews included. Both
verbs are absolute, so repeated fetches leave the device in the same state a
single fetch does. The default renders a confirmation page on `GET` and fires on
`POST`.

`quota.per_minute` bounds how often a pass can fire. It is the standing limit on
what a leaked token can do.

Every reload prints the full expansion — each URL, its call, its quota — to the
add-on log.

## Rotating a pass

Replace the token:

```yaml
    tokens: ["N4WJ7KP2XQ8MRT3VBZ9CDL6HFA"]
```

Save. guestpass reloads on file change and the previous token stops working
immediately. Print the new card.

To swap physical tags without a gap, keep the previous token for a window:

```yaml
    tokens:
      - "N4WJ7KP2XQ8MRT3VBZ9CDL6HFA"
      - value: "P2LX8KJ4NRQ7WM3VBZ9CDT6HFA"
        accepted_until: 2026-09-07T00:00:00Z
```

QR images cover the head token, so the output folder matches what belongs on the
wall:

```
guestpass qr --config guestpass.yaml --out ./qr
```

This is a one-shot command. The running service needs no writable path.

## Documentation

* [docs/design.md](docs/design.md) — domain model, URL algebra, effect boundary, complexity
* [docs/threat-model.md](docs/threat-model.md) — adversary, worst case, residual risk
* [docs/decisions.md](docs/decisions.md) — the premises each design decision rests on
* [AGENTS.md](AGENTS.md) — invariants, contribution rules, CI gates

## License

MIT.
