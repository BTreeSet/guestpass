# guestpass

Give a visitor a QR code that turns on your living room lamp from anywhere on the
internet.

guestpass exposes a closed vocabulary of six Home Assistant calls to anyone
holding a high-entropy URL. Home Assistant stays on the LAN. guestpass opens no
network port at all: it listens on a UNIX socket that cloudflared reaches inside
the same container, and the only route in is an outbound Cloudflare Tunnel.

```
guest phone ── https ──▶ Cloudflare edge ──▶ [tunnel] ──▶ guestpass ──▶ Home Assistant
                                                       unix socket        (LAN only)
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

A pass is a high-entropy path segment. Later segments apply arguments.

```
https://gp.example.com/t/k7qf3m2x9wplna4rtvbc6dhj8z          control page
https://gp.example.com/t/k7qf3m2x9wplna4rtvbc6dhj8z/lamp/on  device and verb
https://gp.example.com/t/p2lx8kj4nrq7wm3vbz9cdt6hfa          one fixed call
```

A pass that stops short of a full call renders a page listing what remains. A
pass that names a full call fires it.

The URL is the credential, so it serves every client that can fetch one: a
browser, an NFC tag, an ESP32 button, an Apple Shortcut, `curl`.

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
    image: ghcr.io/btreeset/guestpass:latest
    read_only: true
    environment:
      GUESTPASS_HA_URL: http://homeassistant:8123
      GUESTPASS_HA_TOKEN_FILE: /run/secrets/ha_token
    volumes:
      - ./guestpass.yaml:/config/guestpass.yaml:ro
```

guestpass keeps no state and runs read-only. Its socket sits on the tmpfs the
container runtime already mounts.

## Configuration

One file describes everything the internet can reach.

```yaml
version: 1

tunnel:
  token: "eyJhIjoiN2Q0..."               # from Cloudflare Zero Trust
  public_url: "https://gp.example.com"   # optional, used when printing URLs

devices:
  - id: lamp
    label: "Living room lamp"
    entity: light.living_room_floor

passes:
  - id: guest                       # arity 2 → https://HOST/t/<token>
    label: "Guest pass"
    tokens: ["k7qf3m2x9wplna4rtvbc6dhj8z"]
    devices: [lamp]
    quota: { per_minute: 6 }

  - id: door-tag                    # arity 0 → https://HOST/t/<token>
    tokens: ["p2lx8kj4nrq7wm3vbz9cdt6hfa"]
    device: lamp
    verb: "on"
    trigger: direct
    quota: { per_minute: 6 }
```

Tokens are inline, so this file is a secret: mode `0600`, same handling as
`secrets.yaml`. `guestpass gen-token` prints a fresh one. Tokens and paths are
case-insensitive; printed cards encode the URL in capitals, which QR encodes in
alphanumeric mode so each module prints larger. `public_url` is scheme and host
only.

### Tunnel

`tunnel.token` is a connector token from Cloudflare Zero Trust. Cloudflare holds
the routing configuration and cloudflared fetches it, so guestpass runs the
connector and takes no part in ingress.

In the Zero Trust portal, set the public hostname's service to exactly:

```
unix:/run/guestpass/guest.sock
```

That path is fixed by guestpass and is the one thing you configure on the
Cloudflare side. `tunnel.public_url` is the hostname you pointed at it, which
guestpass uses to print URLs and cards.

Bot Fight Mode on the tunnel hostname blocks NFC tags, microcontrollers, and
`curl`.

### Passes

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
      - value: "p2lx8kj4nrq7wm3vbz9cdt6hfa"
        accepted_until: 2026-09-07T00:00:00Z
```

## Printing cards

guestpass emits a LaTeX document and stops there. Compile it with `pdflatex`, or
paste it into Overleaf, and print the resulting page.

```
guestpass tex --config guestpass.yaml > pass.tex
pdflatex pass.tex
```

The document needs only the `qrcode` package, which draws QR codes with the TeX
`\rule` primitive: no shell-escape, no external program, and no graphics package.
It compiles unchanged under pdflatex, xelatex, lualatex, and Overleaf.

Cards cover head tokens, so the page matches what belongs on the wall.

Add-on installs have no shell. Set `emit_tex: true` in the add-on options and the
document is printed to the **Log** tab on startup, ready to copy into Overleaf or
a local file. `guestpass tex` is a pure function of the config, so running the
standalone binary from Releases against a copy of `guestpass.yaml` on your own
machine produces the same bytes.

[`template/pass.tex`](template/pass.tex) is the same document with two example
cards, for editing by hand.

## Documentation

* [docs/design.md](docs/design.md) — domain model, URL algebra, effect boundary, complexity
* [docs/threat-model.md](docs/threat-model.md) — adversary, worst case, residual risk
* [docs/decisions.md](docs/decisions.md) — the premises each design decision rests on
* [AGENTS.md](AGENTS.md) — invariants, contribution rules, CI gates

## License

MIT.
