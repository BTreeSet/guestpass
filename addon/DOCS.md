# guestpass

Give a visitor a QR code that turns on one light. The code works from anywhere.
Home Assistant stays off the internet.

## Before installing

Create a Cloudflare Zero Trust tunnel and copy its connector token. In the
tunnel's public hostname, set the service to exactly:

```
unix:/run/guestpass/guest.sock
```

## Configure

Write `/config/guestpass.yaml` (the add-on configuration directory, reachable
from the **File editor** add-on as `/addon_configs/*_guestpass/`):

```yaml
version: 1

tunnel:
  token: "eyJhIjoiN2Q0..."
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
```

The file holds tokens, so it is a secret. Give it mode `0600`.

## Options

| Option | Meaning |
| --- | --- |
| `policy_file` | Path to the YAML above. |
| `log_level` | Verbosity of this log. |
| `emit_tex` | Print the printable LaTeX pass document to this log at startup. |

## Print the passes

Set `emit_tex` and restart. The **Log** tab then carries a complete LaTeX
document. Paste it into Overleaf and print the PDF.

## Replace a token

Edit the token in the YAML, restart, print a new QR code. The old URL stops
working the moment the config reloads.

## Log

Every start prints every URL the config denotes and the call each one makes.
Compare it against what you meant to publish.
