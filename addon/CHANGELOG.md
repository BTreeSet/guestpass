# Changelog

## 0.1.0

First release.

* Guest control page and direct-fire URLs behind high-entropy pass tokens.
* Closed vocabulary: light, switch, and fan; on and off.
* Cloudflare Tunnel is the sole ingress, over a UNIX socket; no network port.
* Token rotation with overlap windows; per-pass quotas.
* Printable pass cards as a LaTeX document (`emit_tex`).
