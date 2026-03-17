# Aegis — Frequently Asked Questions

---

### Why not just use env vars?

Env vars are easy, but any process the agent can access may also read them. One prompt injection and the key is exfiltrated. Aegis keeps the raw secret out of the agent context entirely and injects it only at the network boundary, to approved domains, with every access logged.

---

### How is this different from Infisical?

Infisical is a cloud secrets platform adding agent features — great product, different trust model. Aegis is local-first: your secrets never leave your machine, there's no cloud control plane, and it works as a transparent proxy rather than an SDK or platform. Different threats, different approaches.

See [COMPARISON.md](COMPARISON.md) for a full feature comparison.

---

### Why not Vault or Doppler?

Those tools help store and distribute secrets. Aegis solves a different problem: preventing agents from directly handling raw credentials during API access. You can use Vault *and* Aegis — store your keys in Vault, route agent API calls through Aegis.

---

### This seems like more setup.

It's slightly more setup than dropping a key into a config file, but that setup buys you domain restrictions, audit trail, credential scoping, and a cleaner trust boundary. `aegis init && aegis vault add && aegis gate` is three commands — about 2 minutes.

---

### Can I trust a new security tool?

Fair question — trust should be earned. The full source is open (Apache 2.0), the architecture and threat model are documented ([SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)), and the crypto choices are standard (AES-256-GCM, PBKDF2). There's a published [STRIDE threat model](THREAT_MODEL.md) with 28 threats analysed and 0 critical/high unmitigated findings. Read the code — that's the point of open source for security tools.

---

### What if the proxy goes down?

Your API calls fail the same way they would if any intermediary went down — the agent gets a connection error. No credentials are exposed. Restart Gate and you're back. For production setups, systemd/launchd/Docker restart policies handle this.

---

### Does this work with Claude/Cursor/Cline?

Yes — Aegis is an MCP server. Run `aegis mcp config claude` and paste the output into your Claude Desktop config. Guides exist for all major MCP clients:

- [Claude Desktop](guides/claude-desktop.md)
- [Cursor](guides/cursor.md)
- [VS Code](guides/vscode.md)
- [Windsurf](guides/windsurf.md)
- [Cline](guides/cline.md)

---

### What's the latency impact?

Aegis is a local proxy (localhost). Added latency is sub-millisecond for credential injection. In benchmarks: 8,400 requests/sec throughput, 2ms p50 latency, 4ms p99. The vast majority of request time is the round-trip to the real API.

---

### What is the X-Target-Host header?

`X-Target-Host` tells Gate which upstream API server to forward the request to. Gate checks this hostname against the credential's domain allowlist before forwarding — if it doesn't match, the request is blocked.

If your credential has only one domain (e.g. `--domains api.slack.com`), Gate uses it automatically and the header is optional. If your credential has multiple allowed domains, include the header to specify which one. See [Request Routing](USAGE.md#request-routing) for details.

---

### Can teams use it or is it only local?

Both. Solo use works out of the box. Teams get agent auth tokens, credential grants, RBAC users, and YAML policy files — all version-controllable and reviewable.

---

### Why TypeScript and not Rust?

Development speed. This is a solo dev project competing in a fast-moving space. TypeScript + Node.js let me ship a complete product (proxy, vault, MCP server, dashboard, CLI, policy engine) faster than I could in Rust. The crypto operations use Node.js's native `crypto` module (OpenSSL under the hood), not JS implementations. If performance becomes a bottleneck, critical paths can be moved to native addons.

---

### Is this production-ready?

It's at v1.0 with a published STRIDE threat model (28 threats analysed, 0 critical/high unmitigated), documented security architecture, and hardening work already in place. Solid for individual and small team use.
