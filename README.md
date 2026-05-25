# deny-sh-mcp

Model Context Protocol server for [deny.sh](https://deny.sh), the deniability infrastructure. Lets any MCP-compatible AI agent call deny.sh tools so the real credential never enters the agent's context window. When the agent gets prompt-injected, what gets surrendered is the decoy.

This package wraps the **Operate pillar** of deny.sh (hosted API mode) and the **Encrypt pillar** (local, offline mode) behind eleven MCP tools.

**[deny.sh](https://deny.sh)** · [Agent docs](https://deny.sh/agents) · [Whitepaper](https://deny.sh/whitepaper) · [Verify it yourself](https://deny.sh/verify) · [TypeScript SDK](https://github.com/deny-sh-crypto/deny-js)

## What this is

A standalone MCP server that exposes deny.sh's deniable-encryption primitive as tools any agent can call.

```bash
npx deny-sh-mcp
```

Single file. Zero runtime dependencies. Speaks stdio JSON-RPC, talks to the deny.sh public API over HTTPS with a user-supplied bearer key.

## Tools

11 tools in two modes. Local-mode tools run entirely on your machine, no network round-trip, no API key required.

### API mode (requires `DENY_API_KEY`)

| Tool                | Purpose                                                                          |
|---------------------|----------------------------------------------------------------------------------|
| `deny_encrypt`      | Encrypt text via the deny.sh API                                                 |
| `deny_decrypt`      | Decrypt with control data + passwords                                            |
| `deny_create_decoy` | Create a deniable decoy (new control data, different plaintext, same ciphertext) |
| `deny_vault_store`  | Store encrypted data in your deny.sh vault                                       |
| `deny_vault_list`   | List your vault items                                                            |
| `deny_vault_get`    | Retrieve a vault item by id                                                      |
| `deny_usage`        | Check current API usage against your plan limits                                 |

### Local mode (no network, no key)

| Tool                       | Purpose                                                                |
|----------------------------|------------------------------------------------------------------------|
| `deny_local_encrypt`       | Encrypt locally using the same algorithm as the API                    |
| `deny_local_decrypt`       | Decrypt locally                                                        |
| `deny_local_create_decoy`  | Create decoy control data locally                                      |
| `deny_local_shamir_split`  | Split a secret into M-of-N Shamir shares locally                       |

## Setup

1. Get an API key at https://deny.sh/register (free tier: 500 calls/mo).
2. Set `DENY_API_KEY` in the agent's MCP server env block.
3. Add to your agent's MCP config.

### Claude Desktop / OpenClaw

```json
{
  "mcpServers": {
    "deny": {
      "command": "npx",
      "args": ["deny-sh-mcp"],
      "env": { "DENY_API_KEY": "dk_your_key" }
    }
  }
}
```

### Anthropic API / Codex CLI / other MCP-compatible agents

Same shape. Most agents accept the standard MCP server config block above. Check your agent's docs for the exact path (Claude Desktop on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`).

## Environment

| Variable        | Default                  | Notes                                        |
|-----------------|--------------------------|----------------------------------------------|
| `DENY_API_KEY`  | (optional)               | Bearer key from https://deny.sh/register. Required only for API-mode tools; local-mode tools work without it. |
| `DENY_API_URL`  | `https://deny.sh/api`    | Override for staging / private deployments   |

## Threat model

**API-mode tools** (`deny_encrypt`, `deny_decrypt`, `deny_create_decoy`, `deny_vault_*`, `deny_usage`) round-trip plaintext through the deny.sh public API. Use these when you want vault sync across devices or when the agent's host machine is untrusted.

**Local-mode tools** (`deny_local_*`) run the same algorithm entirely on the agent's host machine. No network call, no plaintext leaves the process. Use these when you want offline-only encryption.

In either mode, the cryptographic primitive itself is the same: AES-256-CTR + Argon2id + XOR composition, byte-for-byte compatible across the TypeScript / Python / Go / Rust SDKs. Full wire format: [deny.sh/sdks](https://deny.sh/sdks). Full threat model: [deny.sh/threat-model](https://deny.sh/threat-model). Cryptographic argument: [deny.sh/whitepaper](https://deny.sh/whitepaper) §5.

There is no per-ciphertext cap on the number of decoys an agent can derive via `deny_create_decoy` / `deny_local_create_decoy`. Each fresh call generates a new control file that opens the same ciphertext to a different cover story, up to the inner-payload envelope (ciphertext length minus 48-byte header minus 4-byte length prefix).

## License

**Apache License 2.0**. See [LICENSE](LICENSE).

The MCP server is a thin wrapper around the deny.sh primitive. Apache 2.0 because the primitive itself is Apache 2.0. Free for commercial and proprietary use. See [deny.sh/licensing](https://deny.sh/licensing).

## Source

This file mirrors the canonical source in the private deny.sh monorepo. Releases are tagged from there.

## Reporting vulnerabilities

Found a bug in the MCP server or the underlying crypto? Email security@deny.sh (PGP fingerprint and disclosure policy at [deny.sh/disclosure](https://deny.sh/disclosure)). Please give us a reasonable window before public disclosure.
