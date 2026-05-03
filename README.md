# mirage-proxy

**Your LLM agent sees fake secrets. Your real ones never leave your machine.**

```
You:    AKIAQX4BIPW3AHOV29GN       →  Agent sees:  AKIADKRY5CJQX4BIPW3A
You:    lee.taylor56789@aol.com     →  Agent sees:  chris.hall456@gmail.com
You:    ghp_abc123secrettoken       →  Agent sees:  ghp_xyz789differentkey
```

Single binary. Sub-millisecond. Runs alongside [Pi coding agent](https://github.com/mariozechner/pi-coding-agent) or any OpenAI-compatible client.

---

## Why

Coding agents send your entire working context to cloud APIs — open files, git history, env vars, shell output. If a secret is anywhere in that context, it transits upstream.

Mirage sits between your tool and the provider. It replaces sensitive data with **plausible fakes** before the request leaves your machine, then rehydrates the originals in the response. The model processes fake data and never knows. Your real secrets stay local.

Other tools use visible tokens like `[REDACTED]` or `[[PERSON_1]]`. The model knows data was removed and adapts — refusing to help, asking for the missing values, generating broken code. Mirage's fakes are invisible. The model behaves normally because the request looks normal.

---

## How it works

```
Your tool → mirage-proxy (detect → replace with fakes) → Provider API
Provider API → mirage-proxy (detect fakes → restore originals) → Your tool
```

One binary. Run as a local HTTP proxy. Configure your LLM tool to point at it.

---

## Install

### From source (cargo)

```bash
cargo install --git https://github.com/omdv/mirage-proxy
```

### Nix flake

```nix
# flake.nix
inputs.mirage-proxy.url = "github:omdv/mirage-proxy";
```

Or with `fetchFromGitHub` using a version tag:
```nix
src = fetchFromGitHub {
  owner = "omdv";
  repo = "mirage-proxy";
  rev = "v0.1.0";
  sha256 = "sha256-...";
};
```

---

## Quick Start

1. **Start the proxy:**

   ```bash
   mirage-proxy
   ```

   Listens on `http://127.0.0.1:8686`. Use `--port` and `--bind` to customize.

2. **Configure your LLM tool** to use mirage as a proxy. For Pi coding agent, edit `~/.pi/agent/models.json`:

   ```json
   {
     "providers": {
       "anthropic": { "baseUrl": "http://127.0.0.1:8686/anthropic" },
       "openai":    { "baseUrl": "http://127.0.0.1:8686/openai" },
       "openrouter":{"baseUrl": "http://127.0.0.1:8686/openrouter" },
       "zai":       { "baseUrl": "http://127.0.0.1:8686/zai" }
     }
   }
   ```

3. **Verify it's working:** watch the terminal where mirage runs — redactions print in real time.

---

## Built-in Providers

Mirage auto-routes requests based on URL path. No per-provider configuration needed — just prefix the path:

| Provider       | Path             | Upstream                              |
|----------------|------------------|---------------------------------------|
| Anthropic      | `/anthropic`     | `https://api.anthropic.com`           |
| OpenAI         | `/openai`        | `https://api.openai.com`             |
| OpenAI Codex   | `/codex`         | `https://chatgpt.com/backend-api/codex` |
| Google AI      | `/google`        | `https://generativelanguage.googleapis.com` |
| Google Vertex  | `/vertex`        | `https://us-central1-aiplatform.googleapis.com` |
| Mistral        | `/mistral`       | `https://api.mistral.ai`             |
| Cohere         | `/cohere`        | `https://api.cohere.com`             |
| Perplexity     | `/perplexity`    | `https://api.perplexity.ai`          |
| DeepSeek       | `/deepseek`      | `https://api.deepseek.com`           |
| Alibaba Qwen   | `/alibaba`       | `https://dashscope.aliyuncs.com`      |
| Zhipu / GLM    | `/zhipu`         | `https://open.bigmodel.cn`           |
| ZAI / GLM      | `/zai`           | `https://api.z.ai/api/coding/paas/v4` |
| Moonshot       | `/moonshot`      | `https://api.moonshot.cn`            |
| Baichuan       | `/baichuan`      | `https://api.baichuan-ai.com`        |
| Yi / 01.AI     | `/yi`            | `https://api.lingyiwanwu.com`        |
| Minimax        | `/minimax`       | `https://api.minimax.chat`           |
| Stepfun        | `/stepfun`      | `https://api.stepfun.com`            |
| SiliconFlow    | `/siliconflow`   | `https://api.siliconflow.cn`         |
| Groq           | `/groq`          | `https://api.groq.com`               |
| Together       | `/together`      | `https://api.together.xyz`           |
| Fireworks      | `/fireworks`     | `https://api.fireworks.ai`           |
| Anyscale       | `/anyscale`      | `https://api.endpoints.anyscale.com`  |
| Replicate      | `/replicate`     | `https://api.replicate.com`          |
| Lepton         | `/lepton`        | `https://api.lepton.ai`              |
| Cerebras       | `/cerebras`      | `https://api.cerebras.ai`            |
| SambaNova      | `/sambanova`     | `https://api.sambanova.ai`           |
| Azure OpenAI   | `/azure`         | `https://YOUR_RESOURCE.openai.azure.com` |
| AWS Bedrock    | `/bedrock`      | `https://bedrock-runtime.us-east-1.amazonaws.com` |
| OpenRouter     | `/openrouter`    | `https://openrouter.ai/api`           |
| xAI / Grok     | `/xai`           | `https://api.x.ai`                   |

List all providers: `mirage-proxy --list-providers`

---

## What it catches

### Secrets & credentials

| Type | Detection method |
|---|---|
| AWS keys (`AKIA...`) | Prefix match |
| GitHub tokens (`ghp_`, `ghs_`, `github_pat_`) | Prefix match |
| OpenAI keys (`sk-proj-...`) | Prefix match |
| Google API keys (`AIzaSy...`) | Prefix match |
| GitLab, Slack, Stripe, 50+ others | 129 patterns from Gitleaks + secrets-patterns-db |
| Bearer tokens | Header pattern |
| Private keys (`-----BEGIN RSA...`) | Structural |
| Connection strings (`postgres://user:pass@host`) | URI + credentials |
| Unknown high-entropy strings | Shannon entropy threshold |

### Personal data

| Type | Original → Fake |
|---|---|
| Email | `lee.taylor@aol.com` → `chris.hall@gmail.com` |
| Phone | `+1-501-369-6183` → `+1-464-316-6112` |
| SSN | `927-83-6041` → `890-30-5970` |
| Credit card | `4890 1234 5678 9012` → `4789 0123 4567 8901` |
| IP address | `10.0.1.42` → `172.18.3.97` |

Every fake matches the **format and length** of the original. An AWS key becomes a different valid-format AWS key. A credit card keeps its issuer prefix and passes Luhn. Within a session, the same value always maps to the same fake (session consistency).

---

## Configuration

Zero config needed. For fine-tuning, create `~/.config/mirage/mirage.yaml`:

```yaml
sensitivity: medium   # low | medium | high | paranoid

bypass:
  - "generativelanguage.googleapis.com"  # skip Google (TLS fingerprint issues)

rules:
  always_redact: [SSN, CREDIT_CARD, PRIVATE_KEY, AWS_KEY, GITHUB_TOKEN]
  mask: [EMAIL, PHONE]
  warn_only: [IP_ADDRESS]

audit:
  enabled: true
  path: "./mirage-audit.jsonl"
  log_values: false

vault:
  path: "./mirage-vault.enc"   # encrypted fake↔original mappings

update_check:
  enabled: true
  timeout_ms: 1200
```

| Sensitivity | What gets filtered |
|---|---|
| `low` | Secrets & credentials only |
| `medium` | Secrets + PII (email, phone) — **default** |
| `high` | Everything including warn-only |
| `paranoid` | All detected patterns |

---

## CLI Reference

```
mirage-proxy [OPTIONS]

  -p, --port <PORT>           Listen port [default: 8686]
  -b, --bind <ADDR>           Bind address [default: 127.0.0.1]
  -c, --config <PATH>         Config file path
      --sensitivity <LEVEL>   low | medium | high | paranoid
      --dry-run               Log detections without modifying traffic
      --vault-key <PHRASE>    Vault passphrase (or MIRAGE_VAULT_KEY env)
      --vault-path <PATH>     Vault file path
      --vault-flush-threshold <N>  Flush after N mappings [default: 50]
      --list-providers        Show all built-in provider routes
      --no-update-check       Skip version check on startup
      --log-level <LEVEL>     trace | debug | info | warn | error [default: info]
  -h, --help
  -V, --version
```

### Subcommands

```
mirage-proxy audit            Interactive TUI viewer for the audit log
  -p, --path <PATH>           Audit log file path
  -c, --config <PATH>         Config file (to load default audit path)

mirage-proxy vault            Interactive TUI viewer for vault mappings
      --vault-key <PHRASE>    Vault passphrase (or MIRAGE_VAULT_KEY env)
      --vault-path <PATH>     Vault file path
  -c, --config <PATH>         Config file (to load default vault path)
```

### Health check

```
curl http://127.0.0.1:8686/healthz
```

Returns JSON with request count, redaction count, and session count.

---

## Trust & privacy

- **No telemetry.** No external reporting pipeline. No analytics.
- **Local only.** Mirage proxies only to your configured upstream provider endpoints.
- **Auditable.** Audit logging writes to a local file. `log_values: false` by default.
- **Dry-run mode.** Log what would be filtered without modifying traffic: `mirage-proxy --dry-run`
- **Encrypted vault.** Persist fake↔original mappings across restarts with AES-256-GCM + Argon2id key derivation: `MIRAGE_VAULT_KEY="passphrase" mirage-proxy`

---

## Known limitations

- **Regex + entropy only** — no NLP/NER. Won't catch secrets described in natural language ("my API key is abc123").
- **Streaming edge case** — 128-byte boundary buffer handles most splits, but a fake value landing exactly at a chunk boundary can slip through.
- **Signed thinking blocks** — Anthropic validates signatures on extended thinking payloads. Mirage intentionally skips modifying these.
- **Google TLS fingerprinting** — Google's APIs can detect Mirage's `reqwest`/`rustls` fingerprint. Use `bypass: ["generativelanguage.googleapis.com"]` in config.

---

## License

MIT

Forked from [@chandika/mirage-proxy](https://github.com/chandika/mirage-proxy). Detection patterns from [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0).