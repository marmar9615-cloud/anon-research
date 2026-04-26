---
name: anon-research
description: |
  Anonymous web search and page fetching through Tor with per-request circuit
  isolation. Use when the user wants to research a topic without target sites
  identifying them or correlating multiple requests as coming from one source.
  Trigger keywords: "anonymous search", "private research", "tor search",
  "search anonymously", "research without being tracked", "anon fetch",
  "search privately", "untraceable research". Differs from firecrawl,
  WebSearch, and enterprise-search (all traceable) — every request through
  this skill goes over Tor with a fresh circuit, so target sites cannot link
  requests together or back to the user.
allowed-tools:
  - Bash(~/.claude/skills/anon-research/scripts/anon.py *)
  - Bash(/Users/marmar/.claude/skills/anon-research/scripts/anon.py *)
  - Bash(python3 ~/.claude/skills/anon-research/scripts/anon.py *)
---

# anon-research

Anonymous internet research through Tor. Every search and every page fetch
uses a **fresh Tor circuit** (different exit IP), so target sites can't link
your requests to each other or to you.

## When to use

Invoke this skill when the user wants to:
- Research a topic without target sites profiling them
- Look something up where the search itself is sensitive
- Pull content from multiple sites without those sites correlating the
  requests as coming from one source

Do **not** use this skill when:
- The user wants speed or rich JS-rendered content (use `firecrawl` instead)
- The user is logging in to something (anonymity is meaningless once you
  authenticate)
- The user asked for a specific search engine that blocks Tor (e.g., Google) —
  fetches will return `BLOCKED`

## Quick start

```bash
# One-time setup (installs Tor if missing, starts the daemon):
~/.claude/skills/anon-research/scripts/anon.py setup

# Verify circuit isolation works (shows two different exit IPs):
~/.claude/skills/anon-research/scripts/anon.py status

# Search the web:
~/.claude/skills/anon-research/scripts/anon.py search "site:nature.com mrna vaccine"

# Fetch a specific page as readable markdown:
~/.claude/skills/anon-research/scripts/anon.py fetch https://example.org/article
```

## Commands

| Command | What it does |
|---|---|
| `setup` | Detects platform; installs Tor (Homebrew on macOS, prints package-manager hint on Linux, link otherwise); starts the daemon. Idempotent. |
| `status` | Confirms Tor is running and proves stream isolation by showing two different exit IPs from two consecutive requests. |
| `search QUERY [--limit N] [--json]` | Searches DuckDuckGo HTML through Tor. Returns markdown list of `{title, url, snippet}` (or JSON with `--json`). |
| `fetch URL [--format markdown\|text\|html]` | GETs URL through Tor with a fresh circuit. Default output is readable markdown. |

## Privacy model

Every request:
- Goes through Tor SOCKS5 (`socks5h://127.0.0.1:9050`) with a **unique random
  SOCKS auth pair**, which forces Tor to build a fresh circuit (different
  guard, middle, and exit relays). Sites cannot link requests by IP.
- Sends DNS through Tor (`socks5h`, not `socks5`) — no DNS leaks to your ISP's
  resolver.
- Uses HTTPS only by default; HTTP URLs print a warning.
- Carries no cookies (no session jar between calls), no `Referer`, and a
  generic Firefox-on-Linux User-Agent (a common, low-fingerprint choice — *not*
  the Tor Browser UA, which without the matching JS fingerprint is its own
  tell).

## Fail-closed behavior

If a site blocks Tor exits (Cloudflare challenge, HTTP 403/429/451, common
captcha bodies), `fetch` returns `BLOCKED:` with the reason and exits 2. It
never silently retries over clearnet. This is by design — silent fallback
would deanonymize you without warning.

If a fetch is blocked and the user really wants the content, they can either
(a) try a different source, (b) use the regular `firecrawl` skill explicitly
(accepting the privacy tradeoff), or (c) wait and retry — Tor exit IPs rotate
and another circuit may work.

## Limitations

- **No JavaScript** — `curl`-based; SPAs and JS-heavy sites won't render.
  For JS, the user has to use `firecrawl` (not anonymous).
- **Many sites block Tor** — Cloudflare, Google, news paywalls, etc. Returns
  `BLOCKED`. Try alternative sources.
- **Don't authenticate** — logging into anything from this skill destroys the
  anonymity property. Don't do it.
- **Slower than direct HTTP** — Tor circuit setup adds 5–15s per request, and
  every request here builds a new circuit (the privacy/speed tradeoff).
- **ISP visibility** — your ISP can see you're using Tor (not what you're
  doing). Mitigation (Tor bridges) is out of scope for v1.

## How it works (one line)

`curl --proxy socks5h://$(openssl rand -hex 8):x@127.0.0.1:9050 ...` — the
random SOCKS user triggers Tor's `IsolateSOCKSAuth` and gives every request
its own circuit.

## See also

- `firecrawl-search` / `firecrawl-scrape` — fast, JS-capable, but traceable
- `WebSearch` — built-in, fast, but goes through Anthropic
- `enterprise-search` — for *internal* knowledge bases, not the open web
