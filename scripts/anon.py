#!/usr/bin/env python3
"""
anon-research — anonymous web search + page fetching through Tor.

Every request uses a fresh random SOCKS5 auth pair, which (because of Tor's
default IsolateSOCKSAuth) forces a new circuit per request. So target sites
see unrelated traffic from unrelated exit IPs even within one session.

Subcommands:
  setup    Detect platform; install Tor if missing; start the daemon.
  status   Confirm Tor is working and prove circuit isolation (two IPs).
  search   DuckDuckGo HTML search through Tor.
  fetch    Fetch a URL through Tor; fail-closed on Tor blocks (no clearnet
           fallback, ever).

Stdlib only. Shells out to `curl` for HTTP (no pip-installable deps needed).
"""

from __future__ import annotations

import argparse
import html as htmllib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 9051
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)
CURL_TIMEOUT = 60   # Tor circuit setup can take 10-15s; total budget per request

# Control-port cookie path written by the enable-control-port subcommand.
# Tor will create this file when the daemon starts with CookieAuthFile set.
CONTROL_COOKIE_PATHS = [
    "/opt/homebrew/var/lib/tor/control_auth_cookie",   # Apple-silicon brew
    "/usr/local/var/lib/tor/control_auth_cookie",      # Intel macOS brew
    "/var/lib/tor/control_auth_cookie",                # Linux system tor
]

# torrc paths we know about. Used by enable-control-port.
TORRC_PATHS = [
    "/opt/homebrew/etc/tor/torrc",
    "/usr/local/etc/tor/torrc",
    "/etc/tor/torrc",
]

# DuckDuckGo: prefer the onion (search traffic stays inside Tor — no exit relay
# sees the query); fall back to the clearnet HTML mirror over Tor if the onion
# is unreachable. Both routes are full-Tor; no privacy regression on fallback.
DDG_ONION = (
    "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/"
)
DDG_CLEARNET = "https://html.duckduckgo.com/html/"


# ---------------------------------------------------------------- helpers ----

def _fresh_socks_auth() -> str:
    """Random SOCKS auth → unique Tor circuit (IsolateSOCKSAuth default on)."""
    return f"{secrets.token_hex(8)}:x"


def _socks_port_open(host: str = SOCKS_HOST, port: int = SOCKS_PORT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _ensure_tor_or_die() -> None:
    if not _socks_port_open():
        print(
            "ERROR: Tor SOCKS port not reachable on "
            f"{SOCKS_HOST}:{SOCKS_PORT}.\n"
            "  Run: ~/.claude/skills/anon-research/scripts/anon.py setup",
            file=sys.stderr,
        )
        sys.exit(1)


def _curl(
    url: str,
    *,
    method: str = "GET",
    data: str | None = None,
    max_size: int = 5_000_000,
    timeout: int = CURL_TIMEOUT,
) -> tuple[int, dict, bytes]:
    """HTTPS through Tor with a fresh circuit. Returns (status, headers, body)."""
    if url.startswith("http://"):
        print(f"WARNING: plaintext HTTP URL: {url}", file=sys.stderr)
    elif not url.startswith("https://"):
        raise ValueError(f"Refusing non-http(s) URL: {url}")

    auth = _fresh_socks_auth()
    proxy = f"socks5h://{auth}@{SOCKS_HOST}:{SOCKS_PORT}"

    body_fd, body_path = tempfile.mkstemp(prefix="anon-body-")
    hdr_fd, hdr_path = tempfile.mkstemp(prefix="anon-hdr-")
    os.close(body_fd)
    os.close(hdr_fd)

    try:
        cmd = [
            "curl",
            "--silent", "--show-error",
            "--max-time", str(timeout),
            "--max-filesize", str(max_size),
            "--proxy", proxy,
            "--user-agent", USER_AGENT,
            "--header", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "--header", "Accept-Language: en-US,en;q=0.5",
            "--location", "--max-redirs", "5",
            "--output", body_path,
            "--dump-header", hdr_path,
            "--write-out", "%{http_code}",
        ]
        if method == "POST":
            cmd += ["--data", data or ""]
        cmd.append(url)

        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", "replace").strip() or "(no stderr)"
            raise RuntimeError(f"curl failed (exit {result.returncode}): {err}")

        try:
            status = int(result.stdout.decode().strip() or "0")
        except ValueError:
            status = 0

        with open(body_path, "rb") as f:
            body = f.read()
        with open(hdr_path, "r", encoding="utf-8", errors="replace") as f:
            hdr_text = f.read()

        # With --location, curl writes one block of headers per response.
        # Take the last non-empty block.
        blocks = [b for b in hdr_text.split("\r\n\r\n") if b.strip()]
        last = blocks[-1] if blocks else ""
        headers: dict[str, str] = {}
        for line in last.split("\r\n")[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return status, headers, body
    finally:
        for path in (body_path, hdr_path):
            try:
                os.unlink(path)
            except OSError:
                pass


# ----------------------------------------------------- control-port (Tor) ---
#
# These helpers talk to Tor's control protocol so we can do things SOCKS5
# can't — most importantly, constrain a circuit to a specific exit country
# via SETCONF ExitNodes={cc}. The control port is opt-in: it's only enabled
# after the user runs `enable-control-port` once, which writes a torrc and
# restarts the daemon.

def _control_port_open() -> bool:
    try:
        with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=2):
            return True
    except OSError:
        return False


def _find_control_cookie() -> str | None:
    for path in CONTROL_COOKIE_PATHS:
        if os.path.exists(path) and os.access(path, os.R_OK):
            return path
    return None


class _TorControl:
    """Minimal Tor control-port client. Cookie-auth only.

    Use as a context manager — `with _TorControl() as c: c.setconf(...)`.
    Wraps a stdlib socket. No dependencies.
    """

    def __init__(self):
        self.sock: socket.socket | None = None

    def __enter__(self) -> "_TorControl":
        cookie_path = _find_control_cookie()
        if not cookie_path:
            raise RuntimeError(
                "No Tor control_auth_cookie found. Run "
                "`scripts/anon.py enable-control-port` to set it up."
            )
        with open(cookie_path, "rb") as f:
            cookie = f.read()
        s = socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=10)
        s.settimeout(10)
        s.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n")
        resp = self._recv_line(s)
        if not resp.startswith("250"):
            s.close()
            raise RuntimeError(f"Tor control auth failed: {resp.strip()!r}")
        self.sock = s
        return self

    def __exit__(self, *args):
        if self.sock:
            try:
                self.sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def _recv_line(self, s: socket.socket | None = None) -> str:
        s = s or self.sock
        assert s is not None
        buf = bytearray()
        while True:
            ch = s.recv(1)
            if not ch:
                break
            buf.extend(ch)
            if buf.endswith(b"\r\n"):
                break
        return buf.decode("utf-8", "replace")

    def _command(self, cmd: str) -> str:
        assert self.sock is not None
        self.sock.sendall((cmd + "\r\n").encode())
        resp = self._recv_line()
        if not resp.startswith("250"):
            raise RuntimeError(f"Tor control command failed: {cmd!r} -> {resp.strip()!r}")
        return resp

    def setconf(self, key: str, value: str) -> None:
        self._command(f"SETCONF {key}={value}")

    def resetconf(self, key: str) -> None:
        self._command(f"RESETCONF {key}")

    def signal(self, sig: str) -> None:
        self._command(f"SIGNAL {sig}")


def _validate_country_code(cc: str) -> str:
    cc = cc.strip().lower()
    if not re.match(r"^[a-z]{2}$", cc):
        raise ValueError(
            f"Invalid country code {cc!r}: expected a 2-letter ISO code "
            "like 'us', 'gb', 'de', 'ca'."
        )
    return cc


class _exit_country:
    """Context manager: pin Tor's exit-node selection to one country, then
    reset on exit. Requires the control port to be configured.

    No-op when `country` is None (so callers can wrap unconditionally).
    """

    def __init__(self, country: str | None):
        self.country = country
        self.ctrl: _TorControl | None = None

    def __enter__(self):
        if not self.country:
            return self
        if not _control_port_open():
            raise RuntimeError(
                "--exit-country requires Tor's control port. Run "
                "`scripts/anon.py enable-control-port` once to set it up."
            )
        cc = _validate_country_code(self.country)
        self.ctrl = _TorControl().__enter__()
        try:
            self.ctrl.setconf("ExitNodes", "{" + cc + "}")
            # StrictNodes makes Tor refuse to fall back to other countries
            # if the requested pool is empty — fail-closed instead of leaking
            # to a different geo than the user asked for.
            self.ctrl.setconf("StrictNodes", "1")
            # NEWNYM forces *new* circuits to be built that obey the new
            # ExitNodes setting; existing cached circuits are abandoned.
            self.ctrl.signal("NEWNYM")
        except Exception:
            self.ctrl.__exit__(None, None, None)
            self.ctrl = None
            raise
        return self

    def __exit__(self, *args):
        if self.ctrl is not None:
            for key in ("ExitNodes", "StrictNodes"):
                try:
                    self.ctrl.resetconf(key)
                except Exception:
                    pass
            self.ctrl.__exit__(*args)
            self.ctrl = None


# -------------------------------------------------------- block detection ---

_CLOUDFLARE_MARKERS = (
    b"Just a moment",
    b"Checking your browser before accessing",
    b"cf-browser-verification",
    b"__cf_chl_",
    b"Attention Required! | Cloudflare",
    b"challenge-platform",
)

_GENERIC_BLOCK_MARKERS = (
    b"Access Denied",
    b"You don't have permission to access",
    b"unusual traffic from your computer",
    b"detected unusual activity",
    b"Sorry, you have been blocked",
    b"Please verify you are a human",
)


def _detect_block(status: int, headers: dict, body: bytes) -> str | None:
    """Return a short reason string if blocked, else None."""
    if status in (401, 403, 429, 451):
        return f"HTTP {status}"
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        if any(m in body for m in _CLOUDFLARE_MARKERS):
            return "Cloudflare challenge"
        if status == 503:
            return "Cloudflare 503"
    if status == 503 and any(m in body for m in _CLOUDFLARE_MARKERS):
        return "Cloudflare challenge"
    if any(m in body[:20_000] for m in _CLOUDFLARE_MARKERS):
        return "Cloudflare challenge"
    if 200 <= status < 300:
        for m in _GENERIC_BLOCK_MARKERS:
            if m in body[:20_000]:
                return f"Body marker: {m.decode('utf-8', 'replace')}"
    return None


# --------------------------------------------------------- DDG result parse --

_DDG_BLOCK_SPLIT = re.compile(
    r'<div[^>]*class="[^"]*\bresult\b[^"]*results_links[^"]*"',
    re.IGNORECASE,
)
_DDG_TITLE = re.compile(
    r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)
_DDG_SNIPPET = re.compile(
    r'class="result__snippet"[^>]*>(.*?)</(?:a|div)>',
    re.DOTALL | re.IGNORECASE,
)
_TAG = re.compile(r"<[^>]+>")


def _ddg_unwrap(url: str) -> str:
    """DDG wraps result links as //duckduckgo.com/l/?uddg=... — extract real URL."""
    if url.startswith("//"):
        url = "https:" + url
    if "duckduckgo.com/l/" in url and "uddg=" in url:
        try:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            if "uddg" in params:
                return urllib.parse.unquote(params["uddg"][0])
        except Exception:
            pass
    return url


def _parse_ddg(body_text: str) -> list[dict]:
    """Return list of {title, url, snippet} from DDG HTML response."""
    out = []
    parts = _DDG_BLOCK_SPLIT.split(body_text)
    for block in parts[1:]:
        m_t = _DDG_TITLE.search(block)
        if not m_t:
            continue
        url = htmllib.unescape(m_t.group(1))
        title = htmllib.unescape(_TAG.sub("", m_t.group(2)).strip())
        snippet = ""
        m_s = _DDG_SNIPPET.search(block)
        if m_s:
            snippet = htmllib.unescape(_TAG.sub("", m_s.group(1)).strip())
            snippet = re.sub(r"\s+", " ", snippet)
        if title and url:
            out.append({"title": title, "url": _ddg_unwrap(url), "snippet": snippet})
    return out


# -------------------------------------------------- HTML → text/markdown ----

def _strip_to_text(html_text: str) -> str:
    s = re.sub(r"<!--.*?-->", "", html_text, flags=re.DOTALL)
    s = re.sub(r"<head[^>]*>.*?</head>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<script[^>]*>.*?</script>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<style[^>]*>.*?</style>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<nav[^>]*>.*?</nav>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<footer[^>]*>.*?</footer>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<(br|/p|/div|/h\d|/li)[^>]*>", "\n", s, flags=re.IGNORECASE)
    s = _TAG.sub("", s)
    s = htmllib.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n\n", s)
    return s.strip() + "\n"


def _to_markdown(html_text: str) -> str:
    s = html_text
    s = re.sub(r"<!--.*?-->", "", s, flags=re.DOTALL)
    s = re.sub(r"<head[^>]*>.*?</head>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<script[^>]*>.*?</script>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<style[^>]*>.*?</style>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<nav[^>]*>.*?</nav>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<footer[^>]*>.*?</footer>", "", s, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r"<aside[^>]*>.*?</aside>", "", s, flags=re.DOTALL | re.IGNORECASE)

    for n in range(1, 7):
        s = re.sub(
            rf"<h{n}[^>]*>(.*?)</h{n}>",
            lambda m, n=n: f"\n\n{'#' * n} {_TAG.sub('', m.group(1)).strip()}\n\n",
            s,
            flags=re.DOTALL | re.IGNORECASE,
        )
    s = re.sub(
        r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        lambda m: f"[{_TAG.sub('', m.group(2)).strip()}]({m.group(1)})",
        s,
        flags=re.DOTALL | re.IGNORECASE,
    )
    s = re.sub(
        r"<(strong|b)[^>]*>(.*?)</\1>",
        lambda m: f"**{m.group(2)}**",
        s,
        flags=re.DOTALL | re.IGNORECASE,
    )
    s = re.sub(
        r"<(em|i)[^>]*>(.*?)</\1>",
        lambda m: f"*{m.group(2)}*",
        s,
        flags=re.DOTALL | re.IGNORECASE,
    )
    s = re.sub(
        r"<li[^>]*>(.*?)</li>",
        lambda m: f"- {_TAG.sub('', m.group(1)).strip()}\n",
        s,
        flags=re.DOTALL | re.IGNORECASE,
    )
    s = re.sub(r"<br[^>]*>", "\n", s, flags=re.IGNORECASE)
    s = re.sub(r"</p>", "\n\n", s, flags=re.IGNORECASE)
    s = _TAG.sub("", s)
    s = htmllib.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n\s*\n\s*\n+", "\n\n", s)
    return s.strip() + "\n"


# ----------------------------------------------------------------- setup ----

def _platform() -> str:
    try:
        return subprocess.check_output(["uname", "-s"]).decode().strip()
    except Exception:
        return ""


def _linux_install_hint(os_release_text: str | None = None) -> str:
    """Return the right `apt`/`dnf`/`pacman`/`apk` command for this distro.

    Reads /etc/os-release by default; pass `os_release_text` to inject content
    for testing.
    """
    if os_release_text is None:
        os_release_text = ""
        try:
            with open("/etc/os-release") as f:
                os_release_text = f.read()
        except OSError:
            pass
    low = os_release_text.lower()
    if "id=fedora" in low or "id_like=fedora" in low or "rhel" in low:
        return "sudo dnf install -y tor"
    if "id=arch" in low or "id_like=arch" in low:
        return "sudo pacman -S --noconfirm tor"
    if "alpine" in low:
        return "sudo apk add tor"
    return "sudo apt-get update && sudo apt-get install -y tor"


def cmd_setup(args) -> int:
    print("==> Checking for tor binary…", flush=True)
    tor_path = shutil.which("tor")
    if tor_path:
        print(f"    found: {tor_path}")
    else:
        sys_name = _platform()
        print(f"    not found. Platform: {sys_name or 'unknown'}")
        if sys_name == "Darwin":
            if shutil.which("brew"):
                print("==> Installing Tor via Homebrew (this can take a minute)…",
                      flush=True)
                r = subprocess.run(["brew", "install", "tor"])
                if r.returncode != 0:
                    print("ERROR: 'brew install tor' failed.", file=sys.stderr)
                    return 1
            else:
                print(
                    "ERROR: Homebrew not installed.\n"
                    "  Install Homebrew first: https://brew.sh\n"
                    "  Then re-run this setup.\n"
                    "  (Or install Tor manually: https://www.torproject.org/download/)",
                    file=sys.stderr,
                )
                return 1
        elif sys_name == "Linux":
            print(
                "ERROR: Tor not installed. Run:\n"
                f"  {_linux_install_hint()}\n"
                "Then start it (e.g. `sudo systemctl start tor`) and re-run setup.",
                file=sys.stderr,
            )
            return 1
        else:
            print(
                f"ERROR: Unsupported platform '{sys_name or 'unknown'}'.\n"
                "  Install Tor manually: https://www.torproject.org/download/",
                file=sys.stderr,
            )
            return 1

    print("==> Checking SOCKS port 9050…", flush=True)
    if _socks_port_open():
        print("    open.")
    else:
        print("    not open. Starting Tor daemon…")
        sys_name = _platform()
        if sys_name == "Darwin" and shutil.which("brew"):
            r = subprocess.run(["brew", "services", "start", "tor"])
            if r.returncode != 0:
                print("ERROR: 'brew services start tor' failed.", file=sys.stderr)
                return 1
        elif sys_name == "Linux":
            print(
                "ERROR: Start Tor manually:\n"
                "  sudo systemctl start tor\n"
                "  (or: tor &  for a foreground process)",
                file=sys.stderr,
            )
            return 1
        else:
            print("ERROR: Don't know how to start Tor on this platform.",
                  file=sys.stderr)
            return 1

        for _ in range(20):
            if _socks_port_open():
                break
            time.sleep(1)
        if not _socks_port_open():
            print(
                f"ERROR: Tor SOCKS port still not reachable on "
                f"{SOCKS_HOST}:{SOCKS_PORT} after 20s.",
                file=sys.stderr,
            )
            return 1

    print("==> Verifying Tor connectivity…", flush=True)
    try:
        status, headers, body = _curl(
            "https://check.torproject.org/api/ip", timeout=45,
        )
        info = json.loads(body)
        if info.get("IsTor"):
            print(f"    OK. Tor ready on {SOCKS_HOST}:{SOCKS_PORT} "
                  f"(exit IP: {info.get('IP')})")
            return 0
        print(f"ERROR: connected but not via Tor: {info}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: could not verify Tor: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------- enable-control-port (opt-in) -

_TORRC_BLOCK_MARKER = "# Added by anon-research enable-control-port"

_TORRC_BLOCK = """
{marker}
ControlPort {port}
CookieAuthentication 1
CookieAuthFile {cookie}
CookieAuthFileGroupReadable 1
"""


def _find_or_choose_torrc() -> str | None:
    """Return existing torrc path, else the path we'd create on this platform."""
    for p in TORRC_PATHS:
        if os.path.exists(p):
            return p
    sys_name = _platform()
    if sys_name == "Darwin":
        # Apple Silicon brew vs. Intel brew
        if os.path.exists("/opt/homebrew"):
            return "/opt/homebrew/etc/tor/torrc"
        if os.path.exists("/usr/local/Homebrew") or os.path.exists("/usr/local/opt"):
            return "/usr/local/etc/tor/torrc"
    elif sys_name == "Linux":
        return "/etc/tor/torrc"
    return None


def _cookie_path_for_torrc(torrc_path: str) -> str:
    """Pick a CookieAuthFile path that matches where Tor stores its data."""
    if torrc_path.startswith("/opt/homebrew/"):
        return "/opt/homebrew/var/lib/tor/control_auth_cookie"
    if torrc_path.startswith("/usr/local/"):
        return "/usr/local/var/lib/tor/control_auth_cookie"
    return "/var/lib/tor/control_auth_cookie"


def cmd_enable_control_port(args) -> int:
    """Idempotent: enable Tor's ControlPort + CookieAuthentication and restart Tor.

    Required once before --exit-country can be used. Modifies the system's
    torrc — that's why this is opt-in instead of being part of `setup`.
    """
    torrc = _find_or_choose_torrc()
    if torrc is None:
        print(
            "ERROR: Could not find a torrc location for this platform.\n"
            "Edit your torrc by hand to add:\n"
            "  ControlPort 9051\n"
            "  CookieAuthentication 1\n"
            "  CookieAuthFile /var/lib/tor/control_auth_cookie\n"
            "  CookieAuthFileGroupReadable 1\n"
            "Then restart Tor.",
            file=sys.stderr,
        )
        return 1

    print(f"==> Using torrc: {torrc}", flush=True)
    existing = ""
    if os.path.exists(torrc):
        try:
            with open(torrc) as f:
                existing = f.read()
        except OSError as e:
            print(f"ERROR: cannot read {torrc}: {e}", file=sys.stderr)
            return 1

    if "ControlPort" in existing and _TORRC_BLOCK_MARKER not in existing:
        print(
            f"ERROR: {torrc} already has a ControlPort directive that anon-research "
            "didn't write. Refusing to touch it. Inspect your torrc by hand.",
            file=sys.stderr,
        )
        return 1

    if _TORRC_BLOCK_MARKER in existing:
        print("    torrc already has the anon-research block — no changes needed.")
    else:
        cookie = _cookie_path_for_torrc(torrc)
        block = _TORRC_BLOCK.format(
            marker=_TORRC_BLOCK_MARKER,
            port=CONTROL_PORT,
            cookie=cookie,
        )
        # Make sure parent dirs exist
        os.makedirs(os.path.dirname(torrc), exist_ok=True)
        os.makedirs(os.path.dirname(cookie), exist_ok=True)
        sep = "" if existing.endswith("\n") or not existing else "\n"
        try:
            with open(torrc, "a") as f:
                f.write(sep + block)
        except PermissionError:
            print(
                f"ERROR: permission denied writing {torrc}. On Linux you may "
                f"need to run this command with sudo, or edit torrc by hand.",
                file=sys.stderr,
            )
            return 1
        print(f"    appended ControlPort + CookieAuthentication block to {torrc}")

    # Restart Tor so the new torrc takes effect
    print("==> Restarting Tor…", flush=True)
    sys_name = _platform()
    if sys_name == "Darwin" and shutil.which("brew"):
        r = subprocess.run(["brew", "services", "restart", "tor"])
        if r.returncode != 0:
            print("ERROR: 'brew services restart tor' failed.", file=sys.stderr)
            return 1
    elif sys_name == "Linux":
        print(
            "Restart Tor manually:\n"
            "  sudo systemctl restart tor\n"
            "Then re-run this command to verify.",
            file=sys.stderr,
        )
        return 1
    else:
        print(
            "Don't know how to restart Tor on this platform — restart it "
            "yourself, then re-run.",
            file=sys.stderr,
        )
        return 1

    print("==> Waiting for control port…", flush=True)
    for _ in range(30):
        if _control_port_open() and _find_control_cookie():
            break
        time.sleep(1)
    if not _control_port_open():
        print(
            f"ERROR: control port {CONTROL_PORT} still not reachable after 30s.",
            file=sys.stderr,
        )
        return 1
    if not _find_control_cookie():
        print(
            "ERROR: control port is open but cookie file isn't where we expect.\n"
            f"Looked in: {', '.join(CONTROL_COOKIE_PATHS)}",
            file=sys.stderr,
        )
        return 1

    # Probe with an actual auth round-trip.
    try:
        with _TorControl():
            pass
        print("    OK. Control port authenticated. --exit-country is now usable.")
        return 0
    except Exception as e:
        print(f"ERROR: control-port authentication failed: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------- status ----

def cmd_status(args) -> int:
    if not _socks_port_open():
        print(
            f"Tor SOCKS port {SOCKS_PORT} not open. Run: anon.py setup",
            file=sys.stderr,
        )
        return 1

    print("Two requests with different SOCKS auth (→ different circuits):")
    seen = []
    for i in (1, 2):
        try:
            status, headers, body = _curl(
                "https://check.torproject.org/api/ip", timeout=45,
            )
            info = json.loads(body)
            ip = info.get("IP", "?")
            is_tor = bool(info.get("IsTor"))
            print(f"  request {i}: IP={ip}  IsTor={is_tor}")
            seen.append((ip, is_tor))
        except Exception as e:
            print(f"  request {i}: ERROR: {e}", file=sys.stderr)
            return 1

    if not all(t for _, t in seen):
        print("FAIL: at least one request did not go through Tor.",
              file=sys.stderr)
        return 1
    if seen[0][0] == seen[1][0]:
        print(
            "WARN: both requests had the same exit IP. Stream isolation "
            "may not be working — re-run; if persistent, check torrc for "
            "IsolateSOCKSAuth (default is on).",
            file=sys.stderr,
        )
        return 2
    print("OK: Tor working with per-request circuit isolation.")
    return 0


# ---------------------------------------------------------------- search ----

def _ddg_search(query: str) -> tuple[list[dict], list[str]]:
    """Run a DuckDuckGo HTML search through Tor.

    Tries the .onion service first (search traffic stays inside the Tor
    network — no exit relay sees the query), then falls back to the clearnet
    HTML mirror over Tor on connection errors, blocks, or empty/garbled
    responses. Both routes go through Tor, so falling back to clearnet does
    NOT leak your IP — only switches which path inside Tor is used.

    Returns (results, errors). On success errors is []; on full failure
    results is [] and errors lists what went wrong with each route.
    """
    data = urllib.parse.urlencode({"q": query, "kl": "us-en"})
    errors: list[str] = []
    for label, url in (("onion", DDG_ONION), ("clearnet", DDG_CLEARNET)):
        try:
            status, headers, body = _curl(url, method="POST", data=data)
        except Exception as e:
            errors.append(f"{label}: {e}")
            continue

        block = _detect_block(status, headers, body)
        if block:
            errors.append(f"{label}: blocked ({block})")
            continue
        if status >= 400 or not body:
            errors.append(f"{label}: HTTP {status}, body {len(body)} bytes")
            continue

        text = body.decode("utf-8", "replace")
        results = _parse_ddg(text)
        if results:
            return results, []
        # parsed empty — could be legitimately no-results, or HTML changed
        if "no results" in text.lower():
            return [], []  # no results, but the query worked
        errors.append(f"{label}: no results parsed (HTML may have changed)")

    return [], errors


def _searx_search(query: str) -> list[dict]:
    """Search a SearXNG instance over Tor using its JSON API.

    Reads the instance URL from `ANON_SEARX_URL`. Public SearXNG instances
    aggressively rate-limit Tor exits in 2026, so this is **bring-your-own**
    (point at your own SearXNG; either self-hosted or one you have a working
    relationship with).

    Raises RuntimeError on configuration / network / parsing problems.
    """
    base = os.environ.get("ANON_SEARX_URL", "").strip().rstrip("/")
    if not base:
        raise RuntimeError(
            "SearXNG fallback requires ANON_SEARX_URL to point at your own "
            "SearXNG instance — public instances rate-limit Tor traffic in "
            "2026. See README for self-hosting notes."
        )

    qs = urllib.parse.urlencode({
        "q": query,
        "format": "json",
        "categories": "general",
        "language": "en",
    })
    url = f"{base}/search?{qs}"
    status, headers, body = _curl(url)

    block = _detect_block(status, headers, body)
    if block:
        raise RuntimeError(f"SearXNG instance blocked Tor exit ({block})")
    if status >= 400:
        raise RuntimeError(f"SearXNG returned HTTP {status}")
    if not body:
        raise RuntimeError("SearXNG returned empty body")

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"SearXNG response was not JSON ({e}). Does this instance have "
            "format=json enabled?"
        )

    out = []
    for r in data.get("results", []):
        out.append({
            "title": (r.get("title") or "").strip(),
            "url": (r.get("url") or "").strip(),
            "snippet": (r.get("content") or "").strip(),
        })
    return out


def cmd_search(args) -> int:
    _ensure_tor_or_die()

    try:
        with _exit_country(getattr(args, "exit_country", None)):
            if args.engine == "searx":
                try:
                    results = _searx_search(args.query)
                except Exception as e:
                    print(f"ERROR: {e}", file=sys.stderr)
                    return 2
            else:  # default: ddg (with onion → clearnet fallback)
                results, errors = _ddg_search(args.query)
                if errors and not results:
                    print("BLOCKED/ERROR: DuckDuckGo search failed on every route:",
                          file=sys.stderr)
                    for err in errors:
                        print(f"  {err}", file=sys.stderr)
                    print("Re-run to roll new circuits, or try again later "
                          "(or try --engine searx if you have ANON_SEARX_URL set).",
                          file=sys.stderr)
                    return 2
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    results = results[: args.limit]
    if not results:
        print("(no results)")
        return 0

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for i, r in enumerate(results, 1):
            print(f"{i}. {r['title']}")
            print(f"   {r['url']}")
            if r["snippet"]:
                print(f"   {r['snippet']}")
            print()
    return 0


# ----------------------------------------------------------------- fetch ----

def cmd_fetch(args) -> int:
    _ensure_tor_or_die()
    try:
        with _exit_country(getattr(args, "exit_country", None)):
            status, headers, body = _curl(args.url, max_size=10_000_000)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: fetch failed: {e}", file=sys.stderr)
        return 1

    block = _detect_block(status, headers, body)
    if block:
        print(
            f"BLOCKED: {args.url}\n"
            f"  reason: {block}\n"
            f"  HTTP status: {status}\n"
            f"  This skill is fail-closed — never falls back to clearnet.\n"
            f"  Try a different source, or re-run for a new Tor circuit.",
            file=sys.stderr,
        )
        return 2

    if status >= 400:
        print(f"HTTP {status} for {args.url}", file=sys.stderr)
        return 1

    text = body.decode("utf-8", "replace")
    if args.format == "html":
        sys.stdout.write(text)
    elif args.format == "text":
        sys.stdout.write(_strip_to_text(text))
    else:  # markdown
        sys.stdout.write(_to_markdown(text))
    return 0


# ----------------------------------------------------------------- main -----

def main() -> None:
    p = argparse.ArgumentParser(
        prog="anon",
        description="Anonymous web research via Tor (per-request circuit isolation).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="Install/start Tor as needed.")
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser(
        "enable-control-port",
        help="One-time opt-in: enable Tor's control port for --exit-country.",
    )
    s.set_defaults(func=cmd_enable_control_port)

    s = sub.add_parser(
        "status",
        help="Check Tor + show two different exit IPs (proves circuit isolation).",
    )
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("search", help="Search the web through Tor.")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--json", action="store_true")
    s.add_argument(
        "--engine",
        choices=["ddg", "searx"],
        default="ddg",
        help=(
            "Search engine. 'ddg' (default): DuckDuckGo onion → clearnet "
            "fallback. 'searx': your own SearXNG instance via ANON_SEARX_URL."
        ),
    )
    s.add_argument(
        "--exit-country",
        metavar="CC",
        help=(
            "Two-letter ISO country code (e.g. 'us', 'gb', 'de'). Constrains "
            "Tor's exit relay to that country. Requires running "
            "`enable-control-port` once."
        ),
    )
    s.set_defaults(func=cmd_search)

    s = sub.add_parser(
        "fetch",
        help="Fetch URL through Tor; fail-closed on Tor blocks.",
    )
    s.add_argument("url")
    s.add_argument(
        "--format",
        choices=["markdown", "text", "html"],
        default="markdown",
    )
    s.add_argument(
        "--exit-country",
        metavar="CC",
        help=(
            "Two-letter ISO country code (e.g. 'us', 'gb', 'de'). Constrains "
            "Tor's exit relay to that country. Requires running "
            "`enable-control-port` once."
        ),
    )
    s.set_defaults(func=cmd_fetch)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
