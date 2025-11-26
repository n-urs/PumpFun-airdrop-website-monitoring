#!/usr/bin/env python3
# watchpump.py — env-configured Pump.fun watcher.
# - Sends sound + Telegram alerts on *positive* signal (200 + body contains "airdrop"/"claim" and min length).
# - Maintains a Telegram subscriber list via /start and /stop, and can broadcast to all subscribers.
# - Startup Telegram ping goes to ADMIN chat (not broadcast), if enabled.
# - NEW: Offline-guard — устойчивость к обрывам интернета (пауза мониторинга, очередь алертов, авто-восстановление).
# - NEW: TLS controls — custom CA bundle / certifi / optional verification disable; honor proxy envs.

import asyncio, aiohttp, hashlib, time, random, re, csv, os, argparse, platform, subprocess, threading, logging, json, ssl
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone

# ---------- Optional deps kept soft ----------
try:
    import certstream  # type: ignore
    HAVE_CERTSTREAM = True
except Exception:
    HAVE_CERTSTREAM = False

try:
    import dns.resolver  # type: ignore
    HAVE_DNSPYTHON = True
except Exception:
    HAVE_DNSPYTHON = False

try:
    from playsound import playsound  # type: ignore
    HAVE_PLAYSOUND = True
except Exception:
    HAVE_PLAYSOUND = False

try:
    import certifi  # type: ignore
    HAVE_CERTIFI = True
except Exception:
    HAVE_CERTIFI = False

logging.getLogger("certstream").setLevel(logging.WARNING)

USER_AGENT  = "pumpwatch/2.4 (+pump.fun monitor)"
ROOT        = "https://pump.fun/"
KEYWORDS_RE = re.compile(r"\b(airdrop|claim|drop|drops|reward|rewards|redeem|points|campaign|campaigns|password|distribution)\b", re.I)

SEED_URLS   = [
    "https://pump.fun/airdrop", "https://pump.fun/redeem",
    "https://pump.fun/claim", "https://api.pump.fun/claim",
    "https://airdrop.pump.fun/", "https://pump.fun/manifest.json",
    "https://claim.pump.fun/", "https://api.pump.fun/rewards/status",
    "https://pump.fun/drops", "https://pump.fun/rewards", 
    "https://pump.fun/bonus", "https://pump.fun/points",
    "https://pump.fun/quests", "https://pump.fun/robots.txt",
    "https://pump.fun/distribution", "https://api.pump.fun/airdrop",
    "https://pump.fun/api/airdrop", "https://pump.fun/api/claim",
    "https://pump.fun/api/rewards", "https://pump.fun/api/campaign",
    "https://pump.fun/api/quests", "https://pump.fun/api/redeem",
    "https://pump.fun/v1/airdrop", "https://pump.fun/v1/claim",
    "https://pump.fun/sitemap.xml",
    "https://pump.fun/check",
    "https://pump.fun/checker",
]


DNS_HOSTS   = ["airdrop.pump.fun", "claim.pump.fun", "drops.pump.fun", 
    "rewards.pump.fun", "redeem.pump.fun", "bonus.pump.fun",
    "points.pump.fun", "campaign.pump.fun", "quests.pump.fun", "promo.pump.fun",
    "events.pump.fun", "distribution.pump.fun",
    "check.pump.fun", "checker.pump.fun",
]


LOGFILE     = "pumpwatch_log.csv"
JITTER      = 0.15

# ---------- utils: time / url / hashing ----------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def domain_is_exact_pumpfun(url_or_host: str) -> bool:
    host = url_or_host
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    host = (host or "").lower().strip(".")
    return host == "pump.fun" or host.endswith(".pump.fun")

def is_interest_url(url: str) -> bool:
    u = url.lower()
    host = (urlparse(u).hostname or "").lower()
    path = urlparse(u).path.lower()
    return (
        "airdrop" in host or "claim" in host or "check" in host or "checker" in host
        or "airdrop" in path or "claim" in path or "check" in path or "checker" in path
    )


def normalize_and_hash(status: int, etag: str, text: str) -> str:
    snippet = re.sub(r"\s+", " ", (text or "")[:4096])
    return hashlib.sha256(f"{status}|{etag}|{snippet}".encode("utf-8", "ignore")).hexdigest()

def ensure_csv_header(path: str):
    if not os.path.exists(path):
        with open(path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["ts_utc", "signal", "key", "detail"])

def log_event(signal: str, key: str, detail: str):
    ensure_csv_header(LOGFILE)
    with open(LOGFILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([utc_now_iso(), signal, key, detail])

# ---------- audio (non-blocking) ----------
def _play_mp3_blocking(alert_file: str):
    if HAVE_PLAYSOUND:
        try:
            playsound(alert_file); return
        except Exception:
            pass
    system = platform.system().lower()
    cmds = []
    if system == "darwin":
        cmds = [["afplay", alert_file]]
    elif "linux" in system:
        cmds = [["mpg123", alert_file],
                ["ffplay", "-nodisp", "-autoexit", alert_file],
                ["xdg-open", alert_file]]
    elif "windows" in system:
        cmds = [["powershell", "-c", f'Start-Process "{os.path.abspath(alert_file)}"']]
    for cmd in cmds:
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); return
        except Exception:
            continue

def play_alert_nonblocking(alert_file: str):
    if not alert_file or not os.path.exists(alert_file):
        print(f"[{utc_now_iso()}] ALERT ERROR: file not found: {alert_file}", flush=True); return
    threading.Thread(target=_play_mp3_blocking, args=(alert_file,), daemon=True).start()

# ---------- config loader (config.env) ----------
class Config:
    def __init__(self, path: str):
        self.path = path
        self._raw = {}
        self._load()

        # Core cadence
        self.interval   = self._f("INTERVAL", 1.0)
        self.heartbeat  = self._f("HEARTBEAT", 0.0)

        # Startup behavior
        self.no_startup_alerts = self._b("NO_STARTUP_ALERTS", True)
        self.startup_mute      = self._f("STARTUP_MUTE", 10.0)
        self.telegram_startup_notify = self._b("TELEGRAM_STARTUP_NOTIFY", True)

        # “Meaningful” positive definition
        self.only_when_200 = self._b("ONLY_WHEN_200", True)
        self.min_ok_length = self._i("MIN_OK_LENGTH", 600)
        self.confirm       = self._i("CONFIRM", 2)
        self.alert_homepage = self._b("ALERT_HOMEPAGE", False)

        # DNS / CT
        self.ct_enabled  = self._b("CT_ENABLED", False)
        self.ct_audio    = self._b("CT_AUDIO", False)
        self.dns_audio   = self._b("DNS_AUDIO", False)

        # Logging noise
        self.quiet_changes = self._b("QUIET_CHANGES", True)
        self.debug         = self._b("DEBUG", False)

        # Alerts
        self.alert_file   = self._s("ALERT_FILE", "alert.mp3")

        # Telegram (base)
        self.telegram_enabled   = self._b("TELEGRAM_ENABLED", False)
        self.tg_bot_token       = self._s("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat_id         = self._s("TELEGRAM_CHAT_ID", "")
        self.tg_admin_chat_id   = self._s("TELEGRAM_ADMIN_CHAT_ID", self.tg_chat_id)

        # Parse mode validation
        pm_raw = self._s("TELEGRAM_PARSE_MODE", "Markdown").strip()
        allowed = {"Markdown", "MarkdownV2", "HTML"}
        if pm_raw.lower() in ("", "none", "off"):
            self.tg_parse_mode = None
        elif pm_raw in allowed:
            self.tg_parse_mode = pm_raw
        else:
            self.tg_parse_mode = None
            print(f"[{utc_now_iso()}] WARNING: Unsupported TELEGRAM_PARSE_MODE='{pm_raw}'. Falling back to none.", flush=True)

        self.tg_silent          = self._b("TELEGRAM_SILENT", False)
        self.tg_retry           = self._i("TELEGRAM_RETRY", 3)

        # Broadcast / subscription
        self.tg_broadcast_all       = self._b("TELEGRAM_BROADCAST_ALL", True)
        self.tg_subscribers_file    = self._s("TELEGRAM_SUBSCRIBERS_FILE", "subscribers.json")
        self.tg_poll_updates        = self._b("TELEGRAM_POLL_UPDATES", True)
        self.tg_poll_interval       = self._f("TELEGRAM_POLL_INTERVAL", 1.2)
        self.tg_require_start       = self._b("TELEGRAM_REQUIRE_START", True)
        self.tg_welcome_text        = self._s("TELEGRAM_WELCOME_TEXT", "✅ Subscribed to PumpWatch alerts. Send /stop to unsubscribe.")
        self.tg_goodbye_text        = self._s("TELEGRAM_GOODBYE_TEXT", "🛑 Unsubscribed from PumpWatch alerts. Send /start to subscribe again.")

        # ---- OFFLINE GUARD (new) ----
        self.offline_guard         = self._b("OFFLINE_GUARD", True)
        self.offline_probe_urls    = self._list("OFFLINE_PROBE_URLS", ["https://api.telegram.org", ROOT + "robots.txt"])
        self.offline_probe_interval= self._f("OFFLINE_PROBE_INTERVAL", 5.0)
        self.offline_backoff_base  = self._f("OFFLINE_BACKOFF_BASE", 3.0)
        self.offline_backoff_max   = self._f("OFFLINE_BACKOFF_MAX", 60.0)
        self.offline_notify        = self._b("OFFLINE_NOTIFY", True)
        self.offline_queue_alerts  = self._b("OFFLINE_QUEUE_ALERTS", True)

        # ---- TLS / Proxies (new) ----
        self.ssl_ca_file           = self._s("SSL_CA_FILE", "")
        self.ssl_no_verify         = self._b("SSL_NO_VERIFY", False)
        self.ssl_trust_env         = self._b("SSL_TRUST_ENV", True)

    @staticmethod
    def _strip_inline_comment(s: str) -> str:
        out, in_quote, i = [], None, 0
        while i < len(s):
            ch = s[i]
            if in_quote:
                out.append(ch)
                if ch == "\\" and i + 1 < len(s):
                    i += 1; out.append(s[i])
                elif ch == in_quote:
                    in_quote = None
            else:
                if ch in ("'", '"'):
                    in_quote = ch; out.append(ch)
                elif ch in ("#", ";"):
                    break
                else:
                    out.append(ch)
            i += 1
        return "".join(out).strip()

    @staticmethod
    def _unquote(v: str) -> str:
        v = v.strip()
        if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
            return v[1:-1]
        return v

    def _load(self):
        if not os.path.exists(self.path):
            print(f"[{utc_now_iso()}] WARNING: {self.path} not found; using defaults.")
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.rstrip("\n")
                s = raw.strip()
                if not s or s.startswith("#"): continue
                if "=" not in s: continue
                k, v = s.split("=", 1)
                v = self._strip_inline_comment(v)
                v = self._unquote(v)
                self._raw[k.strip()] = v

    def _s(self, k, d): return self._raw.get(k, d)
    def _i(self, k, d):
        try: return int(self._raw.get(k, d))
        except: return d
    def _f(self, k, d):
        try: return float(self._raw.get(k, d))
        except: return d
    def _b(self, k, d):
        v = self._raw.get(k, None)
        if v is None: return d
        return str(v).strip().lower() in ("1","true","yes","on","y","t")
    def _list(self, k, d):
        v = self._raw.get(k, None)
        if not v: return d
        return [x.strip() for x in v.split(",") if x.strip()]

# ---------- Telegram helper ----------
class Telegram:
    def __init__(self, cfg: Config):
        self.enabled = cfg.telegram_enabled and bool(cfg.tg_bot_token)
        self.token = cfg.tg_bot_token
        self.default_chat_id = cfg.tg_chat_id
        self.admin_chat_id = cfg.tg_admin_chat_id or cfg.tg_chat_id
        self.parse_mode = cfg.tg_parse_mode  # None or valid str
        self.silent = cfg.tg_silent
        self.retries = max(0, cfg.tg_retry)

        # Subscribers (for broadcast)
        self.subs_path = cfg.tg_subscribers_file
        self.subscribers = set()
        self._load_subscribers()

        # Behavior
        self.broadcast_all = cfg.tg_broadcast_all
        self.require_start = cfg.tg_require_start
        self.welcome_text = cfg.tg_welcome_text
        self.goodbye_text = cfg.tg_goodbye_text

    # ---- persistence ----
    def _load_subscribers(self):
        try:
            if os.path.exists(self.subs_path):
                with open(self.subs_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.subscribers = set(str(x) for x in data.get("subscribers", []))
        except Exception as e:
            print(f"[{utc_now_iso()}] WARNING: failed to load subscribers: {e}", flush=True)
            self.subscribers = set()

    def _save_subscribers(self):
        try:
            data = {"subscribers": sorted(self.subscribers), "updated_utc": utc_now_iso()}
            with open(self.subs_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[{utc_now_iso()}] WARNING: failed to save subscribers: {e}", flush=True)

    def add_sub(self, chat_id: int) -> bool:
        s = str(chat_id)
        if s in self.subscribers:
            return False
        self.subscribers.add(s)
        self._save_subscribers()
        return True

    def remove_sub(self, chat_id: int) -> bool:
        s = str(chat_id)
        if s not in self.subscribers:
            return False
        self.subscribers.remove(s)
        self._save_subscribers()
        return True

    # ---- sending ----
    async def _send_core(self, session: aiohttp.ClientSession, chat_id: str, text: str, parse_mode: str | None):
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "disable_notification": self.silent}
        if parse_mode:
            payload["parse_mode"] = parse_mode

        last_err = ""
        pm = parse_mode
        for attempt in range(self.retries + 2):  # + fallback attempt w/o parse_mode
            try:
                async with session.post(url, json=payload, timeout=10) as r:
                    if r.status == 200:
                        return True
                    body = await r.text()
                    last_err = f"HTTP {r.status} {body[:200]}"
                    if r.status == 400 and "unsupported parse_mode" in body.lower() and pm:
                        pm = None
                        payload.pop("parse_mode", None)
                        continue
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
            await asyncio.sleep(min(1.5 * (attempt + 1), 5))
        print(f"[{utc_now_iso()}] TELEGRAM ERROR (chat {chat_id}): {last_err}", flush=True)
        return False

    async def send_to(self, session: aiohttp.ClientSession, chat_id: str, text: str):
        return await self._send_core(session, chat_id, text, self.parse_mode)

    async def send_admin(self, session: aiohttp.ClientSession, text: str):
        if not self.admin_chat_id:
            return
        await self.send_to(session, str(self.admin_chat_id), text)

    async def send_default(self, session: aiohttp.ClientSession, text: str):
        if not self.default_chat_id:
            return
        await self.send_to(session, str(self.default_chat_id), text)

    async def broadcast(self, session: aiohttp.ClientSession, text: str):
        if not self.subscribers:
            await self.send_default(session, text)
            return
        for cid in sorted(self.subscribers):
            await self.send_to(session, cid, text)
            await asyncio.sleep(0.05)

# ---------- main watcher ----------
class PumpWatch:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.interval = cfg.interval
        self.heartbeat = cfg.heartbeat
        self.enable_ct = cfg.ct_enabled and HAVE_CERTSTREAM

        self.watch_urls = set(SEED_URLS)
        self.http_signatures = {}
        self.ok_consec = {}
        self.last_alert = {}
        self.dns_state = {}
        self.have_wildcard_dns = None

        self.loop = None
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.run_started_monotonic = None

        self.telegram = Telegram(cfg)

        # ---- Offline guard state ----
        self.net_event = asyncio.Event()
        self.net_event.set()      # assume online at start
        self.online = True
        self.tg_outbox: list[str] = []
        self._last_hb = 0.0
        self.ct_thread = None

        # ---- TLS context (new) ----
        self.ssl_context = self._build_ssl_context()

    def _build_ssl_context(self):
        """
        Returns:
          - False to disable verification (aiohttp semantics),
          - or an ssl.SSLContext with proper CA roots.
        """
        if self.cfg.ssl_no_verify:
            return False
        ctx = ssl.create_default_context()
        # Prefer explicit CA file, else fall back to certifi if available
        if self.cfg.ssl_ca_file and os.path.exists(self.cfg.ssl_ca_file):
            try:
                ctx.load_verify_locations(self.cfg.ssl_ca_file)
            except Exception as e:
                print(f"[{utc_now_iso()}] WARNING: failed to load SSL_CA_FILE: {e}", flush=True)
        elif HAVE_CERTIFI:
            try:
                ctx.load_verify_locations(certifi.where())
            except Exception as e:
                print(f"[{utc_now_iso()}] WARNING: certifi load failed: {e}", flush=True)
        return ctx

    def _startup_muted(self) -> bool:
        if not self.cfg.no_startup_alerts:
            return False
        if self.run_started_monotonic is None:
            return True
        return (time.monotonic() - self.run_started_monotonic) < self.cfg.startup_mute

    def should_alert(self, alert_key: str) -> bool:
        t = time.monotonic()
        last = self.last_alert.get(alert_key, 0)
        if t - last >= 20:
            self.last_alert[alert_key] = t
            return True
        return False

    async def telegram_broadcast_text(self, text: str):
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            trust_env=self.cfg.ssl_trust_env,
        ) as s:
            if self.cfg.tg_broadcast_all:
                await self.telegram.broadcast(s, text)
            else:
                await self.telegram.send_default(s, text)

    async def flush_outbox(self):
        if not self.tg_outbox:
            return
        msgs = list(self.tg_outbox)
        self.tg_outbox.clear()
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            trust_env=self.cfg.ssl_trust_env,
        ) as s:
            for text in msgs:
                if self.cfg.tg_broadcast_all:
                    await self.telegram.broadcast(s, text)
                else:
                    await self.telegram.send_default(s, text)
                await asyncio.sleep(0.05)

    async def emit(self, signal: str, key: str, detail: str, alert: bool = False):
        msg = f"[{utc_now_iso()}] {signal}: {key} -> {detail}"
        if not self.cfg.quiet_changes or signal.startswith("ALERT_") or signal in ("ALIVE","HTTP_CYCLE","DNS_CHANGE","DNS_INFO","CT_HIT","CT_INFO","NET_OFFLINE","NET_ONLINE"):
            print(msg, flush=True)
        log_event(signal, key, detail)
        if alert and self.should_alert(f"{signal}:{key}"):
            play_alert_nonblocking(self.cfg.alert_file)
            text = f"🚨 *PumpWatch positive*\nURL: `{key}`\nDetail: {detail}\nUTC: {utc_now_iso()}"
            if self.cfg.offline_queue_alerts and not self.net_event.is_set():
                self.tg_outbox.append(text)   # отложим до онлайна
            else:
                await self.telegram_broadcast_text(text)

    async def fetch_text(self, session: aiohttp.ClientSession, url: str):
        err = ""
        try:
            async with session.get(url, timeout=8, allow_redirects=True) as r:
                status = r.status
                etag = r.headers.get("ETag", "")
                try:
                    text = await r.text(errors="ignore")
                except Exception:
                    raw = await r.read()
                    text = raw[:8192].decode("utf-8", "ignore")
                return url, status, etag, text, err
        except asyncio.TimeoutError:
            return url, -1, "", "", "timeout"
        except Exception as e:
            return url, -2, "", "", f"{type(e).__name__}: {e}"

    def discover_urls_from_html(self, html: str):
        candidates = set()
        for attr in ("href", "src"):
            for m in re.finditer(attr + r'\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                candidates.add(m.group(1))
        for c in list(candidates):
            if c.startswith("//"):   c = "https:" + c
            elif c.startswith("/"):  c = urljoin(ROOT, c)
            elif not re.match(r"^https?://", c, re.I): c = urljoin(ROOT, c)
            if domain_is_exact_pumpfun(c) and is_interest_url(c):
                self.watch_urls.add(c)

    def is_meaningful_ok(self, url: str, status: int, text: str) -> bool:
        if not is_interest_url(url):
            return self.cfg.alert_homepage and status == 200 and bool(KEYWORDS_RE.search(text or ""))
        if self.cfg.only_when_200 and status != 200:
            return False
        if not (200 <= status < 400):
            return False
        if len(text or "") < self.cfg.min_ok_length:
            return False
        return bool(KEYWORDS_RE.search(text or ""))

    async def http_monitor(self):
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        connector = aiohttp.TCPConnector(limit=8, ttl_dns_cache=60, ssl=self.ssl_context)
        async with aiohttp.ClientSession(headers=headers, connector=connector, trust_env=self.cfg.ssl_trust_env) as session:
            self.watch_urls.add(ROOT)
            while True:
                # ---- офлайн-пауза ----
                if self.cfg.offline_guard and not self.net_event.is_set():
                    if self.heartbeat > 0 and (time.monotonic() - self._last_hb) >= self.heartbeat:
                        self._last_hb = time.monotonic()
                        await self.emit("ALIVE", "monitor", f"OFFLINE • watching={len(self.watch_urls)} urls; ct={'on' if self.enable_ct else 'off'}", alert=False)
                    await asyncio.sleep(self.cfg.offline_probe_interval)
                    continue

                cycle_start = time.perf_counter()
                urls = list(self.watch_urls)
                results = await asyncio.gather(*(self.fetch_text(session, u) for u in urls))
                changes = 0
                for (url, status, etag, text, err) in results:
                    if url == ROOT and 200 <= status < 400 and text:
                        self.discover_urls_from_html(text)

                    sig = normalize_and_hash(status, etag, text)
                    prev_sig = self.http_signatures.get(url)
                    if prev_sig is None or prev_sig != sig:
                        self.http_signatures[url] = sig
                        base = f"status={status} etag={etag[:64]} len={len(text)}"
                        detail = base + (f" err={err}" if err else "")
                        await self.emit("HTTP_CHANGE", url, detail, alert=False)
                        changes += 1

                    ok = self.is_meaningful_ok(url, status, text)
                    self.ok_consec[url] = (self.ok_consec.get(url, 0) + 1) if ok else 0
                    if self.ok_consec[url] == self.cfg.confirm:
                        if not self._startup_muted():
                            detail = f"OK x{self.cfg.confirm} (status={status}, len={len(text)})"
                            await self.emit("ALERT_HTTP", url, detail, alert=True)
                        else:
                            await self.emit("ALERT_HTTP", url, f"OK x{self.cfg.confirm} (startup-muted)", alert=False)

                if self.cfg.debug:
                    elapsed_ms = int((time.perf_counter() - cycle_start) * 1000)
                    await self.emit("HTTP_CYCLE", f"{len(urls)} urls", f"elapsed={elapsed_ms}ms changes={changes}", alert=False)

                if self.heartbeat > 0 and (time.monotonic() - self._last_hb) >= self.heartbeat:
                    self._last_hb = time.monotonic()
                    await self.emit("ALIVE", "monitor", f"watching={len(self.watch_urls)} urls; ct={'on' if self.enable_ct else 'off'}", alert=False)

                elapsed = (time.perf_counter() - cycle_start)
                await asyncio.sleep(max(0, self.interval + random.uniform(-JITTER, JITTER) - elapsed))

    async def dns_monitor(self):
        if not HAVE_DNSPYTHON:
            print(f"[{utc_now_iso()}] DNS monitor disabled (pip install dnspython).", flush=True)
            return
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 3
        resolver.lifetime = 5
        while True:
            # ---- офлайн-пауза ----
            if self.cfg.offline_guard and not self.net_event.is_set():
                await asyncio.sleep(self.cfg.offline_probe_interval)
                continue

            if self.have_wildcard_dns is None:
                try:
                    bogus = f"zz-{int(time.time())}-{random.randint(1000,9999)}.pump.fun"
                    answers = []
                    for rtype in ("A", "AAAA"):
                        try:
                            ans = resolver.resolve(bogus, rtype, raise_on_no_answer=False)
                            if ans: answers.extend([str(r) for r in ans])
                        except Exception:
                            pass
                    self.have_wildcard_dns = len(answers) > 0
                    await self.emit("DNS_INFO", "wildcard", str(self.have_wildcard_dns), alert=False)
                except Exception:
                    self.have_wildcard_dns = False

            for host in DNS_HOSTS:
                if not domain_is_exact_pumpfun(host): continue
                addrs = []
                for rtype in ("A", "AAAA"):
                    try:
                        ans = resolver.resolve(host, rtype, raise_on_no_answer=False)
                        if ans: addrs.extend([str(r) for r in ans])
                    except dns.resolver.NXDOMAIN:
                        pass
                    except Exception:
                        pass
                addrs = tuple(sorted(set(addrs)))
                prev = self.dns_state.get(host)
                initial = prev is None
                if initial or prev != addrs:
                    self.dns_state[host] = addrs
                    label = "RESOLVES" if addrs else "NO_ANSWER"
                    extra = " (wildcard?)" if self.have_wildcard_dns else ""
                    beep = (self.cfg.dns_audio and not (initial and self.cfg.no_startup_alerts) and not self._startup_muted())
                    await self.emit("DNS_CHANGE", host, f"{label} {addrs}{extra}", alert=beep)
            await asyncio.sleep(3 + random.uniform(-JITTER, JITTER))

    # ---------- CT (optional) ----------
    def _ct_callback(self, message, _context):
        if not message or message.get("message_type") != "certificate_update":
            return
        leaf = (message.get("data") or {}).get("leaf_cert") or {}
        all_domains = leaf.get("all_domains") or []
        hits = []
        for name in all_domains:
            if not isinstance(name, str): continue
            n = name.strip().lower()
            if n.startswith("*."): continue
            if n.endswith(".pump.fun") and ("airdrop" in n or "claim" in n):
                hits.append(n)
        if hits and self.loop is not None:
            muted = self._startup_muted() or not self.cfg.ct_audio
            try:
                self.loop.call_soon_threadsafe(self.event_queue.put_nowait, ("CT_HIT", ",".join(sorted(set(hits))), "certstream", muted))
            except Exception:
                pass

    def start_ct_thread(self):
        if not self.enable_ct:
            print(f"[{utc_now_iso()}] CT monitor disabled (set CT_ENABLED=true and install certstream websocket-client).", flush=True)
            return None
        def run():
            try:
                certstream.listen_for_events(self._ct_callback, url='wss://certstream.calidog.io/')
            except Exception as e:
                try:
                    if self.loop is not None:
                        self.loop.call_soon_threadsafe(self.event_queue.put_nowait, ("CT_INFO", "stopped", str(e), True))
                except Exception:
                    pass
        th = threading.Thread(target=run, name="certstream-thread", daemon=True)
        th.start()
        self.ct_thread = th
        return th

    async def ct_event_drain(self):
        while True:
            payload = await self.event_queue.get()
            if len(payload) == 4:
                signal, key, detail, muted = payload
            else:
                signal, key, detail = payload; muted = False
            await self.emit(signal, key, detail, alert=(not muted and self.cfg.ct_audio))

    # ---------- Telegram updates poller ----------
    async def telegram_updates_monitor(self):
        if not self.telegram.enabled or not self.cfg.tg_poll_updates:
            return
        url = f"https://api.telegram.org/bot{self.telegram.token}/getUpdates"
        params = {"timeout": 60}
        offset = None
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            trust_env=self.cfg.ssl_trust_env,
        ) as s:
            while True:
                try:
                    if self.cfg.offline_guard and not self.net_event.is_set():
                        await asyncio.sleep(self.cfg.offline_probe_interval); continue
                    q = params.copy()
                    if offset is not None:
                        q["offset"] = offset
                    async with s.get(url, params=q, timeout=70) as r:
                        if r.status != 200:
                            await asyncio.sleep(self.cfg.tg_poll_interval); continue
                        data = await r.json(content_type=None)
                        if not data.get("ok"):
                            await asyncio.sleep(self.cfg.tg_poll_interval); continue
                        for upd in data.get("result", []):
                            offset = max(offset or 0, upd.get("update_id", 0) + 1)
                            msg = upd.get("message") or {}
                            if not msg: continue
                            chat = msg.get("chat") or {}
                            chat_id = chat.get("id")
                            text = (msg.get("text") or "").strip()
                            if not chat_id: continue
                            if text.startswith("/start") or text.startswith("/subscribe"):
                                added = self.telegram.add_sub(chat_id)
                                if added:
                                    await self.telegram.send_to(s, str(chat_id), self.telegram.welcome_text)
                            elif text.startswith("/stop") or text.startswith("/unsubscribe"):
                                removed = self.telegram.remove_sub(chat_id)
                                if removed:
                                    await self.telegram.send_to(s, str(chat_id), self.telegram.goodbye_text)
                            elif not self.require_start:
                                if self.telegram.add_sub(chat_id):
                                    await self.telegram.send_to(s, str(chat_id), self.telegram.welcome_text)
                            if text.startswith("/status"):
                                await self.telegram.send_to(
                                    s, str(chat_id),
                                    f"PumpWatch is running.\nWatching: {len(self.watch_urls)} urls • CT: {'on' if self.enable_ct else 'off'}\nUTC: {utc_now_iso()}"
                                )
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(self.cfg.tg_poll_interval)

    # ---------- Network watchdog (offline guard) ----------
    async def network_watchdog(self):
        if not self.cfg.offline_guard:
            self.net_event.set(); return
        backoff = self.cfg.offline_backoff_base
        ok_streak = 0
        fail_streak = 0
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            trust_env=self.cfg.ssl_trust_env,
        ) as s:
            while True:
                any_ok = False
                for url in self.cfg.offline_probe_urls:
                    try:
                        async with s.head(url, timeout=5) as r:
                            if 200 <= r.status < 500:
                                any_ok = True
                                break
                    except Exception:
                        pass
                if any_ok:
                    ok_streak += 1
                    fail_streak = 0
                    backoff = self.cfg.offline_backoff_base
                    if not self.net_event.is_set() and ok_streak >= 2:
                        self.net_event.set()
                        self.online = True
                        await self.emit("NET_ONLINE", "connectivity", "restored", alert=False)
                        if self.cfg.offline_notify and self.telegram.enabled:
                            await self.telegram_broadcast_text(f"🟢 PumpWatch back online.\nUTC: {utc_now_iso()}")
                        # restart CT thread if needed
                        if self.enable_ct and (self.ct_thread is None or not self.ct_thread.is_alive()):
                            self.start_ct_thread()
                        await self.flush_outbox()
                    await asyncio.sleep(self.cfg.offline_probe_interval)
                else:
                    fail_streak += 1
                    ok_streak = 0
                    if self.net_event.is_set() and fail_streak >= 2:
                        self.net_event.clear()
                        self.online = False
                        await self.emit("NET_OFFLINE", "connectivity", "lost", alert=False)
                        if self.cfg.offline_notify and self.telegram.enabled:
                            try:
                                await self.telegram_broadcast_text(f"🔴 PumpWatch offline (network).\nUTC: {utc_now_iso()}")
                            except Exception:
                                pass
                    await asyncio.sleep(min(backoff, self.cfg.offline_backoff_max))
                    backoff = min(backoff * 1.7, self.cfg.offline_backoff_max)

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.run_started_monotonic = time.monotonic()

        # Telegram: startup notification (to admin chat only)
        if self.telegram.enabled and self.cfg.telegram_startup_notify and self.telegram.admin_chat_id:
            text = (
                f"🟢 *PumpWatch started* on `{platform.node()}`\n"
                f"interval={self.cfg.interval}s • confirm={self.cfg.confirm} • only_when_200={self.cfg.only_when_200}\n"
                f"watching={len(self.watch_urls)} urls • ct={'on' if self.enable_ct else 'off'}\n"
                f"subs={len(self.telegram.subscribers)} • broadcast={'on' if self.cfg.tg_broadcast_all else 'off'}\n"
                f"UTC: {utc_now_iso()}"
            )
            async with aiohttp.ClientSession(
                headers={"User-Agent": USER_AGENT},
                connector=aiohttp.TCPConnector(ssl=self.ssl_context),
                trust_env=self.cfg.ssl_trust_env,
            ) as s:
                await self.telegram.send_admin(s, text)

        # CT thread
        if self.enable_ct:
            self.start_ct_thread()

        tasks = [self.http_monitor(), self.dns_monitor(), self.network_watchdog()]
        if self.enable_ct:
            tasks.append(self.ct_event_drain())
        if self.telegram.enabled and self.cfg.tg_poll_updates:
            tasks.append(self.telegram_updates_monitor())
        await asyncio.gather(*tasks)

# ---------- entrypoint ----------
def main():
    ap = argparse.ArgumentParser(description="Monitor pump.fun for airdrop/claim signals (env-configured).")
    ap.add_argument("--config", default="config.env", help="Path to config.env")
    ap.add_argument("--print-config", action="store_true", help="Print loaded config and exit")
    args = ap.parse_args()

    cfg = Config(args.config)
    if args.print_config:
        print("Loaded config from", cfg.path)
        for k, v in cfg.__dict__.items():
            if k.startswith("_"): continue
            print(f"{k} = {v}")
        return

    print(f"[{utc_now_iso()}] pumpwatch starting | interval={cfg.interval}s | CT={'on' if cfg.ct_enabled else 'off'} | alert={cfg.alert_file}")
    print(f"[{utc_now_iso()}] Watching initial URLs: {', '.join(SEED_URLS)}")
    if not HAVE_CERTSTREAM and cfg.ct_enabled:
        print(f"[{utc_now_iso()}] Tip: pip install certstream websocket-client  # to enable CT watch")
    if not HAVE_DNSPYTHON:
        print(f"[{utc_now_iso()}] Tip: pip install dnspython  # to enable DNS watch")
    if not HAVE_PLAYSOUND:
        print(f"[{utc_now_iso()}] Tip: pip install playsound==1.2.2  # for reliable MP3 alerts")
    if not HAVE_CERTIFI and not cfg.ssl_ca_file and not cfg.ssl_no_verify:
        print(f"[{utc_now_iso()}] Tip: pip install certifi  # modern CA bundle for TLS verification")

    try:
        asyncio.run(PumpWatch(cfg).run())
    except KeyboardInterrupt:
        print(f"\n[{utc_now_iso()}] pumpwatch stopped.", flush=True)

if __name__ == "__main__":
    main()
